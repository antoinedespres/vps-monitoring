#!/usr/bin/env python3
"""Entry point for vps-monitoring. Two jobs:

  1. Watch SSH (via fail2ban + auth log) and Caddy access logs, sending
     color-coded Discord embed alerts on brute-force activity and flagging
     whether an attack actually succeeded in logging in.
  2. Serve read-only slash commands (/status, /cpu, /mem, /disk, /docker,
     /updates, /uptime) over the Discord Gateway, giving the same view of this
     VPS that the sibling pi-monitoring bot gives of the Raspberry Pi.
  3. Report what unattended-upgrades installed on this VPS - package names and
     old -> new versions - read back from the host's apt history.
"""
import logging
import os
import re
import threading
import time

import system
from alerting import CRITICAL, INFO, OK, WARNING, DiscordNotifier, Monitor
from commands import InteractionHandler, fetch_application_id, register_guild_commands
from presence import GatewayPresence
from sources import CaddyLoginOutcomes, CaddyRequestRate, Fail2banBanEvents, SSHBruteForceSuccess
from state import State

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("vps-monitoring")


def env(name, default=None, cast=str):
    value = os.environ.get(name, default)
    return cast(value) if value is not None else None


def trusted_ips():
    raw = env("TRUSTED_IPS", "")
    return {ip.strip() for ip in raw.split(",") if ip.strip()}


def watch_ssh_bans(notifier):
    jail = env("FAIL2BAN_JAIL", "sshd")
    log_path = env("FAIL2BAN_LOG", "/var/log/fail2ban.log")
    port = env("SSH_PORT", "22")
    mon = Monitor("SSH brute-force", notifier, warn_threshold=1, crit_threshold=1, metric_label="Banned IPs")
    banned = set()

    for event in Fail2banBanEvents(log_path, jail).events():
        if event["type"] == "ban":
            banned.add(event["ip"])
            mon.force(
                CRITICAL,
                "SSH brute-force detected",
                f"fail2ban banned an IP after repeated failed login attempts on port {port}.",
                {"IP": event["ip"], "Jail": jail, "Port": port, "Currently banned": len(banned)},
            )
        elif event["type"] == "unban":
            banned.discard(event["ip"])
            if not banned:
                mon.force(
                    OK,
                    "SSH brute-force: recovered",
                    "No more banned IPs on this jail.",
                    {"IP": event["ip"], "Jail": jail, "Port": port},
                )


def watch_ssh_success(notifier):
    """Flags an SSH login that succeeded right after a burst of failures from
    the same IP - i.e. a brute-force that got in before fail2ban could ban it."""
    threshold = env("SSH_BRUTEFORCE_SUCCESS_THRESHOLD", "3", int)
    window = env("LOGIN_CORRELATION_WINDOW_SECONDS", "600", int)
    auth_log = env("SSH_AUTH_LOG", "/var/log/auth.log")
    trusted = trusted_ips()

    for event in SSHBruteForceSuccess(log_path=auth_log, window_seconds=window).events():
        if event["recent_failures"] < threshold:
            continue
        is_trusted = event["ip"] in trusted
        fields = {
            "IP": event["ip"],
            "User": event["user"],
            "Method": event["method"],
            "Recent failures": event["recent_failures"],
        }
        if is_trusted:
            notifier.send_embed(
                "SSH login after failed attempts (trusted IP)",
                f"A known/trusted IP had {event['recent_failures']} failed attempts before logging in - likely a typo or a retried connection, not an attack.",
                fields, INFO,
            )
        else:
            notifier.send_embed(
                "SSH brute-force SUCCEEDED",
                f"An SSH login succeeded from an IP that had {event['recent_failures']} failed attempts in the last {window}s.",
                fields, CRITICAL,
            )


def watch_http(notifier):
    log_path = env("CADDY_LOG", "/var/log/caddy/access.log")
    host = env("MONITORED_HOST")
    window = env("HTTP_WINDOW_SECONDS", "300", int)
    warn = env("HTTP_WARN_THRESHOLD", "30", int)
    crit = env("HTTP_CRIT_THRESHOLD", "100", int)

    mon = Monitor(
        f"HTTP brute-force ({host})",
        notifier,
        warn_threshold=warn,
        crit_threshold=crit,
        metric_label=f"Requests / {window}s from one IP",
    )

    for event in CaddyRequestRate(log_path, host, window_seconds=window).events():
        mon.update(event["count"], context={"IP": event["ip"], "Host": host, "Top routes hit": event["top_paths"]})


def watch_http_login(notifier):
    """Flags every successful Home Assistant login. Severity depends on
    whether it followed a burst of failed login attempts from the same IP
    (brute-force that got in) or was a normal, isolated login (informational)."""
    log_path = env("CADDY_LOG", "/var/log/caddy/access.log")
    host = env("MONITORED_HOST")
    threshold = env("HTTP_BRUTEFORCE_SUCCESS_THRESHOLD", "3", int)
    window = env("LOGIN_CORRELATION_WINDOW_SECONDS", "600", int)
    trusted = trusted_ips()

    for event in CaddyLoginOutcomes(log_path, host, window_seconds=window).events():
        is_trusted = event["ip"] in trusted
        fields = {
            "IP": event["ip"],
            "Host": host,
            "Recent attempts": event["recent_attempts"],
            "Device": event["user_agent"],
        }
        if event["recent_attempts"] >= threshold and not is_trusted:
            notifier.send_embed(
                "HTTP brute-force SUCCEEDED",
                f"A Home Assistant login succeeded from an IP that made {event['recent_attempts']} login attempts in the last {window}s.",
                fields,
                CRITICAL,
            )
        else:
            note = " (trusted IP)" if is_trusted else ""
            notifier.send_embed(
                f"New Home Assistant login{note}",
                "A login succeeded (audit trail, not necessarily suspicious). Check \"Device\" below - background app refresh from your own phone often looks like a fresh login from the same carrier IP.",
                fields,
                INFO,
            )


# unattended-upgrades with MinimalSteps splits one nightly run into several
# small dpkg transactions, each landing as its own history.log entry. Entries
# this close together are folded into one report instead of one embed per batch.
UPGRADE_SESSION_GAP_SECONDS = 900

# Vendor packaging suffixes that repeat on nearly every line of an upgrade:
# Debian's "+deb13u1" / "~deb13u2", Raspberry Pi's "+rpt1", and the "~ubuntu."
# tail third-party archives append (docker's "1~ubuntu.26.04~resolute").
# Requiring a digit after deb/rpt keeps those off versions that merely contain
# the letters (+debian1, +debug2); requiring a literal "~" before ubuntu keeps
# the ubuntu rule off "-2ubuntu4.3", where the revision is the whole point.
_DEB_SUFFIX_RE = re.compile(r"[+~]deb\d[0-9a-z.]*", re.IGNORECASE)
_RPT_SUFFIX_RE = re.compile(r"[+~]rpt\d[0-9a-z.]*", re.IGNORECASE)
_VENDOR_SUFFIX_RE = re.compile(r"~ubuntu[0-9a-z.~]*", re.IGNORECASE)

# Tried most-aggressive first. A suffix only earns room on the line when
# dropping it would leave an upgrade reading as one from a version to itself -
# which is what a security respin (deb13u1 -> deb13u2) looks like. Identical on
# both sides, it says nothing and goes.
_VERSION_TRIMS = (
    lambda v: _VENDOR_SUFFIX_RE.sub("", _RPT_SUFFIX_RE.sub("", _DEB_SUFFIX_RE.sub("", v))),
    lambda v: _DEB_SUFFIX_RE.sub("", v),
    lambda v: v,
)


def _short_version(value):
    """For a lone version (an install or a removal) there is nothing to tell
    apart, so the shortest form always applies."""
    return _VERSION_TRIMS[0](value) if value else value


def _short_version_pair(old, new):
    if not old or not new:
        return _short_version(old), _short_version(new)
    for trim in _VERSION_TRIMS:
        short_old, short_new = trim(old), trim(new)
        if short_old != short_new:
            return short_old, short_new
    return old, new


def _dedupe(packages):
    """A package can span several MinimalSteps batches; keep its first sighting."""
    seen, unique = set(), []
    for p in packages:
        if p["name"] not in seen:
            seen.add(p["name"])
            unique.append(p)
    return unique


def _clip_lines(lines, limit=1000):
    """Discord caps an embed field value at 1024 characters."""
    kept, total = [], 0
    for line in lines:
        if total + len(line) + 1 > limit:
            kept.append(f"... and {len(lines) - len(kept)} more")
            break
        kept.append(line)
        total += len(line) + 1
    return "\n".join(kept) or "-"


def _parse_ts(value):
    try:
        return time.strptime(value, "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def _group_upgrade_sessions(runs):
    sessions = []
    for run in runs:
        previous_end = _parse_ts(sessions[-1][-1]["end"]) if sessions else None
        start = _parse_ts(run["start"])
        if previous_end and start and \
                (time.mktime(start) - time.mktime(previous_end)) <= UPGRADE_SESSION_GAP_SECONDS:
            sessions[-1].append(run)
        else:
            sessions.append([run])
    return sessions


def _notify_upgrade_session(notifier, host_label, session):
    upgraded, installed, removed, errors = [], [], [], []
    for run in session:
        upgraded += run["upgrade"]
        installed += run["install"]
        removed += run["remove"]
        if run["error"]:
            errors.append(run["error"])
    upgraded, installed, removed = _dedupe(upgraded), _dedupe(installed), _dedupe(removed)

    if not (upgraded or installed or removed or errors):
        return  # a no-op run (e.g. only autoremove candidates) isn't news

    fields = {}
    if upgraded:
        fields[f"Upgraded ({len(upgraded)})"] = _clip_lines(
            [f"`{p['name']}` {old} -> {new}"
             for p in upgraded for old, new in [_short_version_pair(p["old"], p["new"])]])
    if installed:
        fields[f"Installed ({len(installed)})"] = _clip_lines(
            [f"`{p['name']}` {_short_version(p['new'])}" for p in installed])
    if removed:
        fields[f"Removed ({len(removed)})"] = _clip_lines(
            [f"`{p['name']}` {_short_version(p['old'] or p['new'])}" for p in removed])
    if errors:
        fields["Errors"] = _clip_lines(errors)
    reboot_required, reboot_pkgs = system.reboot_state()
    if reboot_required:
        fields["Reboot required"] = ", ".join(reboot_pkgs)[:1000] or "yes"

    window = session[0]["start"]
    if session[-1]["end"] != window:
        window += f" -> {session[-1]['end'].split()[-1]}"
    summary = ", ".join(part for part in (
        f"{len(upgraded)} upgraded" if upgraded else "",
        f"{len(installed)} installed" if installed else "",
        f"{len(removed)} removed" if removed else "",
    ) if part)

    notifier.send_embed(
        f"\U0001F4E6 {host_label}: automatic updates installed",
        f"unattended-upgrades ran and applied **{summary}**.\n`{window}` (host local time)",
        fields,
        WARNING if errors else INFO,
        inline=False,
    )


def _check_apt_history(notifier, host_label, state, settle_seconds):
    """Report unattended-upgrades runs newer than the stored watermark.

    Nothing is reported while the log is still being written to: a multi-step
    upgrade is announced once and complete rather than batch by batch."""
    hist = system.apt_history()
    if "error" in hist:
        logger.debug("apt history unavailable: %s", hist["error"])
        return

    runs = [r for r in hist["runs"] if r["unattended"]]
    seen = state.get("apt_history_seen")
    if seen is None:
        # First start: adopt the newest entry already in the log - of any kind,
        # so a manual apt run counts too - instead of replaying the backlog.
        # An empty log seeds empty, and the next upgrade is reported.
        state.set("apt_history_seen", max((r["end"] for r in hist["runs"]), default=""))
        return

    pending = [r for r in runs if r["end"] > seen]
    if not pending or hist["quiet_seconds"] < settle_seconds:
        return
    for session in _group_upgrade_sessions(pending):
        _notify_upgrade_session(notifier, host_label, session)
        state.set("apt_history_seen", session[-1]["end"])


def watch_apt_upgrades(notifier):
    """Poll the host's apt history for what unattended-upgrades installed.

    A poll rather than a log tail like the other watchers: this log is appended
    to once a day, so there is nothing to gain from following it live."""
    if env("REPORT_INSTALLED_UPDATES", "1") in ("0", "false", "no"):
        logger.info("REPORT_INSTALLED_UPDATES is off - not watching the apt history")
        return
    host_label = env("HOST_LABEL", "vps")
    interval = env("INSTALLED_UPDATES_POLL_SECONDS", "300", int)
    settle = env("INSTALLED_UPDATES_SETTLE_SECONDS", "180", int)
    state = State(env("STATE_PATH", "/var/lib/vps-monitoring/state.json"))

    while True:
        try:
            _check_apt_history(notifier, host_label, state, settle)
        except Exception:
            logger.exception("apt history check failed")
        time.sleep(interval)


def main():
    token = env("DISCORD_BOT_TOKEN")
    channel_id = env("DISCORD_CHANNEL_ID")
    guild_id = env("DISCORD_GUILD_ID")
    host = env("MONITORED_HOST")
    host_label = env("HOST_LABEL", "vps")
    if not token or not channel_id or not host:
        raise SystemExit("DISCORD_BOT_TOKEN, DISCORD_CHANNEL_ID and MONITORED_HOST must be set (see .env.example)")

    notifier = DiscordNotifier(token, channel_id)
    version = env("APP_VERSION", "dev")
    logger.info("vps-monitoring starting (version %s)", version)
    notifier.send_embed(
        "vps-monitoring started",
        "Deployment succeeded and the bot is now watching for brute-force activity.",
        {"Version": version, "Monitored host": host},
        INFO,
    )

    on_interaction = None
    if guild_id:
        application_id = fetch_application_id(token)
        register_guild_commands(token, application_id, guild_id)
        on_interaction = InteractionHandler(application_id, token, host_label).handle
    else:
        logger.info("DISCORD_GUILD_ID not set - slash commands disabled")

    GatewayPresence(token, on_interaction=on_interaction).start()

    watchers = [watch_ssh_bans, watch_ssh_success, watch_http, watch_http_login,
                watch_apt_upgrades]
    threads = [threading.Thread(target=w, args=(notifier,), daemon=True) for w in watchers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
