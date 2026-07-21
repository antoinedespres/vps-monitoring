#!/usr/bin/env python3
"""Entry point: watches SSH (via fail2ban + auth log) and Caddy access logs,
sends color-coded Discord embed alerts on brute-force activity and flags
whether an attack actually succeeded in logging in."""
import logging
import os
import threading

from alerting import CRITICAL, INFO, OK, DiscordNotifier, Monitor
from presence import GatewayPresence
from sources import CaddyLoginOutcomes, CaddyRequestRate, Fail2banBanEvents, SSHBruteForceSuccess

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


def main():
    token = env("DISCORD_BOT_TOKEN")
    channel_id = env("DISCORD_CHANNEL_ID")
    host = env("MONITORED_HOST")
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

    GatewayPresence(token).start()

    watchers = [watch_ssh_bans, watch_ssh_success, watch_http, watch_http_login]
    threads = [threading.Thread(target=w, args=(notifier,), daemon=True) for w in watchers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
