"""Discord slash commands: registration + interaction handling.

Read-only views of the VPS this bot runs on, built from the same collectors in
system.py. Handled over the Gateway connection that also drives the bot's
presence. Mirrors the sibling pi-monitoring bot's command set so both hosts
answer the same questions in the same shape.
"""
import datetime
import logging

import requests

import system

logger = logging.getLogger("vps-monitoring")

API = "https://discord.com/api/v10"

# Discord interaction/response types
TYPE_APPLICATION_COMMAND = 2
CALLBACK_DEFERRED_CHANNEL_MESSAGE = 5

COLOR_OK = 0x2ECC71
COLOR_INFO = 0x3498DB
COLOR_WARN = 0xE67E22
COLOR_ERROR = 0xE74C3C

COMMANDS = [
    {"name": "status", "description": "Overview: CPU, RAM, disk, uptime, containers, updates"},
    {"name": "cpu", "description": "CPU load, utilisation and the top processes by CPU"},
    {"name": "mem", "description": "Memory and swap usage, and the top processes by memory"},
    {"name": "disk", "description": "Disk usage per mounted filesystem"},
    {"name": "docker", "description": "State of every Docker container on the VPS"},
    {"name": "updates", "description": "Pending apt package updates and reboot-required status"},
    {"name": "uptime", "description": "Uptime and load averages"},
]


def fetch_application_id(bot_token):
    resp = requests.get(f"{API}/oauth2/applications/@me", headers={"Authorization": f"Bot {bot_token}"}, timeout=15)
    resp.raise_for_status()
    return resp.json()["id"]


def register_guild_commands(bot_token, application_id, guild_id):
    """Guild-scoped registration: updates instantly (global commands can take
    up to an hour to propagate), which matters while iterating/testing."""
    url = f"{API}/applications/{application_id}/guilds/{guild_id}/commands"
    resp = requests.put(url, headers={"Authorization": f"Bot {bot_token}"}, json=COMMANDS, timeout=15)
    if resp.status_code >= 300:
        logger.error("Failed to register slash commands: %s %s", resp.status_code, resp.text)
    else:
        logger.info("Registered %d slash command(s) for guild %s", len(COMMANDS), guild_id)


def _clip(value, limit=1024):
    """Discord rejects the whole message if a single field value exceeds 1024
    characters - a real risk for the package list on a long-neglected host."""
    return value if len(value) <= limit else value[:limit - 1] + "…"


def _bar(percent, width=10):
    filled = int(round(percent / 100.0 * width))
    filled = max(0, min(width, filled))
    return "█" * filled + "░" * (width - filled)


def _usage_line(percent):
    icon = "🟢" if percent < 80 else ("🟠" if percent < 90 else "🔴")
    return f"{icon} `{_bar(percent)}` {percent:.0f}%"


class InteractionHandler:
    def __init__(self, application_id, bot_token, host_label):
        self.application_id = application_id
        self.bot_token = bot_token
        self.host_label = host_label

    def handle(self, interaction):
        """Entry point for a Gateway INTERACTION_CREATE dispatch. Runs in its
        own thread - deferring/responding does blocking HTTP."""
        if interaction.get("type") != TYPE_APPLICATION_COMMAND:
            return
        interaction_id = interaction["id"]
        token = interaction["token"]
        name = interaction["data"]["name"]
        logger.info("Slash command received: /%s", name)

        self._defer(interaction_id, token)
        try:
            embed = self._dispatch(name)
        except Exception:
            logger.exception("Error handling /%s", name)
            embed = {"title": "⚠️ Error", "description": "Something went wrong handling that command.", "color": COLOR_ERROR}
        embed.setdefault("footer", {"text": self.host_label})
        self._respond(token, embed)

    def _defer(self, interaction_id, token):
        url = f"{API}/interactions/{interaction_id}/{token}/callback"
        resp = requests.post(url, json={"type": CALLBACK_DEFERRED_CHANNEL_MESSAGE}, timeout=10)
        if resp.status_code >= 300:
            logger.error("Failed to defer interaction: %s %s", resp.status_code, resp.text)

    def _respond(self, token, embed):
        url = f"{API}/webhooks/{self.application_id}/{token}/messages/@original"
        resp = requests.patch(url, json={"embeds": [embed]}, timeout=10)
        if resp.status_code >= 300:
            logger.error("Failed to send interaction response: %s %s", resp.status_code, resp.text)

    def _dispatch(self, name):
        return {
            "status": self._cmd_status,
            "cpu": self._cmd_cpu,
            "mem": self._cmd_mem,
            "disk": self._cmd_disk,
            "docker": self._cmd_docker,
            "updates": self._cmd_updates,
            "uptime": self._cmd_uptime,
        }.get(name, lambda: {"title": "Unknown command", "color": COLOR_WARN})()

    # --- commands ---------------------------------------------------------- #
    def _cmd_status(self):
        cpu = system.cpu_percent()
        mem = system.meminfo()
        disk = system.disk_usage("/")
        temp = system.temperature_c()
        one, five, fifteen = system.loadavg()
        up = system.format_duration(system.uptime_seconds())

        containers = system.docker_containers()
        if isinstance(containers, dict):
            docker_line = f"⚠️ {containers['error']}"
        else:
            running = sum(1 for c in containers if c["state"] == "running")
            unhealthy = sum(1 for c in containers if c["health"] == "unhealthy")
            docker_line = f"{running}/{len(containers)} running"
            if unhealthy:
                docker_line += f", 🔴 {unhealthy} unhealthy"

        apt = system.apt_status()
        if "error" in apt:
            updates_line = f"⚠️ {apt['error']}"
        else:
            updates_line = f"{apt['count']} pending"
            if apt["security_count"]:
                updates_line += f" (🔴 {apt['security_count']} security)"
        if apt["reboot_required"]:
            updates_line += " · ♻️ reboot required"

        disk_line = _usage_line(disk["percent"]) if "error" not in disk else f"⚠️ {disk['error']}"

        fields = [
            {"name": "🧠 CPU", "value": f"{_usage_line(cpu)}\nload {one:.2f} / {five:.2f} / {fifteen:.2f}", "inline": True},
            {"name": "💾 RAM", "value": f"{_usage_line(mem['percent'])}\n{system.human_bytes(mem['used'])} / {system.human_bytes(mem['total'])}", "inline": True},
            {"name": "🗄️ Disk /", "value": f"{disk_line}\n{system.human_bytes(disk['used'])} / {system.human_bytes(disk['total'])}" if "error" not in disk else disk_line, "inline": True},
            {"name": "🐳 Docker", "value": docker_line, "inline": True},
            {"name": "📦 Updates", "value": updates_line, "inline": True},
        ]
        # Virtualised hosts usually expose no thermal zone; only show it if real.
        if temp is not None:
            fields.append({"name": "🌡️ Temp", "value": f"{temp:.1f} °C", "inline": True})
        return {"title": f"🖥️ {self.host_label} — status", "color": COLOR_INFO, "fields": fields,
                "footer": {"text": f"uptime {up}"}}

    def _cmd_cpu(self):
        cpu = system.cpu_percent()
        one, five, fifteen = system.loadavg()
        ncpu = system.cpu_count()
        top = system.top_by_cpu(6)
        lines = [f"`{pct:5.1f}%` {name} (pid {pid})" for pct, name, pid in top] or ["_no active processes seen_"]
        return {
            "title": f"🧠 CPU — {self.host_label}",
            "color": COLOR_INFO,
            "description": f"{_usage_line(cpu)}  across {ncpu} core(s)\nLoad average: **{one:.2f}** / {five:.2f} / {fifteen:.2f}",
            "fields": [{"name": "Top processes by CPU", "value": "\n".join(lines), "inline": False}],
        }

    def _cmd_mem(self):
        mem = system.meminfo()
        top = system.top_by_mem(6)
        lines = [f"`{system.human_bytes(rss):>9}` {name} (pid {pid})" for rss, name, pid in top] or ["_no processes seen_"]
        desc = (f"**RAM** {_usage_line(mem['percent'])}\n"
                f"{system.human_bytes(mem['used'])} used / {system.human_bytes(mem['total'])} total\n")
        if mem["swap_total"]:
            desc += f"**Swap** {_usage_line(mem['swap_percent'])}\n{system.human_bytes(mem['swap_used'])} / {system.human_bytes(mem['swap_total'])}"
        else:
            desc += "**Swap** none configured"
        return {
            "title": f"💾 Memory — {self.host_label}",
            "color": COLOR_INFO,
            "description": desc,
            "fields": [{"name": "Top processes by memory", "value": "\n".join(lines), "inline": False}],
        }

    def _cmd_disk(self):
        usages = system.disk_usages()
        fields = []
        worst = 0
        for u in usages:
            if "error" in u:
                fields.append({"name": u["path"], "value": f"⚠️ {u['error']}", "inline": False})
                continue
            worst = max(worst, u["percent"])
            fields.append({
                "name": u["path"],
                "value": f"{_usage_line(u['percent'])}\n{system.human_bytes(u['used'])} / {system.human_bytes(u['total'])}  ·  {system.human_bytes(u['free'])} free",
                "inline": False,
            })
        color = COLOR_OK if worst < 80 else (COLOR_WARN if worst < 90 else COLOR_ERROR)
        return {"title": f"🗄️ Disk — {self.host_label}", "color": color, "fields": fields}

    def _cmd_docker(self):
        containers = system.docker_containers()
        if isinstance(containers, dict):
            return {"title": "🐳 Docker", "description": f"⚠️ {containers['error']}", "color": COLOR_ERROR}
        if not containers:
            return {"title": "🐳 Docker", "description": "No containers found.", "color": COLOR_WARN}

        def icon(c):
            if c["state"] != "running":
                return "🔴"
            if c["health"] == "unhealthy":
                return "🟠"
            if c["health"] == "starting":
                return "🟡"
            return "🟢"

        lines = [f"{icon(c)} **{c['name']}** — {c['status']}" for c in containers]
        running = sum(1 for c in containers if c["state"] == "running")
        down = len(containers) - running
        color = COLOR_OK if down == 0 else COLOR_WARN
        return {
            "title": f"🐳 Docker — {self.host_label}",
            "description": "\n".join(lines)[:4000],
            "color": color,
            "footer": {"text": f"{running} running · {down} stopped · {len(containers)} total"},
        }

    def _cmd_updates(self):
        apt = system.apt_status()
        if "error" in apt:
            desc = f"⚠️ {apt['error']}"
            if apt["reboot_required"]:
                desc += "\n♻️ **Reboot required.**"
            return {"title": "📦 Updates", "description": desc, "color": COLOR_WARN}

        count = apt["count"]
        sec = apt["security_count"]
        if count == 0:
            desc = "✅ System is up to date."
            color = COLOR_OK
        else:
            desc = f"**{count}** package(s) upgradable"
            desc += f", including 🔴 **{sec}** security update(s)." if sec else "."
            color = COLOR_ERROR if sec else COLOR_WARN

        fields = []
        if apt["packages"]:
            names = [("🔴 " if p["security"] else "") + p["name"] for p in apt["packages"][:25]]
            more = f"\n… and {count - 25} more" if count > 25 else ""
            fields.append({"name": "Packages", "value": _clip(", ".join(names) + more), "inline": False})
        elif count:
            # motd fallback: counts only, no package list available.
            fields.append({"name": "Packages", "value": "_not listed (counts read from the daily motd summary)_", "inline": False})
        if apt["reboot_required"]:
            pkgs = ", ".join(apt["reboot_pkgs"][:10]) if apt["reboot_pkgs"] else ""
            fields.append({"name": "♻️ Reboot required", "value": pkgs or "yes", "inline": False})

        footer = "vps-monitoring"
        if apt.get("last_update"):
            ago = system.format_duration(datetime.datetime.now().timestamp() - apt["last_update"])
            footer = f"apt lists refreshed {ago} ago"
        return {"title": f"📦 Updates — {self.host_label}", "description": desc, "color": color,
                "fields": fields, "footer": {"text": footer}}

    def _cmd_uptime(self):
        secs = system.uptime_seconds()
        up = system.format_duration(secs)
        one, five, fifteen = system.loadavg()
        boot = datetime.datetime.now() - datetime.timedelta(seconds=secs)
        return {
            "title": f"⏱️ Uptime — {self.host_label}",
            "color": COLOR_INFO,
            "description": f"Up **{up}**\nBooted {boot.strftime('%Y-%m-%d %H:%M')}\nLoad average: {one:.2f} / {five:.2f} / {fifteen:.2f}",
        }
