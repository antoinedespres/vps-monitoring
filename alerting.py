"""Alert state machine + Discord embed delivery:
OK -> WARN -> CRITICAL -> (recovered to) OK monitor lifecycle."""
import datetime
import logging

import requests

logger = logging.getLogger("vps-monitoring")

OK, WARNING, CRITICAL, INFO = "OK", "WARNING", "CRITICAL", "INFO"

COLOR = {
    OK: 0x2ECC71,       # green
    WARNING: 0xE67E22,  # orange
    CRITICAL: 0xE74C3C,  # red
    INFO: 0x3498DB,     # blue - standalone audit notice, not part of a monitor's state
}
EMOJI = {OK: "✅", WARNING: "⚠️", CRITICAL: "\U0001F6A8", INFO: "\U0001F535"}


class DiscordNotifier:
    def __init__(self, bot_token, channel_id):
        self.channel_id = channel_id
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bot {bot_token}",
            "Content-Type": "application/json",
        })

    def send_embed(self, title, description, fields, state):
        payload = {
            "embeds": [{
                "title": f"{EMOJI[state]} {title}",
                "description": description,
                "color": COLOR[state],
                "fields": [{"name": k, "value": str(v), "inline": True} for k, v in fields.items()],
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "footer": {"text": "vps-monitoring"},
            }]
        }
        url = f"https://discord.com/api/v10/channels/{self.channel_id}/messages"
        resp = self.session.post(url, json=payload, timeout=10)
        if resp.status_code >= 300:
            logger.error("Discord API error %s: %s", resp.status_code, resp.text)
        else:
            logger.info("Alert sent: %s [%s]", title, state)


class Monitor:
    """One named monitor tracking OK/WARNING/CRITICAL state, only notifying on transitions."""

    def __init__(self, name, notifier, warn_threshold, crit_threshold, metric_label):
        self.name = name
        self.notifier = notifier
        self.warn_threshold = warn_threshold
        self.crit_threshold = crit_threshold
        self.metric_label = metric_label
        self.state = OK
        self.context = {}

    def update(self, value, context=None):
        context = context or {}
        new_state = OK
        if value >= self.crit_threshold:
            new_state = CRITICAL
        elif value >= self.warn_threshold:
            new_state = WARNING

        if new_state == self.state:
            return

        previous = self.state
        self.state = new_state
        self.context = context

        if new_state == OK:
            title = f"{self.name}: recovered"
            description = f"Back to normal (was {previous})."
        elif new_state == WARNING:
            title = f"{self.name}: elevated activity"
            description = f"{self.metric_label} crossed the warning threshold."
        else:
            title = f"{self.name}: brute-force suspected"
            description = f"{self.metric_label} crossed the critical threshold."

        fields = {self.metric_label: value, "Warn at": self.warn_threshold, "Critical at": self.crit_threshold}
        fields.update(context)
        self.notifier.send_embed(title, description, fields, new_state)

    def force(self, state, title, description, context=None):
        """For event-driven sources (e.g. fail2ban ban/unban) that don't map to a single numeric value."""
        if state == self.state:
            return
        self.state = state
        self.notifier.send_embed(title, description, context or {}, state)
