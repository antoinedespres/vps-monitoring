"""Maintains a Discord Gateway connection purely so the bot shows as online
with a status. Alerts are still sent over plain REST (see alerting.py) -
this connection carries no events, it only exists for presence."""
import json
import logging
import threading
import time

import requests
import websocket

logger = logging.getLogger("vps-monitoring")

GATEWAY_VERSION = 10


class GatewayPresence:
    def __init__(self, token, status_text="for brute-force attempts"):
        self.token = token
        self.status_text = status_text
        self._stop = threading.Event()

    def start(self):
        threading.Thread(target=self._run_forever, daemon=True).start()

    def _run_forever(self):
        while not self._stop.is_set():
            try:
                self._connect_once()
            except Exception:
                logger.exception("Gateway presence connection error, reconnecting in 5s")
            time.sleep(5)

    def _gateway_url(self):
        resp = requests.get(
            "https://discord.com/api/v10/gateway/bot",
            headers={"Authorization": f"Bot {self.token}"},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["url"]

    def _connect_once(self):
        url = f"{self._gateway_url()}/?v={GATEWAY_VERSION}&encoding=json"
        ws = websocket.create_connection(url, timeout=30)
        try:
            hello = json.loads(ws.recv())
            interval = hello["d"]["heartbeat_interval"] / 1000

            ws.send(json.dumps({
                "op": 2,
                "d": {
                    "token": self.token,
                    "intents": 0,
                    "properties": {"os": "linux", "browser": "vps-monitoring", "device": "vps-monitoring"},
                    "presence": {
                        "since": None,
                        "activities": [{"name": self.status_text, "type": 3}],  # type 3 = Watching
                        "status": "online",
                        "afk": False,
                    },
                },
            }))
            logger.info("Gateway presence connected")

            last_heartbeat = time.time()
            ws.settimeout(1)
            while not self._stop.is_set():
                try:
                    msg = ws.recv()
                except websocket.WebSocketTimeoutException:
                    msg = None
                if msg:
                    data = json.loads(msg)
                    op = data.get("op")
                    if op == 1:  # server requested an immediate heartbeat
                        ws.send(json.dumps({"op": 1, "d": None}))
                    elif op in (7, 9):  # reconnect requested / invalid session
                        break
                if time.time() - last_heartbeat >= interval:
                    ws.send(json.dumps({"op": 1, "d": None}))
                    last_heartbeat = time.time()
        finally:
            ws.close()
