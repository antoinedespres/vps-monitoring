"""Tail log files on the VPS and yield structured events for the alerting engine."""
import json
import os
import re
import time
from collections import Counter, defaultdict, deque

FAIL2BAN_BAN_RE = re.compile(r"NOTICE\s+\[(?P<jail>\S+)\]\s+Ban\s+(?P<ip>\S+)")
FAIL2BAN_UNBAN_RE = re.compile(r"NOTICE\s+\[(?P<jail>\S+)\]\s+Unban\s+(?P<ip>\S+)")

SSH_FAILED_RE = re.compile(r"Failed password for (?:invalid user )?\S+ from (?P<ip>\S+) port \d+")
SSH_INVALID_USER_RE = re.compile(r"Invalid user \S+ from (?P<ip>\S+) port \d+")
SSH_ACCEPTED_RE = re.compile(r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+")


def follow(path):
    """Yield new lines appended to `path`, like `tail -f`. Tolerates the file not existing yet."""
    f = None
    inode = None
    while True:
        try:
            if f is None:
                f = open(path, "r")
                inode = _inode(path)
                f.seek(0, 2)  # start at end of file
            line = f.readline()
            if line:
                yield line.rstrip("\n")
                continue
            # No new data: check for log rotation (inode changed) then sleep.
            if _inode(path) != inode:
                f.close()
                f = None
            time.sleep(1)
        except FileNotFoundError:
            f = None
            time.sleep(5)


def _inode(path):
    try:
        return os.stat(path).st_ino
    except FileNotFoundError:
        return None


class SlidingWindowCounter:
    """Counts events per key within a trailing time window."""

    def __init__(self, window_seconds):
        self.window_seconds = window_seconds
        self._hits = defaultdict(deque)

    def add(self, key, now=None):
        now = now if now is not None else time.time()
        hits = self._hits[key]
        hits.append(now)
        self._trim(key, now)
        return len(hits)

    def count(self, key, now=None):
        now = now if now is not None else time.time()
        self._trim(key, now)
        return len(self._hits[key])

    def _trim(self, key, now):
        hits = self._hits[key]
        while hits and now - hits[0] > self.window_seconds:
            hits.popleft()


class Fail2banBanEvents:
    """Watches fail2ban's log for Ban/Unban lines on a given jail."""

    def __init__(self, log_path, jail):
        self.log_path = log_path
        self.jail = jail

    def events(self):
        for line in follow(self.log_path):
            m = FAIL2BAN_BAN_RE.search(line)
            if m and m.group("jail") == self.jail:
                yield {"type": "ban", "ip": m.group("ip"), "jail": self.jail}
                continue
            m = FAIL2BAN_UNBAN_RE.search(line)
            if m and m.group("jail") == self.jail:
                yield {"type": "unban", "ip": m.group("ip"), "jail": self.jail}


class SSHBruteForceSuccess:
    """Correlates SSH auth failures with a subsequent Accepted login from the
    same IP, to flag a brute-force that actually got in. fail2ban already
    handles pure failure-rate detection/banning; this fills the gap it can't
    cover (an attacker who succeeds before hitting fail2ban's ban threshold)."""

    def __init__(self, log_path="/var/log/auth.log", window_seconds=600):
        self.log_path = log_path
        self.failures = SlidingWindowCounter(window_seconds)

    def events(self):
        for line in follow(self.log_path):
            m = SSH_FAILED_RE.search(line) or SSH_INVALID_USER_RE.search(line)
            if m:
                self.failures.add(m.group("ip"))
                continue
            m = SSH_ACCEPTED_RE.search(line)
            if m:
                ip = m.group("ip")
                recent_failures = self.failures.count(ip)
                yield {
                    "type": "accepted",
                    "ip": ip,
                    "user": m.group("user"),
                    "method": m.group("method"),
                    "recent_failures": recent_failures,
                }


class CaddyRequestRate:
    """Watches a Caddy JSON access log and reports, per poll, the per-IP
    request count within a sliding time window for a given host, plus the
    most-hit paths for that IP so alerts show what was actually targeted."""

    def __init__(self, log_path, host, window_seconds=300, top_n_paths=5):
        self.log_path = log_path
        self.host = host
        self.window_seconds = window_seconds
        self.top_n_paths = top_n_paths
        self._hits = defaultdict(deque)  # ip -> deque[timestamp]
        self._paths = defaultdict(Counter)  # ip -> Counter[path]

    def events(self):
        for line in follow(self.log_path):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            request = entry.get("request", {})
            if request.get("host") != self.host:
                continue
            ip = request.get("client_ip") or request.get("remote_ip")
            if not ip:
                continue
            now = time.time()
            hits = self._hits[ip]
            hits.append(now)
            while hits and now - hits[0] > self.window_seconds:
                hits.popleft()

            uri = request.get("uri", "")
            path = uri.split("?", 1)[0]
            self._paths[ip][path] += 1

            top_paths = ", ".join(f"{p} ({n})" for p, n in self._paths[ip].most_common(self.top_n_paths))
            yield {
                "type": "request_rate",
                "ip": ip,
                "host": self.host,
                "count": len(hits),
                "top_paths": top_paths,
            }


class CaddyLoginOutcomes:
    """Watches Caddy's access log for the Home Assistant login flow and flags
    every successful login (POST /auth/token), tagging it with how many login
    attempts (POST /auth/login_flow/...) that same IP made just before it."""

    def __init__(self, log_path, host, window_seconds=600):
        self.log_path = log_path
        self.host = host
        self.attempts = SlidingWindowCounter(window_seconds)

    def events(self):
        for line in follow(self.log_path):
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            request = entry.get("request", {})
            if request.get("host") != self.host:
                continue
            ip = request.get("client_ip") or request.get("remote_ip")
            if not ip:
                continue
            uri = request.get("uri", "")
            method = request.get("method")

            if method == "POST" and uri.startswith("/auth/login_flow"):
                self.attempts.add(ip)
                continue

            if method == "POST" and uri.startswith("/auth/token") and entry.get("status") == 200:
                yield {
                    "type": "login_success",
                    "ip": ip,
                    "recent_attempts": self.attempts.count(ip),
                }
