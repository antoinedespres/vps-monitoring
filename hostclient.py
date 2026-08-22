"""Access to the host this bot runs on.

The sibling pi-monitoring bot reaches its target over SSH; this one already
runs *on* the machine it reports about, so there is no transport - metrics are
read straight from the local kernel interfaces. The only thing in the way is
the container boundary, and each source crosses it differently:

  * ``/proc`` is reached through the host mount, at ``/host/proc`` - the bind
    is recursive, so the host's procfs comes with it, per-process entries and
    all. That deliberately avoids ``pid: host``, which would work too but makes
    apt skip Ubuntu's phased updates (it compares PID 1's root with its own,
    concludes it is in a chroot, and reports upgrades the host would defer).
  * Anything else that lives on disk - the apt/dpkg state, /run/reboot-required, the
    real filesystems - is only reachable through the read-only bind mount of
    the host root at ``HOST_ROOT`` (default /host).
  * Docker is queried over the mounted ``/var/run/docker.sock`` using the
    Engine API directly, so the image needs no docker CLI.

Accessors return an ``{"error": ...}`` marker rather than raising when their
mount is missing, so a partially-mounted deployment still answers the commands
it can.
"""
import http.client
import json
import logging
import os
import socket
import subprocess

logger = logging.getLogger("vps-monitoring")

HOST_ROOT = os.environ.get("HOST_ROOT", "/host").rstrip("/")
DOCKER_SOCKET = os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock")
COMMAND_TIMEOUT = int(os.environ.get("HOST_COMMAND_TIMEOUT", "30"))

DOCKER_API_VERSION = "v1.41"


class HostUnavailable(Exception):
    """A local command could not be run at all (missing binary, timeout)."""


# --------------------------------------------------------------------------- #
# Host filesystem (read-only bind mount of / at HOST_ROOT)
# --------------------------------------------------------------------------- #
def host_path(path):
    """Translate an absolute host path into its path inside this container."""
    return f"{HOST_ROOT}{path}" if HOST_ROOT else path


def host_mounted():
    """True when the host root really is bind-mounted. Tested with ismount
    rather than a plain exists() so that an empty /host directory - which is
    what a deployment that forgot the volume looks like - reports honestly."""
    if not HOST_ROOT:
        return True  # running outside a container: host paths are just paths
    return os.path.ismount(HOST_ROOT)


def read_text(path, default=""):
    """Read a file, returning `default` if it is missing or unreadable."""
    try:
        with open(path, "r") as fh:
            return fh.read()
    except OSError:
        return default


def read_host_text(path, default=""):
    return read_text(host_path(path), default)


# --------------------------------------------------------------------------- #
# procfs
# --------------------------------------------------------------------------- #
_proc_root = None


def proc_root():
    """The host's /proc - via the host mount when it is there, else our own
    (which still reports host-wide figures for the aggregate files, just not
    the host's processes). Resolved once; mounts don't come and go."""
    global _proc_root
    if _proc_root is None:
        mounted = host_path("/proc")
        _proc_root = mounted if HOST_ROOT and os.path.exists(f"{mounted}/stat") else "/proc"
    return _proc_root


def read_proc(name, default=""):
    return read_text(f"{proc_root()}/{name}", default)


def proc_pids():
    try:
        return [entry for entry in os.listdir(proc_root()) if entry.isdigit()]
    except OSError:
        return []


# --------------------------------------------------------------------------- #
# Local commands
# --------------------------------------------------------------------------- #
def run(command, timeout=COMMAND_TIMEOUT):
    """Run a shell command in this container. Returns (exit_code, stdout,
    stderr). Raises HostUnavailable only if it could not be run or timed out;
    a non-zero exit is returned normally so callers can degrade gracefully."""
    try:
        proc = subprocess.run(
            ["/bin/sh", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise HostUnavailable(f"command timed out after {timeout}s") from exc
    except OSError as exc:
        raise HostUnavailable(f"cannot run commands: {exc}") from exc
    return proc.returncode, proc.stdout, proc.stderr


# --------------------------------------------------------------------------- #
# Docker Engine API over the unix socket
# --------------------------------------------------------------------------- #
class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that dials a unix socket instead of a TCP host."""

    def __init__(self, socket_path, timeout=10):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


def docker_get(path, timeout=10):
    """GET a Docker Engine API endpoint. Returns the decoded JSON, or raises
    HostUnavailable with a human-readable reason if the socket isn't usable."""
    if not os.path.exists(DOCKER_SOCKET):
        raise HostUnavailable(f"Docker socket not mounted at {DOCKER_SOCKET}")
    conn = _UnixHTTPConnection(DOCKER_SOCKET, timeout=timeout)
    try:
        conn.request("GET", f"/{DOCKER_API_VERSION}{path}")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        if resp.status >= 300:
            raise HostUnavailable(f"Docker API returned {resp.status}: {body.strip()[:200]}")
        return json.loads(body)
    except PermissionError as exc:
        raise HostUnavailable("permission denied on the Docker socket") from exc
    except (OSError, ValueError) as exc:
        raise HostUnavailable(f"cannot query the Docker socket: {exc}") from exc
    finally:
        conn.close()
