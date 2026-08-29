"""Host metric collection.

The read-only half of the bot: the same kind of view pi-monitoring gives of the
Raspberry Pi, but for the VPS this process is running on. Sources are the local
kernel interfaces rather than SSH - see hostclient.py for how each one crosses
the container boundary.

Collectors that depend on a mount that may be absent return an
``{"error": ...}`` marker instead of raising, so `/status` still renders the
fields it does have.
"""
import os
import re
import time

import hostclient
from hostclient import HostUnavailable

CLK_TCK = os.sysconf("SC_CLK_TCK")
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")


# --------------------------------------------------------------------------- #
# CPU / load / uptime  (/proc aggregates - host-wide even inside a container)
# --------------------------------------------------------------------------- #
def _cpu_totals():
    for line in hostclient.read_proc("stat").splitlines():
        if line.startswith("cpu "):
            nums = [int(x) for x in line.split()[1:]]
            idle = nums[3] + (nums[4] if len(nums) > 4 else 0)  # idle + iowait
            return idle, sum(nums)
    return 0, 0


def cpu_percent(sample_seconds=0.3):
    """Overall CPU utilisation, sampled over a short window."""
    idle1, total1 = _cpu_totals()
    time.sleep(sample_seconds)
    idle2, total2 = _cpu_totals()
    dtotal = total2 - total1
    if dtotal <= 0:
        return 0.0
    return round(100.0 * (1.0 - (idle2 - idle1) / dtotal), 1)


def cpu_count():
    return os.cpu_count() or 1


def loadavg():
    one, five, fifteen = hostclient.read_proc("loadavg", "0 0 0").split()[:3]
    return float(one), float(five), float(fifteen)


def uptime_seconds():
    return float(hostclient.read_proc("uptime", "0").split()[0])


def format_duration(seconds):
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


# --------------------------------------------------------------------------- #
# Memory
# --------------------------------------------------------------------------- #
def meminfo():
    info = {}
    for line in hostclient.read_proc("meminfo").splitlines():
        key, _, rest = line.partition(":")
        if rest.strip():
            info[key] = int(rest.split()[0]) * 1024  # kB -> bytes
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", info.get("MemFree", 0))
    used = total - available
    swap_total = info.get("SwapTotal", 0)
    swap_free = info.get("SwapFree", 0)
    return {
        "total": total,
        "available": available,
        "used": used,
        "percent": round(100.0 * used / total, 1) if total else 0.0,
        "swap_total": swap_total,
        "swap_used": swap_total - swap_free,
        "swap_percent": round(100.0 * (swap_total - swap_free) / swap_total, 1) if swap_total else 0.0,
    }


# --------------------------------------------------------------------------- #
# Temperature (usually absent on a virtualised VPS - None is the normal answer)
# --------------------------------------------------------------------------- #
def temperature_c():
    raw = hostclient.read_text("/sys/class/thermal/thermal_zone0/temp").strip()
    if not raw:
        raw = hostclient.read_host_text("/sys/class/thermal/thermal_zone0/temp").strip()
    return round(int(raw) / 1000.0, 1) if raw.isdigit() else None


# --------------------------------------------------------------------------- #
# Disk
#
# The root filesystem is measured with statvfs on the bind mount itself, so it
# is reported whatever its type - `df`'s job here is only to enumerate the
# *other* host filesystems. Both run inside the container, so host mounts show
# up at their mounted-through paths under HOST_ROOT (/host, /host/boot/efi,
# ...); rows outside that prefix belong to this container and are dropped, and
# the prefix is stripped so paths read as they do on the host.
# --------------------------------------------------------------------------- #
DF_COMMAND = "df -P -B1 -x tmpfs -x devtmpfs -x overlay -x squashfs -x aufs 2>/dev/null | tail -n +2"


def _statvfs_usage(path, label):
    try:
        st = os.statvfs(path)
    except OSError as exc:
        return {"path": label, "error": f"cannot stat {label}: {exc.strerror}"}
    total = st.f_blocks * st.f_frsize
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    return {
        "path": label,
        "total": total,
        "used": used,
        "free": st.f_bavail * st.f_frsize,
        "percent": round(100.0 * used / total, 1) if total else 0.0,
    }


def _is_noise(mount):
    """Mounts that are real but not worth reporting: snap loopbacks, and
    Docker's per-container internals (which appear under the host mount once
    other containers are running)."""
    return mount.startswith("/snap") or mount.startswith("/var/lib/docker/")


def disk_usages():
    prefix = hostclient.HOST_ROOT
    root = prefix or "/"
    if not hostclient.host_mounted():
        return [{"path": "/", "error": f"host filesystems not visible (is / bind-mounted at {root}?)"}]

    results = [_statvfs_usage(root, "/")]
    seen = {"/"}

    _, out, _ = hostclient.run(DF_COMMAND)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        mount = parts[5]
        if prefix:
            if mount.startswith(prefix + "/"):
                mount = mount[len(prefix):]
            else:
                continue  # a mount of this container, not of the host
        total, used, free = int(parts[1]), int(parts[2]), int(parts[3])
        if total == 0 or mount in seen or _is_noise(mount):
            continue
        seen.add(mount)
        results.append({
            "path": mount,
            "total": total,
            "used": used,
            "free": free,
            "percent": round(100.0 * used / total, 1) if total else 0.0,
        })
    results.sort(key=lambda u: u["path"])
    return results


def disk_usage(path="/"):
    for usage in disk_usages():
        if usage["path"] == path:
            return usage
    return {"path": path, "error": f"no filesystem mounted at {path}"}


# --------------------------------------------------------------------------- #
# Processes
#
# Read from /proc directly rather than shelling out to ps: it keeps the image
# free of procps, and sampling utime/stime twice gives a real instantaneous CPU
# share (what `top` shows) instead of ps's process-lifetime average. The host's
# processes come from the host mount's procfs - see hostclient.proc_root.
# --------------------------------------------------------------------------- #
def _proc_stat(pid):
    """(comm, utime+stime in ticks, rss in bytes) for one pid, or None if it
    exited while we were reading it."""
    raw = hostclient.read_proc(f"{pid}/stat")
    head, _, rest = raw.rpartition(")")  # comm can contain spaces and parens
    if not rest:
        return None
    comm = head.partition("(")[2]
    fields = rest.split()
    if len(fields) < 22:
        return None
    try:
        return comm, int(fields[11]) + int(fields[12]), int(fields[21]) * PAGE_SIZE
    except ValueError:
        return None


def top_by_cpu(n=5, sample_seconds=0.3):
    first = {}
    for pid in hostclient.proc_pids():
        stat = _proc_stat(pid)
        if stat:
            first[pid] = stat[1]

    time.sleep(sample_seconds)

    rows = []
    for pid, ticks_before in first.items():
        stat = _proc_stat(pid)
        if not stat:
            continue
        comm, ticks_now, _ = stat
        percent = 100.0 * (ticks_now - ticks_before) / CLK_TCK / sample_seconds
        if percent > 0:
            rows.append((round(percent, 1), comm, pid))
    rows.sort(reverse=True)
    return rows[:n]


def top_by_mem(n=5):
    rows = []
    for pid in hostclient.proc_pids():
        stat = _proc_stat(pid)
        if stat and stat[2] > 0:
            rows.append((stat[2], stat[0], pid))
    rows.sort(reverse=True)
    return rows[:n]


# --------------------------------------------------------------------------- #
# Docker (Engine API over the mounted socket)
# --------------------------------------------------------------------------- #
def docker_containers():
    """All containers on the host. Returns a list of dicts, or a dict with an
    `error` key if the socket isn't mounted/permitted."""
    try:
        raw = hostclient.docker_get("/containers/json?all=1")
    except HostUnavailable as exc:
        return {"error": str(exc)}

    containers = []
    for c in raw:
        names = c.get("Names") or []
        name = names[0].lstrip("/") if names else c.get("Id", "?")[:12]
        status = c.get("Status", "")
        m = re.search(r"\((healthy|unhealthy|starting)\)", status)
        containers.append({
            "name": name,
            "state": c.get("State") or ("running" if status.startswith("Up") else "exited"),
            "status": status,
            "health": m.group(1) if m else None,
            "image": c.get("Image", "?"),
        })
    containers.sort(key=lambda c: c["name"])
    return containers


# --------------------------------------------------------------------------- #
# APT updates
#
# The container has its own apt, but the interesting state is the host's, so
# apt-get is pointed at the host tree via `-o Dir` (the package list and dpkg
# status formats are shared across Debian/Ubuntu). Dir::Cache goes to /tmp
# because the host mount is read-only, and NoLocking stops apt trying to
# create lock files there. Dir::Bin::dpkg stays on the container's own dpkg -
# the host binary would not run against this image's libc.
#
# If that fails, fall back to update-notifier's motd counts, which Ubuntu
# refreshes daily - fewer details, but better than nothing.
# --------------------------------------------------------------------------- #
UPDATES_AVAILABLE = "/var/lib/update-notifier/updates-available"


def _apt_command():
    root = hostclient.HOST_ROOT or "/"
    return (
        "mkdir -p /tmp/apt-cache/archives/partial 2>/dev/null; "
        "apt-get -s dist-upgrade "
        f"-o Dir={root} "
        "-o Dir::Cache=/tmp/apt-cache "
        "-o Dir::Bin::dpkg=/usr/bin/dpkg "
        "-o Debug::NoLocking=1"
    )


def _motd_counts():
    """(total, security) parsed from update-notifier's motd file, or None."""
    text = hostclient.read_host_text(UPDATES_AVAILABLE)
    if not text.strip():
        return None
    total = re.search(r"(\d+)\s+updates?\s+can be applied", text)
    security = re.search(r"(\d+)\s+of these updates (?:are|is)\s+.*security", text)
    if not total:
        return None
    return int(total.group(1)), int(security.group(1)) if security else 0


def reboot_state():
    """(required, packages) - the flag file a package update drops when its
    change only takes effect after a reboot. Cheap: two stat calls, so the
    upgrade reporter can ask without paying for a full apt simulation."""
    required = os.path.exists(hostclient.host_path("/run/reboot-required")) or \
        os.path.exists(hostclient.host_path("/var/run/reboot-required"))
    packages = []
    if required:
        raw = hostclient.read_host_text("/run/reboot-required.pkgs") or \
            hostclient.read_host_text("/var/run/reboot-required.pkgs")
        packages = sorted({p.strip() for p in raw.splitlines() if p.strip()})
    return required, packages


def apt_status():
    reboot, reboot_pkgs = reboot_state()
    base = {"reboot_required": reboot, "reboot_pkgs": reboot_pkgs}

    if not hostclient.host_mounted():
        return {**base, "error": f"host root not mounted at {hostclient.HOST_ROOT}"}
    if not os.path.exists(hostclient.host_path("/var/lib/dpkg/status")):
        return {**base, "error": "no dpkg database on the host - not a Debian/Ubuntu system?"}

    try:
        code, out, err = hostclient.run(_apt_command())
    except HostUnavailable as exc:
        code, out, err = 1, "", str(exc)

    if code != 0:
        counts = _motd_counts()
        if counts is None:
            reason = (err or out).strip().splitlines()
            return {**base, "error": reason[-1][:200] if reason else "apt simulation failed"}
        total, security = counts
        return {**base, "count": total, "security_count": security, "packages": [],
                "stale": True, "last_update": _apt_lists_mtime()}

    packages = [
        {"name": line.split()[1], "security": "security" in line.lower()}
        for line in out.splitlines() if line.startswith("Inst ")
    ]
    return {
        **base,
        "count": len(packages),
        "security_count": sum(1 for p in packages if p["security"]),
        "packages": packages,
        "stale": False,
        "last_update": _apt_lists_mtime(),
    }


def _apt_lists_mtime():
    try:
        return os.stat(hostclient.host_path("/var/lib/apt/lists")).st_mtime
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# APT history (what was actually installed, not just what is pending)
# --------------------------------------------------------------------------- #
HISTORY_LOG = "/var/log/apt/history.log"

# "wget:amd64 (1.25.0-2ubuntu4.3, 1.25.0-2ubuntu4.4)" -> name, versions.
# Matched per package rather than split on commas, because the version pairs
# contain commas themselves.
_HISTORY_PKG_RE = re.compile(r"([^\s,()]+?)(?::[a-z0-9]+)?\s+\(([^)]*)\)")


def _norm_ts(value):
    """history.log separates date and time with two spaces; collapse it so the
    fixed-width timestamps compare correctly as plain strings."""
    return " ".join(value.split()) if value else ""


def _parse_history_packages(value):
    packages = []
    for name, versions in _HISTORY_PKG_RE.findall(value or ""):
        parts = [v.strip() for v in versions.split(",")]
        # Upgrades read "(old, new)"; installs read "(version)" or
        # "(version, automatic)" when the package came in as a dependency.
        if len(parts) == 2 and parts[1] != "automatic":
            packages.append({"name": name, "old": parts[0], "new": parts[1]})
        else:
            packages.append({"name": name, "old": None, "new": parts[0]})
    return packages


def apt_history():
    """Recent apt transactions, parsed from the host's /var/log/apt/history.log.

    Returns {"runs": [...], "quiet_seconds": ...}, or an {"error": ...} marker.

    `quiet_seconds` is how long the log has been idle, taken from its mtime.
    That is an epoch comparison, so it holds whatever timezones the host and
    this container are in - they need not agree, and this one is UTC while the
    host's is whatever it is. Entry timestamps stay as the log's own strings
    and are only ever compared with each other, never with a clock.

    `unattended` marks a run started by unattended-upgrades. Its --dry-run
    simulations land in this log too, and are deliberately excluded - reporting
    them would announce upgrades that were never installed.
    """
    if not hostclient.host_mounted():
        return {"error": f"host root not mounted at {hostclient.HOST_ROOT}"}
    path = hostclient.host_path(HISTORY_LOG)
    try:
        quiet_seconds = time.time() - os.stat(path).st_mtime
    except OSError as exc:
        return {"error": f"cannot read {HISTORY_LOG}: {exc}"}

    runs = []
    for block in re.split(r"\n\s*\n", hostclient.read_text(path)):
        entry = {}
        for line in block.splitlines():
            key, sep, value = line.partition(":")
            if sep and key and not key[0].isspace():
                entry[key.strip()] = value.strip()
        start = _norm_ts(entry.get("Start-Date", ""))
        if not start:
            continue
        commandline = entry.get("Commandline", "")
        runs.append({
            "start": start,
            "end": _norm_ts(entry.get("End-Date", "")) or start,
            "commandline": commandline,
            "requested_by": entry.get("Requested-By"),
            "unattended": (commandline.startswith("/usr/bin/unattended-upgrade")
                           and "--dry-run" not in commandline),
            "upgrade": _parse_history_packages(entry.get("Upgrade")),
            "install": _parse_history_packages(entry.get("Install")),
            "remove": _parse_history_packages(
                " ".join(v for v in (entry.get("Remove"), entry.get("Purge")) if v)
            ),
            "error": entry.get("Error"),
        })
    runs.sort(key=lambda r: r["start"])
    return {"runs": runs, "quiet_seconds": quiet_seconds}


# --------------------------------------------------------------------------- #
# Formatting helpers
# --------------------------------------------------------------------------- #
def human_bytes(n):
    step = 1024.0
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < step:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= step
    return f"{n:.1f} PiB"
