"""Read-only system collectors for Tori-Hanzo.

Every collector follows the same contract:

    parse_* (pure function)  — text -> structured data (unit-tested)
    collect_* (thin wrapper) — runs the command, feeds text to the parser

Splitting parsing from execution means the whole detection pipeline can be
tested offline with canned `ss`/`journalctl` output — no root, no network,
no side effects.  LEARN: collectors must never modify the system, and must
never raise.  On any failure they return an empty result plus an "error"
note so the report can say "unavailable" instead of crashing.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path

CMD_TIMEOUT = 25  # seconds; a hung journalctl must not stall the agent


# ----------------------------------------------------------------------
# command runner (injectable for tests)
# ----------------------------------------------------------------------
def run_command(cmd: list[str], timeout: int = CMD_TIMEOUT) -> tuple[int, str, str]:
    """Run a command, never raising.  Returns (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)


# ----------------------------------------------------------------------
# listening sockets — `ss -lntupH`
# ----------------------------------------------------------------------
# Tolerant of the optional users:(("proc",pid=…)) trailer, which requires
# privileges and may be absent for other users' sockets.
_SS_USERS_RE = re.compile(r'users:\(\("(?P<proc>[^"]{0,256})"(?:,pid=(?P<pid>\d+))?')


def _split_addr_port(addr: str) -> tuple[str, str]:
    """Split 'host:port' including IPv6 forms like [::1]:8642 or *:80.

    Order matters: peel the port off FIRST, then strip any %zone suffix
    from the host ('fe80::1%eth0', '127.0.0.53%lo') — doing it the other
    way round eats the port.
    """
    addr = addr.strip()
    if addr.startswith("["):
        host, _, rest = addr[1:].partition("]:")
    else:
        host, _, rest = addr.rpartition(":")
    if "%" in host:
        host = host.split("%", 1)[0]
    return host, rest


def parse_ss_listening(text: str) -> list[dict]:
    """Parse `ss -lntupH` output into socket dicts."""
    sockets = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        if proto not in ("tcp", "udp"):
            continue
        host, port = _split_addr_port(parts[4])
        if not port.isdigit():
            continue
        proc, pid = "", None
        m = _SS_USERS_RE.search(line)
        if m:
            proc = m.group("proc")
            if m.group("pid"):
                pid = int(m.group("pid"))
        sockets.append({
            "proto": proto, "addr": host, "port": int(port),
            "process": proc, "pid": pid,
            "key": f"{proto}:{host}:{port}",
        })
    return sockets


def collect_listening_ports(run=run_command) -> list[dict]:
    rc, out, _ = run(["ss", "-lntupH"])
    if rc != 0:
        return []
    return parse_ss_listening(out)


# ----------------------------------------------------------------------
# established connections — `ss -tnpH state established`
# ----------------------------------------------------------------------
def parse_ss_established(text: str) -> list[dict]:
    """Parse established TCP connections (the 'who is talking to us' view).

    Column layout: Netid State Recv-Q Send-Q Local Peer Process — so the
    local address is field 4 and the peer is field 5.
    """
    conns = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6 or parts[0].lower() != "tcp":
            continue
        local_host, local_port = _split_addr_port(parts[4])
        peer_host, peer_port = _split_addr_port(parts[5])
        if not peer_port.isdigit():
            continue
        proc, pid = "", None
        m = _SS_USERS_RE.search(line)
        if m:
            proc = m.group("proc")
            if m.group("pid"):
                pid = int(m.group("pid"))
        conns.append({
            "local_addr": local_host,
            "local_port": int(local_port) if local_port.isdigit() else None,
            "remote_addr": peer_host, "remote_port": int(peer_port),
            "process": proc, "pid": pid,
        })
    return conns


def collect_established(run=run_command) -> list[dict]:
    rc, out, _ = run(["ss", "-tnpH", "state", "established"])
    if rc != 0:
        return []
    return parse_ss_established(out)


# ----------------------------------------------------------------------
# processes — `ps -eo pid,ppid,user,comm,args`
# ----------------------------------------------------------------------
def parse_ps(text: str, max_args: int = 512) -> list[dict]:
    procs = []
    for line in text.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5 or not parts[0].isdigit():
            continue
        procs.append({
            "pid": int(parts[0]), "ppid": int(parts[1]),
            "user": parts[2], "comm": parts[3],
            "args": parts[4][:max_args],
        })
    return procs


def collect_processes(run=run_command, max_args: int = 512) -> list[dict]:
    rc, out, _ = run(
        ["ps", "-eo", "pid=,ppid=,user=,comm=,args="])
    if rc != 0:
        return []
    return parse_ps(out, max_args)


# ----------------------------------------------------------------------
# logged-in users — `who`
# ----------------------------------------------------------------------
def parse_who(text: str) -> list[dict]:
    """'walker pts/0 2026-07-18 10:04 (192.168.1.20)' -> dict."""
    users = []
    for line in text.splitlines():
        m = re.match(r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+"
                     r"(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})"
                     r"(?:\s+\((?P<host>[^)]+)\))?", line)
        if m:
            users.append({
                "user": m.group("user"), "tty": m.group("tty"),
                "since": m.group("ts"), "host": m.group("host") or "local",
            })
    return users


def collect_logged_in_users(run=run_command) -> list[dict]:
    rc, out, _ = run(["who"])
    if rc != 0:
        return []
    return parse_who(out)


# ----------------------------------------------------------------------
# SSH + sudo journals
# ----------------------------------------------------------------------
_SSH_FAILED_RE = re.compile(
    r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+|[0-9a-fA-F:]+)")
_SSH_ACCEPTED_RE = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+|[0-9a-fA-F:]+)")
_SUDO_CMD_RE = re.compile(r"COMMAND=(?P<cmd>.+)$")
_SUDO_USER_RE = re.compile(r"^\S+\s+\S+\s+\S+\s+(?P<user>\S+)\s*:")


def hash_ip(ip: str, salt: str) -> str:
    """One-way, per-install-stable IP token for privacy-safe reporting."""
    return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()[:12]


def parse_ssh_journal(text: str, salt: str) -> dict:
    """Extract SSH auth stats.  Raw IPs are hashed immediately — they are
    only ever needed in identifiable form inside the localhost portal."""
    failed, accepted = 0, []
    failed_by_ip: dict[str, int] = {}
    for line in text.splitlines():
        m = _SSH_FAILED_RE.search(line)
        if m:
            failed += 1
            token = hash_ip(m.group("ip"), salt)
            failed_by_ip[token] = failed_by_ip.get(token, 0) + 1
            continue
        m = _SSH_ACCEPTED_RE.search(line)
        if m:
            accepted.append({"user": m.group("user"),
                             "ip_hash": hash_ip(m.group("ip"), salt)})
    return {
        "failed": failed,
        "success": len(accepted),
        "failed_by_ip": failed_by_ip,
        "accepted": accepted[:20],
    }


def collect_ssh(hours: int, salt: str, run=run_command) -> dict:
    since = f"-{hours}h"
    rc, out, _ = run(["journalctl", "SYSLOG_IDENTIFIER=sshd",
                      "--since", since, "--no-pager"])
    if rc != 0:
        # Fallback for systems where the unit is named differently.
        rc, out, _ = run(["journalctl", "-u", "ssh.service",
                          "--since", since, "--no-pager"])
    if rc != 0:
        return {"failed": 0, "success": 0, "failed_by_ip": {},
                "accepted": [], "error": "journal unavailable"}
    return parse_ssh_journal(out, salt)


def parse_sudo_journal(text: str) -> dict:
    commands = []
    for line in text.splitlines():
        m = _SUDO_CMD_RE.search(line)
        if not m:
            continue
        u = _SUDO_USER_RE.search(line)
        commands.append({"user": u.group("user") if u else "?",
                         "command": m.group("cmd").strip()[:200]})
    return {"count": len(commands), "commands": commands[:25]}


def collect_sudo(hours: int, run=run_command) -> dict:
    rc, out, _ = run(["journalctl", "SYSLOG_IDENTIFIER=sudo",
                      "--since", f"-{hours}h", "--no-pager"])
    if rc != 0:
        return {"count": 0, "commands": [], "error": "journal unavailable"}
    return parse_sudo_journal(out)


# ----------------------------------------------------------------------
# kernel log watch
# ----------------------------------------------------------------------
_KERNEL_ALERT_RE = re.compile(
    r"(segfault|apparmor=\"DENIED\"|selinux.*denied|oom-kill|"
    r"possible rootkit|suspicious|module verification failed|"
    r"loading out-of-tree module)", re.IGNORECASE)


def parse_kernel_journal(text: str, max_lines: int = 200) -> dict:
    alerts = []
    for line in text.splitlines():
        if _KERNEL_ALERT_RE.search(line):
            # Keep the message short and control-char free.
            clean = re.sub(r"[\x00-\x1f]", " ", line).strip()[:240]
            alerts.append(clean)
            if len(alerts) >= max_lines:
                break
    return {"alerts": alerts, "count": len(alerts)}


def collect_kernel(hours: int, run=run_command,
                   max_lines: int = 200) -> dict:
    rc, out, _ = run(["journalctl", "-k", "--since", f"-{hours}h",
                      "--no-pager"])
    if rc != 0:
        return {"alerts": [], "count": 0, "error": "journal unavailable"}
    return parse_kernel_journal(out, max_lines)


# ----------------------------------------------------------------------
# file integrity
# ----------------------------------------------------------------------
def sha256_file(path: Path) -> str | None:
    """Streaming hash; None on any read failure (missing, permission…)."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def check_file_integrity(paths: list[str], baseline: dict) -> dict:
    """Diff current hashes against the stored baseline.

    Returns changed/new/missing/skipped lists.  Permission-denied paths are
    skipped quietly — root-owned files must never abort the check.
    """
    changed, new, missing, skipped = [], [], [], []
    current: dict[str, str] = {}
    for p in paths:
        path = Path(p)
        digest = sha256_file(path)
        if digest is None:
            if path.exists():
                skipped.append(p)          # exists but unreadable
            elif p in baseline:
                missing.append(p)          # was there, now gone
            continue
        current[p] = digest
        old = baseline.get(p)
        if old is None:
            new.append(p)
        elif old != digest:
            changed.append(p)
    return {"changed": changed, "new": new, "missing": missing,
            "skipped": skipped, "current": current}


# ----------------------------------------------------------------------
# full observation snapshot
# ----------------------------------------------------------------------
def snapshot(cfg, salt: str, run=run_command) -> dict:
    """One complete read-only observation of the host."""
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "listeners": collect_listening_ports(run),
        "established": collect_established(run),
        "processes": collect_processes(run, cfg.max_process_args_len),
        "users": collect_logged_in_users(run),
        "ssh": collect_ssh(cfg.lookback_hours, salt, run),
        "sudo": collect_sudo(cfg.lookback_hours, run),
        "kernel": collect_kernel(cfg.lookback_hours, run,
                                 cfg.max_kernel_lines),
    }
