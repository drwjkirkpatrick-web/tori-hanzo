"""Detection engine for Tori-Hanzo.

Takes one monitor observation + the CSV definitions + the persisted
baselines, and emits *findings* — structured, dedupeable alert records.

Finding shape:
    id, ts, type, severity, summary, details{}, status(open|ack|resolved)

Severity ladder: info < low < medium < high < critical

LEARN: detectors are pure functions of (observation, baselines, defs) —
they never touch the system and never persist anything.  The agent loop
owns all side effects (baselines, event log, auto-fixes), which keeps this
file easy to test and safe to reason about.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Findings on these files are always critical — they mean account takeover
# or auth bypass if tampered with.
_CRITICAL_INTEGRITY_PATHS = ("/etc/shadow", "/etc/passwd", "authorized_keys",
                             "sshd_config")


def _mk(finding_type: str, severity: str, summary: str,
        details: dict | None = None) -> dict:
    return {
        "id": uuid.uuid4().hex[:12],
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": finding_type,
        "severity": severity,
        "summary": summary,
        "details": details or {},
        "status": "open",
    }


def _mask(ip: str, salt: str) -> str:
    """Salted one-way token for an IP, used in finding *summaries*.

    Summaries end up in the Telegram daily report, so they must never
    carry raw IPs.  The raw address stays in details.connection where the
    localhost portal and the responder legitimately need it.
    """
    return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()[:12]


def finding_key(f: dict) -> str:
    """Stable dedupe key: same type + same summary = same ongoing issue."""
    raw = f"{f['type']}|{f['summary']}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _listener_severity(dispo: str, addr: str) -> str | None:
    """Map a listener's disposition + bind address to a severity."""
    if dispo in ("allow", "ignore"):
        return None
    if dispo == "allow-local":
        # Fine on loopback; suspicious when exposed to the network.
        if addr in ("127.0.0.1", "::1", "localhost"):
            return None
        return "high"
    if dispo == "deny":
        return "high"
    return "medium"  # default 'alert'


def detect_listener_deltas(obs: dict, baseline: dict, defs) -> tuple[list[dict], dict, int]:
    """Compare current listeners to the stored baseline.

    Returns (findings, new_baseline, udp_ignored_count).  UDP sockets in the
    ignore baseline are silently folded into the new baseline — this is the
    'ignore normal UDP churn' feature in action.
    """
    findings: list[dict] = []
    udp_ignored = 0
    current: dict[str, dict] = {}

    for sock in obs["listeners"]:
        key = sock["key"]
        if sock["proto"] == "udp" and defs.is_ignored_udp(sock["port"], sock["process"]):
            udp_ignored += 1
            current[key] = sock
            continue

        dispo = defs.port_disposition(sock["proto"], sock["port"], sock["process"])
        current[key] = sock
        if key in baseline:
            continue  # known socket — nothing to say

        sev = _listener_severity(dispo, sock["addr"])
        if sev is None:
            continue
        proc = sock["process"] or "unknown"
        findings.append(_mk(
            "new_listener", sev,
            f"New {sock['proto']} listener {sock['addr']}:{sock['port']} ({proc})",
            {"socket": sock, "disposition": dispo}))

    for key, old in baseline.items():
        if key not in current:
            findings.append(_mk(
                "removed_listener", "info",
                f"Listener gone: {key} ({old.get('process') or 'unknown'})",
                {"socket": old}))

    return findings, current, udp_ignored


def detect_process_threats(obs: dict, defs) -> list[dict]:
    """Match running command lines against process definitions."""
    findings = []
    for proc in obs["processes"]:
        hay = f"{proc['comm']} {proc['args']}"
        for rule in defs.process_verdicts(hay):
            if rule.disposition == "allow":
                continue
            sev = "high" if rule.disposition == "deny" else "medium"
            ftype = "rogue_process" if rule.disposition == "deny" \
                else "suspicious_process"
            findings.append(_mk(
                ftype, sev,
                f"{rule.name}: pid={proc['pid']} user={proc['user']} "
                f"cmd={proc['args'][:80]}",
                {"pid": proc["pid"], "user": proc["user"],
                 "rule": rule.name, "args": proc["args"][:200]}))
    return findings


def detect_intruders(obs: dict, defs, ssh_failed_threshold: int,
                     salt: str = "") -> list[dict]:
    """SSH brute force + denied-IP connections + unexpected remote sessions."""
    findings = []

    # 1) brute force from a single source (hashed)
    for ip_hash, count in obs["ssh"].get("failed_by_ip", {}).items():
        if count >= ssh_failed_threshold:
            findings.append(_mk(
                "ssh_bruteforce", "high",
                f"SSH brute force: {count} failures from source {ip_hash}",
                {"ip_hash": ip_hash, "failures": count}))

    # 2) successful logins (medium — worth eyeballing daily)
    for login in obs["ssh"].get("accepted", []):
        findings.append(_mk(
            "ssh_login", "medium",
            f"SSH login: {login['user']} from {login['ip_hash']}",
            dict(login)))

    # 3) established connections from deny-listed IPs
    for conn in obs["established"]:
        dispo = defs.ip_disposition(conn["remote_addr"])
        masked = _mask(conn["remote_addr"], salt)
        if dispo == "deny":
            findings.append(_mk(
                "denied_ip_connected", "critical",
                f"Denied IP connected: {masked} -> "
                f"port {conn['local_port']} ({conn['process'] or '?'})",
                {"connection": conn}))
        elif dispo == "alert":
            findings.append(_mk(
                "unknown_remote_connection", "low",
                f"Unknown remote {masked}:{conn['remote_port']} -> "
                f"local port {conn['local_port']} ({conn['process'] or '?'})",
                {"connection": conn}))
    return findings


def detect_integrity(integrity: dict) -> list[dict]:
    """Turn file-integrity diffs into findings."""
    findings = []
    for path in integrity["changed"]:
        critical = any(marker in path for marker in _CRITICAL_INTEGRITY_PATHS)
        findings.append(_mk(
            "file_integrity_change",
            "critical" if critical else "medium",
            f"Critical file changed: {path}" if critical
            else f"Watched file changed: {path}",
            {"path": path}))
    for path in integrity["missing"]:
        findings.append(_mk(
            "file_integrity_missing", "high",
            f"Watched file deleted: {path}", {"path": path}))
    return findings


def detect_kernel(obs: dict) -> list[dict]:
    findings = []
    for line in obs["kernel"].get("alerts", [])[:10]:
        findings.append(_mk("kernel_alert", "medium",
                            f"Kernel: {line[:120]}", {"line": line}))
    return findings


def detect_self_integrity(changed_files: list[str]) -> list[dict]:
    """The agent watching itself: source tampering is always high."""
    if not changed_files:
        return []
    return [_mk("self_integrity_change", "high",
                f"Tori-Hanzo source modified: {', '.join(changed_files[:5])}",
                {"files": changed_files})]


def evaluate(obs: dict, baselines: dict, defs, cfg,
             integrity: dict | None = None,
             self_changed: list[str] | None = None,
             salt: str = "") -> tuple[list[dict], dict, int]:
    """Run every detector over one observation.

    Returns (findings, new_listener_baseline, udp_ignored_count).
    """
    findings: list[dict] = []
    f, new_baseline, udp_ignored = detect_listener_deltas(
        obs, baselines.get("listeners", {}), defs)
    findings += f
    findings += detect_process_threats(obs, defs)
    findings += detect_intruders(obs, defs, cfg.ssh_failed_threshold,
                                 salt=salt)
    if integrity:
        findings += detect_integrity(integrity)
    findings += detect_kernel(obs)
    findings += detect_self_integrity(self_changed or [])
    return findings, new_baseline, udp_ignored
