"""Active countermeasures for Tori-Hanzo.

Two actions exist, both wrapped in thick safety rails:

    kill_process(pid)  — SIGTERM, grace period, SIGKILL
    block_ip(ip)       — iptables INPUT drop rule (needs root)

Safety rails (LEARN — a security agent that can be tricked into killing
systemd is itself a vulnerability):
  1. Master switch: Config.active_response must be True, else dry-run only.
  2. Dry-run mode records the exact command that *would* run in the audit
     log and does nothing else.
  3. Protected process list (sshd, systemd, hermes, shells, …) + a minimum
     PID floor.  Refusals are logged, never silent.
  4. IPs are validated with the ipaddress module; loopback/private blocks
     require an explicit force flag so a spoofed finding can't cut off the
     admin's own LAN.
  5. Every attempt (success, refusal, dry-run) lands in state/actions.jsonl.
"""

from __future__ import annotations

import ipaddress
import os
import signal
import subprocess
import time
from datetime import datetime, timezone

from state import StateStore


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# Ranges we refuse to block without an explicit force flag.  Written out
# longhand instead of using ipaddress.is_private because Python counts the
# documentation TEST-NET ranges (192.0.2/24, 198.51.100/24, 203.0.113/24)
# as "private", which would make those impossible to block even in drills.
_LAN_NETWORKS = tuple(ipaddress.ip_network(c) for c in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC1918
    "169.254.0.0/16", "fe80::/10",                      # link-local
    "fc00::/7",                                         # IPv6 ULA
))


class Responder:
    def __init__(self, cfg, state: StateStore):
        self.cfg = cfg
        self.state = state

    # ------------------------------------------------------------------
    # process termination
    # ------------------------------------------------------------------
    def _process_info(self, pid: int) -> dict | None:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmdline = fh.read().replace(b"\x00", b" ").decode(
                    "utf-8", "replace").strip()
            with open(f"/proc/{pid}/comm") as fh:
                comm = fh.read().strip()
            return {"pid": pid, "comm": comm, "cmdline": cmdline[:300]}
        except OSError:
            return None

    def _refusal_reason(self, pid: int, info: dict | None) -> str | None:
        """None = allowed to kill; otherwise a human-readable refusal."""
        if pid < self.cfg.min_killable_pid:
            return f"pid {pid} below safety floor {self.cfg.min_killable_pid}"
        if pid == os.getpid():
            return "refusing to kill tori-hanzo itself"
        if info is None:
            return "process no longer exists"
        protected = {p.lower() for p in self.cfg.protected_processes}
        if info["comm"].lower() in protected:
            return f"'{info['comm']}' is on the protected list"
        # Extra belt-and-braces: never touch anything whose cmdline mentions
        # hermes or tori-hanzo — killing the things we protect defeats us.
        hay = info["cmdline"].lower()
        if "tori-hanzo" in hay or "hermes" in hay:
            return "cmdline references hermes/tori-hanzo — protected"
        return None

    def kill_process(self, pid: int, reason: str = "",
                     dry_run: bool | None = None) -> dict:
        """Terminate a process with prejudice (and safeguards)."""
        if dry_run is None:
            dry_run = not self.cfg.active_response
        info = self._process_info(pid)
        refusal = self._refusal_reason(pid, info)

        action = {"action": "kill_process", "pid": pid, "reason": reason,
                  "dry_run": dry_run, "process": info}

        if refusal:
            action.update(result="refused", detail=refusal)
            self.state.append_action(action)
            return action

        if dry_run:
            action.update(result="dry_run",
                          detail=f"would SIGTERM pid {pid} "
                                 f"({info['comm']}), SIGKILL after "
                                 f"{self.cfg.kill_grace_sec}s")
            self.state.append_action(action)
            return action

        try:
            os.kill(pid, signal.SIGTERM)
            deadline = time.time() + self.cfg.kill_grace_sec
            while time.time() < deadline:
                if self._process_info(pid) is None:
                    break
                time.sleep(0.1)
            if self._process_info(pid) is not None:
                os.kill(pid, signal.SIGKILL)
            action.update(result="killed",
                          detail=f"SIGTERM+SIGKILL pid {pid} ({info['comm']})")
        except OSError as exc:
            action.update(result="error", detail=str(exc))
        self.state.append_action(action)
        return action

    # ------------------------------------------------------------------
    # IP blocking
    # ------------------------------------------------------------------
    def block_ip(self, ip: str, reason: str = "", force: bool = False,
                 dry_run: bool | None = None) -> dict:
        """Drop all traffic from an IP via iptables (dry-run by default)."""
        if dry_run is None:
            dry_run = not self.cfg.active_response

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            action = {"action": "block_ip", "ip": ip, "result": "refused",
                      "detail": "not a valid IP address", "dry_run": dry_run}
            self.state.append_action(action)
            return action

        refusal = None
        if addr.is_loopback:
            refusal = "refusing to block loopback"
        elif any(addr in net for net in _LAN_NETWORKS) and not force:
            refusal = "private/LAN address requires force=True"
        elif addr.is_multicast or addr.is_unspecified:
            refusal = "refusing to block multicast/unspecified address"

        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        action = {"action": "block_ip", "ip": ip, "reason": reason,
                  "dry_run": dry_run, "command": " ".join(cmd)}

        if refusal:
            action.update(result="refused", detail=refusal)
        elif dry_run:
            action.update(result="dry_run",
                          detail=f"would run: {' '.join(cmd)}")
        else:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=15)
                if proc.returncode == 0:
                    action.update(result="blocked")
                    blocked = self.state.load_blocked_ips()
                    blocked.append({"ip": ip, "reason": reason,
                                    "ts": _utcnow()})
                    self.state.save_blocked_ips(blocked)
                else:
                    action.update(result="error",
                                  detail=proc.stderr.strip()[:200])
            except (OSError, subprocess.TimeoutExpired) as exc:
                action.update(result="error", detail=str(exc))
        self.state.append_action(action)
        return action

    def unblock_ip(self, ip: str, dry_run: bool | None = None) -> dict:
        """Remove a drop rule (companion to block_ip)."""
        if dry_run is None:
            dry_run = not self.cfg.active_response
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        action = {"action": "unblock_ip", "ip": ip, "dry_run": dry_run,
                  "command": " ".join(cmd)}
        if dry_run:
            action.update(result="dry_run",
                          detail=f"would run: {' '.join(cmd)}")
        else:
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=15)
                if proc.returncode == 0:
                    action.update(result="unblocked")
                    blocked = [b for b in self.state.load_blocked_ips()
                               if b.get("ip") != ip]
                    self.state.save_blocked_ips(blocked)
                else:
                    action.update(result="error",
                                  detail=proc.stderr.strip()[:200])
            except (OSError, subprocess.TimeoutExpired) as exc:
                action.update(result="error", detail=str(exc))
        self.state.append_action(action)
        return action

    # ------------------------------------------------------------------
    # fix engine — apply fixes.csv policy to a finding
    # ------------------------------------------------------------------
    def apply_fix(self, finding: dict, fix_rule, manual: bool = False) -> dict:
        """Execute the fix mapped to a finding type.

        Auto fixes only run when cfg.active_response is on AND the CSV row
        says auto=true.  Manual fixes (portal buttons) still respect the
        master switch — they run as dry-run when it's off, so the admin can
        rehearse a response safely.
        """
        if fix_rule is None:
            return {"result": "no_fix", "detail": "no fix rule for type "
                    f"{finding['type']}"}
        if not manual and not fix_rule.auto:
            return {"result": "skipped", "detail": "fix is not automatic"}

        dry_run = not self.cfg.active_response
        action = fix_rule.action
        details = finding.get("details", {})

        if action == "alert":
            return {"result": "alert_only"}
        if action == "kill_process":
            pid = details.get("pid")
            if not isinstance(pid, int):
                return {"result": "error", "detail": "finding has no pid"}
            return self.kill_process(pid, reason=finding["summary"],
                                     dry_run=dry_run)
        if action == "block_ip":
            conn = details.get("connection", {})
            ip = conn.get("remote_addr")
            if not ip:
                return {"result": "error", "detail": "finding has no remote ip"}
            return self.block_ip(ip, reason=finding["summary"],
                                 dry_run=dry_run)
        return {"result": "error", "detail": f"unknown action {action}"}
