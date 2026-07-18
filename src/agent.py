"""The Tori-Hanzo agent loop — ties monitor -> detector -> responder -> state.

One cycle:
    1. snapshot the host (read-only collectors)
    2. diff file integrity + self integrity against baselines
    3. evaluate detectors -> findings
    4. dedupe + persist findings
    5. apply automatic fixes from fixes.csv (gated by active_response)
    6. update baselines, write event log, record last run

LEARN: the loop is deliberately boring.  All cleverness lives in the pure
detector functions; this file only orchestrates and persists.  A boring
security loop is a trustworthy security loop.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import detector
import monitor
from definitions import DefinitionStore
from reporter import generate_daily_report, write_report
from responder import Responder
from state import StateStore, read_json, atomic_write_json


class Agent:
    def __init__(self, cfg, run=monitor.run_command):
        self.cfg = cfg
        self.state = StateStore(cfg.state_dir)
        self.defs = DefinitionStore(cfg.data_dir)
        self.responder = Responder(cfg, self.state)
        self.run = run  # injectable command runner (tests)

    # ------------------------------------------------------------------
    # self integrity: hash the agent's own source
    # ------------------------------------------------------------------
    def _self_manifest(self) -> dict[str, str]:
        manifest = {}
        src = Path(self.cfg.base_dir) / "src"
        files = sorted(src.glob("*.py")) + [Path(self.cfg.base_dir) / "tori-hanzo.py"]
        for f in files:
            digest = monitor.sha256_file(f)
            if digest:
                manifest[str(f.name)] = digest
        return manifest

    def _check_self_integrity(self) -> list[str]:
        path = Path(self.cfg.state_dir) / "self_manifest.json"
        old = read_json(path, {})
        new = self._self_manifest()
        changed = [name for name, digest in new.items()
                   if name in old and old[name] != digest]
        atomic_write_json(path, new)
        return changed

    # ------------------------------------------------------------------
    # one monitor cycle
    # ------------------------------------------------------------------
    def run_cycle(self) -> dict:
        cfg, state, defs = self.cfg, self.state, self.defs

        obs = monitor.snapshot(cfg, state.get_salt(), run=self.run)

        # file integrity
        fi_path = Path(cfg.state_dir) / "file_integrity.json"
        fi_baseline = read_json(fi_path, {})
        integrity = monitor.check_file_integrity(cfg.critical_files, fi_baseline)
        atomic_write_json(fi_path, integrity["current"])

        # self integrity
        self_changed = self._check_self_integrity()

        # listener baseline
        lb_path = Path(cfg.state_dir) / "listening_baseline.json"
        listener_baseline = read_json(lb_path, {})

        findings, new_lb, udp_ignored = detector.evaluate(
            obs, {"listeners": listener_baseline}, defs, cfg,
            integrity=integrity, self_changed=self_changed,
            salt=state.get_salt())
        atomic_write_json(lb_path, new_lb)

        # dedupe against existing open findings
        existing = state.load_findings()
        open_keys = set()
        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=cfg.finding_dedupe_hours)
        for f in existing:
            if f.get("status") != "open":
                continue
            try:
                ts = datetime.fromisoformat(f["ts"])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except (KeyError, ValueError):
                continue
            if ts >= cutoff:
                open_keys.add(detector.finding_key(f))

        new_findings = [f for f in findings
                        if detector.finding_key(f) not in open_keys]
        if new_findings:
            state.save_findings(new_findings + existing,
                                cap=cfg.max_findings)

        # automatic fixes per fixes.csv (dry-run unless active_response)
        auto_actions = []
        for f in new_findings:
            rule = defs.fix_for(f["type"])
            if rule and rule.auto:
                result = self.responder.apply_fix(f, rule, manual=False)
                if result.get("result") not in ("skipped", "alert_only"):
                    auto_actions.append({"finding": f["id"], **result})

        # Persist the observation for the admin portal (trimmed — the full
        # process table can be huge and the portal only needs the rest).
        atomic_write_json(Path(cfg.state_dir) / "last_observation.json", {
            "ts": obs["ts"],
            "listeners": obs["listeners"],
            "established": obs["established"],
            "users": obs["users"],
            "ssh": obs["ssh"],
            "sudo": obs["sudo"],
            "kernel": obs["kernel"],
        })

        # event + last run
        removed = sum(1 for f in findings if f["type"] == "removed_listener")
        new_listeners = [f["details"]["socket"] for f in new_findings
                         if f["type"] == "new_listener"]
        state.append_event("monitor_cycle", {
            "findings_new": len(new_findings),
            "findings_total_open": sum(
                1 for f in state.load_findings() if f.get("status") == "open"),
            "udp_ignored": udp_ignored,
            "new_listeners": new_listeners,
            "removed_listeners": removed,
            "ssh": obs["ssh"],
            "sudo_count": obs["sudo"].get("count", 0),
            "file_changes": len(integrity["changed"]),
            "self_changes": len(self_changed),
            "auto_actions": len(auto_actions),
        })
        state.record_last_run({
            "findings_new": len(new_findings),
            "udp_ignored": udp_ignored,
            "defs_version": defs.version(),
            "status": "ok",
        })
        return {"observation": obs, "findings": new_findings,
                "udp_ignored": udp_ignored, "auto_actions": auto_actions,
                "integrity": integrity}

    # ------------------------------------------------------------------
    # daily report
    # ------------------------------------------------------------------
    def daily_report(self) -> tuple[str, dict]:
        text, meta = generate_daily_report(self.cfg, self.state, self.defs)
        write_report(self.cfg, self.state, text, meta)
        self.state.append_event("daily_report", {
            "open_findings": meta["open_findings"],
            "severity_counts": meta["severity_counts"],
        })
        return text, meta

    # ------------------------------------------------------------------
    # daemon
    # ------------------------------------------------------------------
    def serve_forever(self) -> None:
        print(f"[tori-hanzo] daemon started — cycle every "
              f"{self.cfg.monitor_interval_sec}s")
        self.state.append_event("daemon_start", {
            "interval": self.cfg.monitor_interval_sec})
        while True:
            try:
                self.run_cycle()
            except Exception as exc:  # the watchdog must not die
                self.state.append_event("cycle_error", {"error": str(exc)})
                print(f"[tori-hanzo] cycle error: {exc}")
            time.sleep(self.cfg.monitor_interval_sec)


def source_fingerprint(base_dir: Path) -> str:
    """One hash for the whole src tree (displayed on the portal)."""
    h = hashlib.sha256()
    for f in sorted((Path(base_dir) / "src").glob("*.py")):
        try:
            h.update(f.read_bytes())
        except OSError:
            pass
    return h.hexdigest()[:12]
