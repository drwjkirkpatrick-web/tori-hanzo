"""State persistence for Tori-Hanzo.

Everything under `state/` is runtime-only and gitignored:

    state/salt                     — per-install secret for IP hashing (0600)
    state/portal_token             — admin login token for the web UI (0600)
    state/events.jsonl             — append-only event log (rotated at ~5 MB)
    state/findings.json            — open/acknowledged findings (capped list)
    state/listening_baseline.json  — last-known listening socket map
    state/file_integrity.json      — path -> sha256 for critical files
    state/self_manifest.json       — sha256 of the agent's own source files
    state/blocked_ips.json         — IPs the responder has blocked
    state/actions.jsonl            — responder action audit trail
    state/last_run.json            — timestamp/status of the last monitor cycle
    state/reports/                 — daily reports (latest.txt/.json + archive)

LEARN: every write is atomic (tempfile -> fsync -> os.replace) so a crash
mid-write can never leave a torn JSON file that breaks the next read.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path

EVENT_LOG_MAX_BYTES = 5 * 1024 * 1024  # rotate events.jsonl beyond ~5 MB


def utcnow_iso() -> str:
    """Timezone-aware UTC timestamp (ISO-8601)."""
    return datetime.now(timezone.utc).isoformat()


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    """Write text atomically with a unique temp file + fsync + rename."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        # Never leave the temp file behind on failure.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, obj, mode: int = 0o600) -> None:
    atomic_write_text(path, json.dumps(obj, indent=2, sort_keys=True), mode)


def read_json(path: Path, default):
    """Tolerant JSON read — any failure returns `default`."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


class StateStore:
    """Small facade over the state directory."""

    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.dir / "events.jsonl"
        self.actions_path = self.dir / "actions.jsonl"
        self.findings_path = self.dir / "findings.json"
        self.blocked_ips_path = self.dir / "blocked_ips.json"
        self.last_run_path = self.dir / "last_run.json"

    # ------------------------------------------------------------------
    # secrets
    # ------------------------------------------------------------------
    def _get_or_create_secret(self, name: str, nbytes: int = 32) -> str:
        path = self.dir / name
        try:
            value = path.read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError:
            pass
        value = secrets.token_hex(nbytes)
        atomic_write_text(path, value + "\n", mode=0o600)
        return value

    def get_salt(self) -> str:
        """Per-install salt for hashing IPs in reports (privacy)."""
        return self._get_or_create_secret("salt")

    def get_portal_token(self) -> str:
        """Admin token for the web portal (shown once via CLI)."""
        return self._get_or_create_secret("portal_token", nbytes=24)

    # ------------------------------------------------------------------
    # event log
    # ------------------------------------------------------------------
    def append_event(self, event_type: str, payload: dict) -> None:
        """Append one JSON line; rotate the log when it grows too large."""
        try:
            if (self.events_path.exists()
                    and self.events_path.stat().st_size > EVENT_LOG_MAX_BYTES):
                os.replace(self.events_path, self.events_path.with_suffix(".jsonl.1"))
        except OSError:
            pass
        record = {"ts": utcnow_iso(), "type": event_type, **payload}
        try:
            with open(self.events_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
        except OSError:
            pass  # logging must never crash the agent

    def read_events(self, limit: int = 200) -> list[dict]:
        """Newest-first list of recent events."""
        try:
            lines = self.events_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out = []
        for line in reversed(lines[-limit:]):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def append_action(self, action: dict) -> None:
        """Responder audit trail (one JSON line per attempted action)."""
        record = {"ts": utcnow_iso(), **action}
        try:
            with open(self.actions_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, sort_keys=True) + "\n")
        except OSError:
            pass

    def read_actions(self, limit: int = 200) -> list[dict]:
        try:
            lines = self.actions_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out = []
        for line in reversed(lines[-limit:]):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    # ------------------------------------------------------------------
    # findings
    # ------------------------------------------------------------------
    def load_findings(self) -> list[dict]:
        data = read_json(self.findings_path, [])
        return data if isinstance(data, list) else []

    def save_findings(self, findings: list[dict], cap: int = 500) -> None:
        atomic_write_json(self.findings_path, findings[:cap])

    # ------------------------------------------------------------------
    # misc small state
    # ------------------------------------------------------------------
    def load_blocked_ips(self) -> list[dict]:
        data = read_json(self.blocked_ips_path, [])
        return data if isinstance(data, list) else []

    def save_blocked_ips(self, entries: list[dict]) -> None:
        atomic_write_json(self.blocked_ips_path, entries)

    def record_last_run(self, payload: dict) -> None:
        atomic_write_json(self.last_run_path, {"ts": utcnow_iso(), **payload})

    def last_run(self) -> dict:
        return read_json(self.last_run_path, {})
