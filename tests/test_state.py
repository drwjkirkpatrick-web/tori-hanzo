"""State persistence: atomic writes, secrets, event log."""

from __future__ import annotations

import os
import stat

from state import StateStore, atomic_write_json, read_json


def test_atomic_write_json_mode_and_content(tmp_path):
    p = tmp_path / "x.json"
    atomic_write_json(p, {"a": 1})
    assert read_json(p, {}) == {"a": 1}
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o600


def test_read_json_tolerates_garbage(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    assert read_json(p, {"fallback": True}) == {"fallback": True}
    assert read_json(tmp_path / "absent.json", 42) == 42


def test_secrets_created_once_with_0600(state):
    salt1 = state.get_salt()
    assert salt1 == state.get_salt()          # stable
    token = state.get_portal_token()
    assert token and token == state.get_portal_token()
    for name in ("salt", "portal_token"):
        mode = stat.S_IMODE(os.stat(state.dir / name).st_mode)
        assert mode == 0o600


def test_event_log_roundtrip_newest_first(state):
    state.append_event("alpha", {"n": 1})
    state.append_event("beta", {"n": 2})
    events = state.read_events()
    assert [e["type"] for e in events] == ["beta", "alpha"]
    assert all("ts" in e for e in events)


def test_findings_capped(state):
    state.save_findings([{"id": str(i)} for i in range(10)], cap=3)
    assert len(state.load_findings()) == 3


def test_actions_audit_trail(state):
    state.append_action({"action": "kill_process", "pid": 1,
                         "result": "refused"})
    actions = state.read_actions()
    assert actions[0]["action"] == "kill_process"
    assert "ts" in actions[0]
