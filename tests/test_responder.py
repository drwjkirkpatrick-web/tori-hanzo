"""Responder: safety rails first, real actions second."""

from __future__ import annotations

import subprocess
import time

from responder import Responder


def test_refuses_low_pid(cfg, state):
    r = Responder(cfg, state)
    res = r.kill_process(4, reason="test", dry_run=False)
    assert res["result"] == "refused" and "floor" in res["detail"]


def test_refuses_protected_process(cfg, state, monkeypatch):
    r = Responder(cfg, state)
    monkeypatch.setattr(r, "_process_info",
                        lambda pid: {"pid": pid, "comm": "sshd",
                                     "cmdline": "/usr/sbin/sshd -D"})
    res = r.kill_process(12345, reason="test", dry_run=False)
    assert res["result"] == "refused" and "protected" in res["detail"]


def test_refuses_to_kill_hermes_cmdline(cfg, state, monkeypatch):
    r = Responder(cfg, state)
    monkeypatch.setattr(r, "_process_info",
                        lambda pid: {"pid": pid, "comm": "python3",
                                     "cmdline": "python3 hermes gateway"})
    res = r.kill_process(12345, reason="test", dry_run=False)
    assert res["result"] == "refused"


def test_dry_run_kill_touches_nothing(cfg, state):
    proc = subprocess.Popen(["sleep", "30"])
    try:
        r = Responder(cfg, state)
        res = r.kill_process(proc.pid, reason="test", dry_run=True)
        assert res["result"] == "dry_run"
        assert proc.poll() is None          # still alive
    finally:
        proc.kill()


def test_real_kill_of_own_subprocess(cfg, state):
    proc = subprocess.Popen(["sleep", "30"])
    r = Responder(cfg, state)
    res = r.kill_process(proc.pid, reason="test", dry_run=False)
    assert res["result"] == "killed"
    deadline = time.time() + 5
    while proc.poll() is None and time.time() < deadline:
        time.sleep(0.05)
    assert proc.poll() is not None


def test_block_ip_validation(cfg, state):
    r = Responder(cfg, state)
    assert r.block_ip("not-an-ip", dry_run=False)["result"] == "refused"
    assert r.block_ip("127.0.0.1", dry_run=False)["result"] == "refused"
    res = r.block_ip("192.168.1.99", dry_run=False)
    assert res["result"] == "refused" and "force" in res["detail"]


def test_block_ip_dry_run_records_action(cfg, state):
    r = Responder(cfg, state)
    res = r.block_ip("203.0.113.7", reason="test", dry_run=True)
    assert res["result"] == "dry_run"
    assert "iptables" in res["command"]
    actions = state.read_actions()
    assert actions[0]["action"] == "block_ip" and actions[0]["dry_run"]


def test_apply_fix_without_pid_is_error(cfg, state):
    r = Responder(cfg, state)
    from definitions import FixRule
    rule = FixRule("rogue_process", "kill_process", auto=True)
    finding = {"type": "rogue_process", "summary": "x", "details": {}}
    assert r.apply_fix(finding, rule)["result"] == "error"


def test_apply_fix_respects_auto_flag(cfg, state):
    r = Responder(cfg, state)
    from definitions import FixRule
    rule = FixRule("denied_ip_connected", "block_ip", auto=False)
    finding = {"type": "denied_ip_connected", "summary": "x",
               "details": {"connection": {"remote_addr": "203.0.113.7"}}}
    assert r.apply_fix(finding, rule, manual=False)["result"] == "skipped"
    # manual override goes through (as dry-run while active_response off)
    res = r.apply_fix(finding, rule, manual=True)
    assert res["result"] == "dry_run"


def test_active_response_flips_default_mode(cfg, state):
    cfg.active_response = True
    r = Responder(cfg, state)
    # would actually run iptables -> but private+no force refuses first,
    # so use dry_run explicitly False on an invalid target to stay safe:
    res = r.block_ip("127.0.0.1")
    assert res["result"] == "refused"
    assert res["dry_run"] is False
