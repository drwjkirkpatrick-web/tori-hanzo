"""Reporter: daily summary shape + the no-raw-IP privacy contract."""

from __future__ import annotations

from pathlib import Path

from reporter import generate_daily_report, write_report


def _seed(state):
    state.append_event("monitor_cycle", {
        "findings_new": 1, "findings_total_open": 1, "udp_ignored": 4,
        "new_listeners": [{"proto": "tcp", "addr": "127.0.0.1",
                           "port": 9999, "process": "demo"}],
        "removed_listeners": 0,
        "ssh": {"failed": 9, "success": 1,
                "failed_by_ip": {"deadbeef01": 9},
                "accepted": [{"user": "walker", "ip_hash": "cafe0001"}]},
        "sudo_count": 2, "file_changes": 0, "self_changes": 0,
        "auto_actions": 0,
    })
    state.save_findings([{
        "id": "f1", "ts": "2026-07-18T00:00:00+00:00",
        "type": "ssh_bruteforce", "severity": "high",
        "summary": "SSH brute force: 9 failures from source deadbeef01",
        "details": {}, "status": "open"}])
    state.append_action({"action": "block_ip", "result": "dry_run",
                         "dry_run": True})
    state.record_last_run({"status": "ok"})


def test_report_sections_and_privacy(cfg, state, defs):
    _seed(state)
    text, meta = generate_daily_report(cfg, state, defs)

    assert "Tori-Hanzo Daily Security Report" in text
    assert "Agent status" in text
    assert "Intruder watch" in text
    assert "Findings" in text
    assert "Response actions" in text
    assert "UDP churn ignored: 4" in text
    assert "deadbeef01" in text                      # hashed source shown
    assert meta["open_findings"] == 1
    assert meta["severity_counts"] == {"high": 1}


def test_report_never_leaks_raw_ips(cfg, state, defs):
    state.append_event("monitor_cycle", {
        "udp_ignored": 0, "new_listeners": [], "removed_listeners": 0,
        "ssh": {"failed": 1, "success": 0,
                "failed_by_ip": {"abc": 1}, "accepted": []},
        "auto_actions": 0,
    })
    text, _ = generate_daily_report(cfg, state, defs)
    for raw in ("198.51.100.", "203.0.113.", "192.168.", "10.0.0."):
        assert raw not in text


def test_write_report_creates_latest_and_archive(cfg, state, defs):
    _seed(state)
    text, meta = generate_daily_report(cfg, state, defs)
    write_report(cfg, state, text, meta)
    reports = Path(cfg.reports_dir)
    assert (reports / "latest.txt").read_text() == text
    assert (reports / "latest.json").exists()
    assert list(reports.glob("report_*.txt"))
