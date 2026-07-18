"""Detector: rules engine behaviour over synthetic observations."""

from __future__ import annotations

import detector


def _obs(listeners=(), established=(), processes=(), ssh=None, kernel=None):
    return {
        "ts": "2026-07-18T00:00:00+00:00",
        "listeners": list(listeners),
        "established": list(established),
        "processes": list(processes),
        "users": [],
        "ssh": ssh or {"failed": 0, "success": 0, "failed_by_ip": {},
                       "accepted": []},
        "sudo": {"count": 0, "commands": []},
        "kernel": kernel or {"alerts": [], "count": 0},
    }


def _sock(proto, addr, port, process=""):
    return {"proto": proto, "addr": addr, "port": port, "process": process,
            "pid": 1234, "key": f"{proto}:{addr}:{port}"}


def test_new_tcp_listener_flagged_once(defs, cfg):
    obs = _obs(listeners=[_sock("tcp", "0.0.0.0", 13337, "mysteryd")])
    findings, baseline, _ = detector.evaluate(obs, {"listeners": {}}, defs, cfg)
    assert any(f["type"] == "new_listener" and f["severity"] == "medium"
               for f in findings)
    # second cycle with updated baseline: silence
    findings2, _, _ = detector.evaluate(obs, {"listeners": baseline}, defs, cfg)
    assert not any(f["type"] == "new_listener" for f in findings2)


def test_udp_in_baseline_is_ignored(defs, cfg):
    obs = _obs(listeners=[_sock("udp", "0.0.0.0", 5353, "avahi-daemon")])
    findings, _, ignored = detector.evaluate(obs, {"listeners": {}}, defs, cfg)
    assert ignored == 1
    assert not any(f["type"] == "new_listener" for f in findings)


def test_udp_not_in_baseline_is_flagged(defs, cfg):
    obs = _obs(listeners=[_sock("udp", "0.0.0.0", 161, "snmpd")])
    findings, _, ignored = detector.evaluate(obs, {"listeners": {}}, defs, cfg)
    assert ignored == 0
    assert any(f["type"] == "new_listener" for f in findings)


def test_allow_local_exposed_is_high(defs, cfg):
    # hermes is allow-local: fine on loopback, high when bound to all ifaces
    good = _obs(listeners=[_sock("tcp", "127.0.0.1", 8642, "hermes")])
    f_good, _, _ = detector.evaluate(good, {"listeners": {}}, defs, cfg)
    assert not any(f["type"] == "new_listener" for f in f_good)

    bad = _obs(listeners=[_sock("tcp", "0.0.0.0", 8642, "hermes")])
    f_bad, _, _ = detector.evaluate(bad, {"listeners": {}}, defs, cfg)
    hits = [f for f in f_bad if f["type"] == "new_listener"]
    assert hits and hits[0]["severity"] == "high"


def test_denied_port_is_high(defs, cfg):
    obs = _obs(listeners=[_sock("tcp", "0.0.0.0", 4444, "unknown")])
    findings, _, _ = detector.evaluate(obs, {"listeners": {}}, defs, cfg)
    hits = [f for f in findings if f["type"] == "new_listener"]
    assert hits and hits[0]["severity"] == "high"


def test_removed_listener_info(defs, cfg):
    baseline = {"tcp:127.0.0.1:9999": _sock("tcp", "127.0.0.1", 9999, "oldapp")}
    findings, _, _ = detector.evaluate(_obs(), {"listeners": baseline},
                                       defs, cfg)
    assert any(f["type"] == "removed_listener" and f["severity"] == "info"
               for f in findings)


def test_rogue_process_high(defs, cfg):
    procs = [{"pid": 4242, "ppid": 1, "user": "walker", "comm": "xmrig",
              "args": "./xmrig -o pool"}]
    findings, _, _ = detector.evaluate(_obs(processes=procs),
                                       {"listeners": {}}, defs, cfg)
    hits = [f for f in findings if f["type"] == "rogue_process"]
    assert hits and hits[0]["severity"] == "high"
    assert hits[0]["details"]["pid"] == 4242


def test_suspicious_process_medium(defs, cfg):
    procs = [{"pid": 5555, "ppid": 1, "user": "walker", "comm": "nc",
              "args": "nc -l -p 31337"}]
    findings, _, _ = detector.evaluate(_obs(processes=procs),
                                       {"listeners": {}}, defs, cfg)
    hits = [f for f in findings if f["type"] == "suspicious_process"]
    assert hits and hits[0]["severity"] == "medium"


def test_ssh_bruteforce_threshold(defs, cfg):
    ssh = {"failed": 7, "success": 0,
           "failed_by_ip": {"abc123": 7}, "accepted": []}
    findings, _, _ = detector.evaluate(_obs(ssh=ssh), {"listeners": {}},
                                       defs, cfg)
    assert any(f["type"] == "ssh_bruteforce" for f in findings)

    ssh["failed_by_ip"] = {"abc123": 2}
    findings, _, _ = detector.evaluate(_obs(ssh=ssh), {"listeners": {}},
                                       defs, cfg)
    assert not any(f["type"] == "ssh_bruteforce" for f in findings)


def test_denied_ip_connection_critical(defs, cfg):
    conns = [{"local_addr": "192.168.1.5", "local_port": 22,
              "remote_addr": "203.0.113.7", "remote_port": 443,
              "process": "sshd", "pid": 900}]
    findings, _, _ = detector.evaluate(_obs(established=conns),
                                       {"listeners": {}}, defs, cfg)
    hits = [f for f in findings if f["type"] == "denied_ip_connected"]
    assert hits and hits[0]["severity"] == "critical"
    assert hits[0]["details"]["connection"]["remote_addr"] == "203.0.113.7"


def test_lan_connection_quiet(defs, cfg):
    conns = [{"local_addr": "192.168.1.5", "local_port": 22,
              "remote_addr": "192.168.1.20", "remote_port": 55100,
              "process": "sshd", "pid": 900}]
    findings, _, _ = detector.evaluate(_obs(established=conns),
                                       {"listeners": {}}, defs, cfg)
    assert not any(f["type"] in ("denied_ip_connected",
                                 "unknown_remote_connection")
                   for f in findings)


def test_integrity_critical_paths(defs, cfg):
    integrity = {"changed": ["/etc/shadow", "/home/walker/notes.txt"],
                 "missing": [], "new": [], "skipped": [], "current": {}}
    findings, _, _ = detector.evaluate(_obs(), {"listeners": {}}, defs, cfg,
                                       integrity=integrity)
    by_path = {f["details"]["path"]: f for f in findings
               if f["type"] == "file_integrity_change"}
    assert by_path["/etc/shadow"]["severity"] == "critical"
    assert by_path["/home/walker/notes.txt"]["severity"] == "medium"


def test_self_integrity_high(defs, cfg):
    findings, _, _ = detector.evaluate(_obs(), {"listeners": {}}, defs, cfg,
                                       self_changed=["detector.py"])
    assert any(f["type"] == "self_integrity_change"
               and f["severity"] == "high" for f in findings)


def test_finding_key_stable():
    f = {"type": "x", "summary": "hello"}
    assert detector.finding_key(f) == detector.finding_key(dict(f))
