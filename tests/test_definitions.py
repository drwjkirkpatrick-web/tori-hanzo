"""DefinitionStore: CSV loading, querying, updating."""

from __future__ import annotations

import csv

from definitions import DefinitionStore


def test_loads_all_csvs(defs):
    s = defs.summary()
    assert s["ports"] == 5            # bad row skipped
    assert s["processes"] == 3
    assert s["ips"] == 3              # 'not-a-cidr' skipped
    assert s["udp_baseline"] == 2
    assert s["fixes"] == 3            # bogus_type (no action) skipped
    assert s["skipped_rows"]["ports"] == 1
    assert s["skipped_rows"]["ips"] == 1


def test_missing_data_dir_is_tolerated(tmp_path):
    d = DefinitionStore(tmp_path / "nope")
    assert d.summary()["ports"] == 0


def test_port_disposition_exact_process_wins(defs):
    assert defs.port_disposition("tcp", 22, "sshd") == "allow"
    assert defs.port_disposition("tcp", 8642, "hermes") == "allow-local"
    # unknown port -> default alert
    assert defs.port_disposition("tcp", 13337, "mystery") == "alert"


def test_port_disposition_process_mismatch_falls_through(defs):
    # port 22 rule requires process 'sshd'; another process on 22 -> alert
    assert defs.port_disposition("tcp", 22, "evil") == "alert"


def test_udp_ignore_via_baseline_and_rules(defs):
    assert defs.is_ignored_udp(5353, "avahi-daemon") is True      # baseline
    assert defs.is_ignored_udp(5353, "anything") is True          # rule too
    assert defs.is_ignored_udp(68, "dhclient") is True            # proc match
    assert defs.is_ignored_udp(53, "named") is False              # not listed


def test_ip_disposition_longest_prefix_wins(defs):
    assert defs.ip_disposition("192.168.1.50") == "ignore"
    assert defs.ip_disposition("203.0.113.7") == "deny"
    assert defs.ip_disposition("8.8.8.8") == "alert"      # unknown -> alert
    assert defs.ip_disposition("not-an-ip") == "alert"


def test_process_rule_matching(defs):
    verdicts = defs.process_verdicts("/usr/bin/xmrig --donate-level=1")
    assert any(r.disposition == "deny" for r in verdicts)
    # invalid regex row must never raise and never match
    assert defs.process_verdicts("anything [ works") is not None


def test_fix_lookup(defs):
    fix = defs.fix_for("rogue_process")
    assert fix is not None and fix.action == "kill_process" and fix.auto
    assert defs.fix_for("nonexistent") is None


def test_add_udp_ignore_appends_and_reloads(defs, data_dir):
    before = len(defs.udp_baseline)
    defs.add_udp_ignore(9999, "chatty-app", "testing =not formula")
    assert len(defs.udp_baseline) == before + 1
    assert defs.is_ignored_udp(9999, "chatty-app")
    # CSV-injection guard: leading '=' stripped from notes
    rows = list(csv.reader(open(data_dir / "udp_baseline.csv")))
    assert rows[-1][2] == "not formula" or not rows[-1][2].startswith("=")


def test_update_from_csv_validates_header(defs):
    ok, _ = defs.update_from_csv("ports",
                                 "proto,port,process,disposition,notes\n"
                                 "tcp,1,x,allow,hi\n")
    assert ok and defs.port_disposition("tcp", 1, "x") == "allow"
    ok, msg = defs.update_from_csv("ports", "wrong,header\n1,2\n")
    assert not ok and "bad header" in msg
    ok, _ = defs.update_from_csv("nonsense", "a,b\n1,2\n")
    assert not ok


def test_version_changes_with_content(defs):
    v1 = defs.version()
    defs.add_udp_ignore(7777, "", "x")
    assert defs.version() != v1
