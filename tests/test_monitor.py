"""Monitor collectors: parsers are pure and tested with canned command output."""

from __future__ import annotations

import monitor


SS_LISTEN = """tcp   LISTEN 0      4096       127.0.0.1:8642       0.0.0.0:*    users:(("hermes",pid=1000,fd=12))
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=800,fd=3))
udp   UNCONN 0      0          127.0.0.53%lo:53     0.0.0.0:*    users:(("systemd-resolve",pid=600,fd=12))
tcp   LISTEN 0      100                *:4444             *:*
"""

SS_ESTAB = """tcp   ESTAB  0      0      192.168.1.5:22    192.168.1.20:55100   users:(("sshd",pid=900,fd=4))
tcp   ESTAB  0      0      192.168.1.5:8642  203.0.113.7:443     users:(("hermes",pid=1000,fd=20))
"""

PS_OUT = """  800     1 root     sshd    /usr/sbin/sshd -D
 1000     1 walker   python3 /home/walker/.hermes/bin/python hermes gateway
 4242  1000 walker   xmrig   ./xmrig -o pool.example
"""

WHO_OUT = """walker   pts/0        2026-07-18 09:58 (192.168.1.20)
walker   tty2         2026-07-18 08:00
"""

SSH_JOURNAL = """Jul 18 01:00:01 host sshd[1]: Failed password for invalid user admin from 198.51.100.9 port 41000 ssh2
Jul 18 01:00:03 host sshd[1]: Failed password for root from 198.51.100.9 port 41002 ssh2
Jul 18 01:00:05 host sshd[1]: Failed password for root from 198.51.100.9 port 41004 ssh2
Jul 18 09:58:00 host sshd[2]: Accepted publickey for walker from 192.168.1.20 port 55100 ssh2
"""

SUDO_JOURNAL = """Jul 18 10:00:00 host sudo[5]: walker : TTY=pts/0 ; PWD=/home/walker ; USER=root ; COMMAND=/usr/bin/apt update
Jul 18 10:05:00 host sudo[6]: walker : TTY=pts/0 ; PWD=/home/walker ; USER=root ; COMMAND=/usr/sbin/iptables -L
"""

KERNEL_JOURNAL = """Jul 18 03:00:00 host kernel: [ 100.0] some normal message
Jul 18 03:01:00 host kernel: [ 101.0] segfault at 0 ip 00007f in badapp[1234]
Jul 18 03:02:00 host kernel: [ 102.0] audit: apparmor="DENIED" operation="open"
"""


def test_parse_ss_listening_with_and_without_users():
    socks = monitor.parse_ss_listening(SS_LISTEN)
    by_port = {s["port"]: s for s in socks}
    assert by_port[8642]["process"] == "hermes" and by_port[8642]["pid"] == 1000
    assert by_port[53]["proto"] == "udp" and by_port[53]["addr"] == "127.0.0.53"
    # no users:() trailer -> still parsed, empty process
    assert 4444 in by_port and by_port[4444]["process"] == ""


def test_parse_ss_established():
    conns = monitor.parse_ss_established(SS_ESTAB)
    assert len(conns) == 2
    remote = {c["remote_addr"] for c in conns}
    assert "203.0.113.7" in remote and "192.168.1.20" in remote
    assert conns[0]["local_port"] == 22


def test_parse_ps_caps_args():
    procs = monitor.parse_ps(PS_OUT)
    assert len(procs) == 3
    xmrig = [p for p in procs if p["comm"] == "xmrig"][0]
    assert xmrig["pid"] == 4242 and xmrig["user"] == "walker"
    long_args = "x " * 1000
    capped = monitor.parse_ps(f" 1 0 root t {long_args}", max_args=50)[0]
    assert len(capped["args"]) == 50


def test_parse_who():
    users = monitor.parse_who(WHO_OUT)
    assert users[0]["host"] == "192.168.1.20"
    assert users[1]["host"] == "local"


def test_parse_ssh_journal_hashes_ips():
    res = monitor.parse_ssh_journal(SSH_JOURNAL, salt="testsalt")
    assert res["failed"] == 3 and res["success"] == 1
    token = monitor.hash_ip("198.51.100.9", "testsalt")
    assert res["failed_by_ip"] == {token: 3}
    assert res["accepted"][0]["user"] == "walker"
    # raw IP must not survive anywhere in the result
    assert "198.51.100.9" not in str(res)
    # hashing is salted: different salt -> different token
    assert monitor.hash_ip("1.2.3.4", "a") != monitor.hash_ip("1.2.3.4", "b")


def test_parse_sudo_journal():
    res = monitor.parse_sudo_journal(SUDO_JOURNAL)
    assert res["count"] == 2
    assert res["commands"][0]["command"] == "/usr/bin/apt update"


def test_parse_kernel_journal_filters_alerts():
    res = monitor.parse_kernel_journal(KERNEL_JOURNAL)
    assert res["count"] == 2
    assert any("segfault" in a for a in res["alerts"])
    assert not any("normal message" in a for a in res["alerts"])


def test_file_integrity_lifecycle(tmp_path):
    f1 = tmp_path / "watched.conf"
    f1.write_text("original")
    f2 = tmp_path / "other.conf"
    f2.write_text("data")
    paths = [str(f1), str(f2), str(tmp_path / "missing.conf")]

    first = monitor.check_file_integrity(paths, {})
    assert set(first["new"]) == {str(f1), str(f2)}
    assert first["changed"] == []

    f1.write_text("tampered")
    second = monitor.check_file_integrity(paths, first["current"])
    assert second["changed"] == [str(f1)]

    f2.unlink()
    third = monitor.check_file_integrity(paths, second["current"])
    assert third["missing"] == [str(f2)]


def test_collectors_never_raise_on_command_failure():
    dead = lambda cmd, timeout=25: (1, "", "boom")
    assert monitor.collect_listening_ports(dead) == []
    assert monitor.collect_established(dead) == []
    assert monitor.collect_processes(dead) == []
    assert monitor.collect_logged_in_users(dead) == []
    assert monitor.collect_ssh(24, "salt", dead)["error"]
    assert monitor.collect_sudo(24, dead)["error"]
    assert monitor.collect_kernel(24, run=dead)["error"]
