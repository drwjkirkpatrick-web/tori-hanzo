"""End-to-end agent cycle: fake command runner -> findings -> baselines."""

from __future__ import annotations

from agent import Agent

from conftest import make_fake_run

SS_LISTEN = """tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=800,fd=3))
tcp   LISTEN 0      4096       127.0.0.1:8642       0.0.0.0:*    users:(("hermes",pid=1000,fd=12))
udp   UNCONN 0      0            0.0.0.0:5353       0.0.0.0:*    users:(("avahi-daemon",pid=700,fd=11))
tcp   LISTEN 0      100          0.0.0.0:4444       0.0.0.0:*
"""

SS_ESTAB = """tcp   ESTAB  0      0      192.168.1.5:22   203.0.113.7:443   users:(("sshd",pid=900,fd=4))
"""

PS_OUT = """  800     1 root   sshd    /usr/sbin/sshd -D
 4242  1000 walker xmrig   ./xmrig -o pool.example
"""

SSH_JOURNAL = """Jul 18 01:00:01 h sshd[1]: Failed password for root from 198.51.100.9 port 41000 ssh2
Jul 18 01:00:03 h sshd[1]: Failed password for root from 198.51.100.9 port 41002 ssh2
Jul 18 01:00:05 h sshd[1]: Failed password for root from 198.51.100.9 port 41004 ssh2
Jul 18 01:00:07 h sshd[1]: Failed password for root from 198.51.100.9 port 41006 ssh2
Jul 18 01:00:09 h sshd[1]: Failed password for root from 198.51.100.9 port 41008 ssh2
Jul 18 01:00:11 h sshd[1]: Failed password for root from 198.51.100.9 port 41010 ssh2
"""

FAKE = make_fake_run({
    "ss -lntupH": (0, SS_LISTEN),
    "ss -tnpH state established": (0, SS_ESTAB),
    "ps -eo": (0, PS_OUT),
    "who": (0, "walker pts/0 2026-07-18 09:58 (192.168.1.20)\n"),
    "SYSLOG_IDENTIFIER=sshd": (0, SSH_JOURNAL),
    "SYSLOG_IDENTIFIER=sudo": (0, ""),
    "journalctl -k": (0, ""),
})


def test_full_cycle_finds_everything_once(cfg):
    agent = Agent(cfg, run=FAKE)
    result = agent.run_cycle()
    types = {f["type"] for f in result["findings"]}

    assert "new_listener" in types            # 4444 deny + 22 allow mismatch?
    assert "rogue_process" in types           # xmrig
    assert "denied_ip_connected" in types     # 203.0.113.7
    assert "ssh_bruteforce" in types          # 6 failures
    assert result["udp_ignored"] == 1         # mDNS 5353

    by_type = {}
    for f in result["findings"]:
        by_type.setdefault(f["type"], []).append(f)
    assert by_type["denied_ip_connected"][0]["severity"] == "critical"
    assert by_type["rogue_process"][0]["severity"] == "high"

    # auto-fix fired for rogue_process (auto=true).  The fake xmrig pid
    # doesn't really exist, so the responder either dry-runs or refuses
    # with "process no longer exists" — both prove the wiring works.
    assert any(a["action"] == "kill_process"
               and a["result"] in ("dry_run", "refused")
               for a in result["auto_actions"])


def test_second_cycle_dedupes(cfg):
    agent = Agent(cfg, run=FAKE)
    agent.run_cycle()
    second = agent.run_cycle()
    # baselines persisted -> no repeat listener findings; dedupe window
    # suppresses identical process/ssh findings too
    assert not any(f["type"] == "new_listener" for f in second["findings"])
    assert not any(f["type"] == "rogue_process" for f in second["findings"])
    assert not any(f["type"] == "ssh_bruteforce" for f in second["findings"])


def test_daily_report_runs_after_cycle(cfg):
    agent = Agent(cfg, run=FAKE)
    agent.run_cycle()
    text, meta = agent.daily_report()
    assert "Tori-Hanzo Daily Security Report" in text
    assert "203.0.113.7" not in text          # privacy: hashed only
    assert meta["open_findings"] > 0
    assert (cfg.reports_dir / "latest.txt").exists()


def test_cycle_persists_observation_for_portal(cfg):
    agent = Agent(cfg, run=FAKE)
    agent.run_cycle()
    obs_path = cfg.state_dir / "last_observation.json"
    assert obs_path.exists()
    import json
    obs = json.loads(obs_path.read_text())
    assert obs["listeners"] and obs["ssh"]["failed"] == 6
