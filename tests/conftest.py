"""Shared fixtures for the tori-hanzo test suite.

Everything runs against tmp_path directories — the tests never touch the
real state/ or data/ folders, and never run real system commands (the
command runner is faked).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from config import Config                     # noqa: E402
from definitions import DefinitionStore       # noqa: E402
from state import StateStore                  # noqa: E402


PORTS_CSV = """proto,port,process,disposition,notes
tcp,22,sshd,allow,System SSH
tcp,8642,hermes,allow-local,Hermes api
tcp,9193,tori-hanzo,allow-local,portal
udp,5353,,ignore,mDNS churn
tcp,4444,,deny,Metasploit
bad,row,here
"""

PROCS_CSV = """name,pattern,match_type,disposition,notes
xmrig,xmrig,substring,deny,miner
nc-listen,nc -l,substring,alert,netcat listener
badregex,[,regex,alert,invalid regex never matches
"""

IPS_CSV = """cidr,disposition,notes
127.0.0.0/8,allow,loopback
192.168.0.0/16,ignore,LAN
203.0.113.7/32,deny,known scanner (TEST-NET-3 example)
not-a-cidr,deny,broken row
"""

UDP_CSV = """port,process,notes
5353,,mDNS
68,dhclient,DHCP client
"""

FIXES_CSV = """finding_type,action,auto,notes
rogue_process,kill_process,true,kill miners automatically
denied_ip_connected,block_ip,false,manual confirm
ssh_login,alert,true,info only
bogus_type,,true,missing action row
"""


@pytest.fixture()
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    (d / "port_definitions.csv").write_text(PORTS_CSV)
    (d / "process_definitions.csv").write_text(PROCS_CSV)
    (d / "ip_definitions.csv").write_text(IPS_CSV)
    (d / "udp_baseline.csv").write_text(UDP_CSV)
    (d / "fixes.csv").write_text(FIXES_CSV)
    return d


@pytest.fixture()
def cfg(tmp_path: Path, data_dir: Path) -> Config:
    c = Config()
    c.base_dir = tmp_path
    c.data_dir = data_dir
    c.state_dir = tmp_path / "state"
    c.reports_dir = c.state_dir / "reports"
    c.critical_files = []
    c.ensure_dirs()
    return c


@pytest.fixture()
def state(cfg: Config) -> StateStore:
    return StateStore(cfg.state_dir)


@pytest.fixture()
def defs(data_dir: Path) -> DefinitionStore:
    return DefinitionStore(data_dir)


def make_fake_run(outputs: dict):
    """Build a fake run_command: outputs maps a command-substring to
    (rc, stdout) tuples.  Unmatched commands return rc=1."""
    def fake_run(cmd, timeout=25):
        text = " ".join(cmd)
        for needle, (rc, out) in outputs.items():
            if needle in text:
                return rc, out, ""
        return 1, "", "no fake output registered"
    return fake_run
