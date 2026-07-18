"""Configuration for Tori-Hanzo.

Design notes (LEARN):
- We avoid YAML here on purpose: the agent should run on a bare Python 3.11
  install with zero third-party deps.  JSON is built in, so the optional
  local override file is `config.local.json` at the project root.
- Anything sensitive (tokens, baselines, events) lives under `state/`,
  which is gitignored.  Anything shareable (CSV definitions) lives in `data/`
  and *is* committed so the fleet/threat knowledge travels with the repo.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

# Project root = the directory that contains this file's parent (src/).
BASE_DIR = Path(__file__).resolve().parent.parent

# Files whose tampering is almost always interesting.  Kept deliberately
# short: every entry costs a SHA-256 per monitor cycle.
DEFAULT_CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/ssh/sshd_config",
    str(Path.home() / ".ssh/authorized_keys"),
    str(Path.home() / ".bashrc"),
    str(Path.home() / ".profile"),
    str(Path.home() / ".hermes/config.yaml"),
    str(Path.home() / ".hermes/SOUL.md"),
]

# Processes the responder will never kill, even if a rule matches.
# Killing any of these can lock you out of the box or crash the session.
DEFAULT_PROTECTED_PROCESSES = [
    "systemd", "init", "sshd", "systemd-journald", "systemd-logind",
    "systemd-networkd", "systemd-resolved", "dbus-daemon", "cron", "crond",
    "login", "agetty", "bash", "zsh", "sh", "hermes", "tori-hanzo",
]


@dataclass
class Config:
    """Runtime configuration.  All paths are absolute after load()."""

    base_dir: Path = BASE_DIR
    data_dir: Path = BASE_DIR / "data"
    state_dir: Path = BASE_DIR / "state"
    reports_dir: Path = BASE_DIR / "state" / "reports"

    # --- monitoring cadence ---
    monitor_interval_sec: int = 300          # daemon loop period
    lookback_hours: int = 24                 # journal window for collectors

    # --- detection thresholds ---
    ssh_failed_threshold: int = 5            # fails from one IP -> brute-force
    max_process_args_len: int = 512          # cap captured cmdline length
    max_kernel_lines: int = 200              # cap kernel log scan

    # --- response posture ---
    # Master switch for *active* countermeasures.  When False every fix is
    # executed in dry-run mode: the action is logged with the exact command
    # that *would* have run, but nothing is touched.
    active_response: bool = False
    kill_grace_sec: float = 3.0              # SIGTERM -> wait -> SIGKILL
    protected_processes: list[str] = field(
        default_factory=lambda: list(DEFAULT_PROTECTED_PROCESSES))
    min_killable_pid: int = 200              # never signal low/system PIDs

    # --- admin portal ---
    portal_host: str = "127.0.0.1"           # localhost only, by design
    portal_port: int = 9193

    # --- integrity watch list ---
    critical_files: list[str] = field(
        default_factory=lambda: list(DEFAULT_CRITICAL_FILES))

    # --- findings retention ---
    max_findings: int = 500
    finding_dedupe_hours: int = 24

    def ensure_dirs(self) -> None:
        """Create runtime directories (idempotent)."""
        for d in (self.state_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)
        # state/ holds sensitive material — tighten permissions.
        try:
            os.chmod(self.state_dir, 0o700)
        except OSError:
            pass


def load_config(base_dir: Path | None = None) -> Config:
    """Build the effective config: defaults overlaid with config.local.json.

    The override file is optional and gitignored, so site-specific policy
    (e.g. enabling active_response) never leaks into the repo.
    """
    cfg = Config()
    if base_dir is not None:
        cfg.base_dir = Path(base_dir)
        cfg.data_dir = cfg.base_dir / "data"
        cfg.state_dir = cfg.base_dir / "state"
        cfg.reports_dir = cfg.state_dir / "reports"

    override = cfg.base_dir / "config.local.json"
    if override.exists():
        try:
            data = json.loads(override.read_text(encoding="utf-8"))
            for key, value in data.items():
                if hasattr(cfg, key):
                    setattr(cfg, key, value)
        except (json.JSONDecodeError, OSError) as exc:
            # A broken override must never stop the agent — fall back to
            # defaults and let the reporter surface the problem.
            print(f"[tori-hanzo] WARNING: ignoring bad {override}: {exc}")

    # Normalise paths that may have been overridden as strings.
    for name in ("base_dir", "data_dir", "state_dir", "reports_dir"):
        setattr(cfg, name, Path(getattr(cfg, name)))

    cfg.ensure_dirs()
    return cfg


def config_as_dict(cfg: Config) -> dict:
    """JSON-safe view (used by the portal status page)."""
    d = asdict(cfg)
    return {k: (str(v) if isinstance(v, Path) else v) for k, v in d.items()}
