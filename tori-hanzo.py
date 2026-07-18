#!/usr/bin/env python3
"""Tori-Hanzo — local security agent for a Hermes host.

Usage:
    python3 tori-hanzo.py run-once     # one monitor cycle, print findings
    python3 tori-hanzo.py daemon       # monitor loop forever
    python3 tori-hanzo.py portal       # admin web UI on 127.0.0.1:9193
    python3 tori-hanzo.py serve        # daemon + portal in one process
    python3 tori-hanzo.py report       # generate + print the daily report
    python3 tori-hanzo.py defs         # show definition store summary
    python3 tori-hanzo.py token        # print the admin portal token
    python3 tori-hanzo.py version
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path

# Make `src/` importable whether invoked from repo root or elsewhere.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from __init__ import __version__          # noqa: E402  (package version)
from agent import Agent                   # noqa: E402
from config import load_config            # noqa: E402
from portal import create_app             # noqa: E402


def cmd_run_once(agent: Agent) -> int:
    result = agent.run_cycle()
    findings = result["findings"]
    print(f"cycle complete — {len(findings)} new findings, "
          f"{result['udp_ignored']} UDP sockets ignored (baseline)")
    for f in findings:
        print(f"  [{f['severity']:>8}] {f['type']}: {f['summary']}")
    for a in result["auto_actions"]:
        print(f"  auto-fix: {a.get('action')} -> {a.get('result')} "
              f"({a.get('detail', '')})")
    return 0


def cmd_daemon(agent: Agent) -> int:
    agent.serve_forever()
    return 0  # unreachable


def cmd_portal(cfg, agent: Agent) -> int:
    app = create_app(cfg, agent.state, agent.defs, agent.responder, agent)
    print(f"[tori-hanzo] admin portal: http://{cfg.portal_host}:{cfg.portal_port}/")
    print(f"[tori-hanzo] login token:  {agent.state.get_portal_token()}")
    app.run(host=cfg.portal_host, port=cfg.portal_port, debug=False)
    return 0


def cmd_serve(cfg, agent: Agent) -> int:
    """Daemon loop in a background thread + portal in the foreground."""
    t = threading.Thread(target=agent.serve_forever, daemon=True)
    t.start()
    return cmd_portal(cfg, agent)


def cmd_report(agent: Agent) -> int:
    text, _ = agent.daily_report()
    print(text, end="")
    return 0


def cmd_defs(agent: Agent) -> int:
    print(json.dumps(agent.defs.summary(), indent=2))
    return 0


def cmd_token(agent: Agent) -> int:
    print(agent.state.get_portal_token())
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="tori-hanzo",
        description="Local security agent for a Hermes host")
    parser.add_argument("command", choices=[
        "run-once", "daemon", "portal", "serve", "report",
        "defs", "token", "version"])
    args = parser.parse_args()

    if args.command == "version":
        print(f"tori-hanzo {__version__}")
        return 0

    cfg = load_config()
    agent = Agent(cfg)

    return {
        "run-once": lambda: cmd_run_once(agent),
        "daemon": lambda: cmd_daemon(agent),
        "portal": lambda: cmd_portal(cfg, agent),
        "serve": lambda: cmd_serve(cfg, agent),
        "report": lambda: cmd_report(agent),
        "defs": lambda: cmd_defs(agent),
        "token": lambda: cmd_token(agent),
    }[args.command]()


if __name__ == "__main__":
    raise SystemExit(main())
