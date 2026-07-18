"""Daily report generator for Tori-Hanzo.

Produces two artifacts per run:
    state/reports/latest.txt   — Telegram-safe plain text (hashed IPs only)
    state/reports/latest.json  — machine-readable metadata
plus dated archive copies under state/reports/.

Privacy contract (LEARN): text reports must never contain a raw IP address.
Everything off-box is identified by salted hashes.  The localhost admin
portal is the *only* place raw IPs are shown.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from state import StateStore, atomic_write_text, atomic_write_json

ARCHIVE_KEEP = 30  # dated report files to retain


def _pt_now() -> str:
    """Human timestamp in the user's timezone (best-effort PT)."""
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo("America/Los_Angeles")).strftime(
            "%Y-%m-%d %H:%M %Z")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M local")


def _severity_counts(findings: list[dict]) -> Counter:
    return Counter(f.get("severity", "info") for f in findings)


def generate_daily_report(cfg, state: StateStore, defs,
                          hours: int = 24) -> tuple[str, dict]:
    """Assemble the daily summary from state (no live probing — the agent
    loop already collected everything during its cycles)."""
    now = _pt_now()
    findings = state.load_findings()
    open_findings = [f for f in findings if f.get("status") == "open"]
    events = state.read_events(limit=1000)
    actions = state.read_actions(limit=200)
    last_run = state.last_run()

    # --- gather cycle stats from the most recent monitor_cycle events ---
    cycle_events = [e for e in events if e.get("type") == "monitor_cycle"]
    latest_cycle = cycle_events[0] if cycle_events else {}
    ssh_stats = latest_cycle.get("ssh", {})
    udp_ignored = latest_cycle.get("udp_ignored", 0)
    new_listeners = latest_cycle.get("new_listeners", [])
    removed_count = latest_cycle.get("removed_listeners", 0)

    counts = _severity_counts(open_findings)
    dsum = defs.summary()

    lines: list[str] = []
    lines.append("🛡 Tori-Hanzo Daily Security Report")
    lines.append(f"Generated: {now}")
    lines.append("")

    # --- agent posture ------------------------------------------------
    lines.append("Agent status")
    lines.append(f"- Last monitor cycle: {last_run.get('ts', 'never')}")
    lines.append(f"- Active response: "
                 f"{'ON' if cfg.active_response else 'OFF (dry-run only)'}")
    lines.append(f"- Definitions v{dsum['version']}: ports={dsum['ports']} "
                 f"procs={dsum['processes']} ips={dsum['ips']} "
                 f"udp-ignore={dsum['udp_baseline']} fixes={dsum['fixes']}")
    lines.append("")

    # --- listeners ----------------------------------------------------
    lines.append(f"Listeners (last {hours}h)")
    lines.append(f"- New: {len(new_listeners)} | Removed: {removed_count} "
                 f"| UDP churn ignored: {udp_ignored}")
    for sock in new_listeners[:10]:
        lines.append(f"  NEW {sock.get('proto')} {sock.get('addr')}:"
                     f"{sock.get('port')} ({sock.get('process') or '?'})")
    lines.append("")

    # --- intruders ----------------------------------------------------
    lines.append("Intruder watch")
    lines.append(f"- SSH: failed={ssh_stats.get('failed', 0)} "
                 f"success={ssh_stats.get('success', 0)}")
    top_fail = sorted(ssh_stats.get("failed_by_ip", {}).items(),
                      key=lambda kv: kv[1], reverse=True)[:5]
    for token, n in top_fail:
        lines.append(f"  source {token}: {n} failures")
    for login in ssh_stats.get("accepted", [])[:5]:
        lines.append(f"  login: {login.get('user')} from {login.get('ip_hash')}")
    lines.append("")

    # --- findings -----------------------------------------------------
    lines.append(f"Findings (open)")
    if open_findings:
        sev_text = ", ".join(f"{n} {s}" for s, n in
                             sorted(counts.items(),
                                    key=lambda kv: -len(kv[0])))
        lines.append(f"- {len(open_findings)} open ({sev_text})")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(open_findings,
                        key=lambda f: order.get(f["severity"], 5))[:10]:
            lines.append(f"  [{f['severity']}] {f['summary']}")
    else:
        lines.append("- None open. Gate is quiet.")
    lines.append("")

    # --- actions taken -------------------------------------------------
    lines.append("Response actions (recent)")
    if actions:
        for a in actions[:10]:
            lines.append(f"- {a.get('action')} -> {a.get('result')} "
                         f"({'dry-run' if a.get('dry_run') else 'applied'})")
    else:
        lines.append("- None.")
    lines.append("")

    # --- notes ---------------------------------------------------------
    notes = []
    if any(f["severity"] in ("critical", "high") for f in open_findings):
        notes.append("Open critical/high findings — review in the admin "
                     f"portal: http://{cfg.portal_host}:{cfg.portal_port}/")
    if new_listeners:
        notes.append("New listeners appeared — verify each is a service "
                     "you intended to run.")
    if not cfg.active_response:
        notes.append("Active response is OFF; fixes are rehearsed as "
                     "dry-runs. Enable in config.local.json when ready.")
    lines.append("Notes / action items")
    for n in notes or ["All quiet."]:
        lines.append(f"- {n}")

    text = "\n".join(lines) + "\n"

    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "open_findings": len(open_findings),
        "severity_counts": dict(counts),
        "ssh": ssh_stats,
        "udp_ignored": udp_ignored,
        "new_listeners": len(new_listeners),
        "definitions": dsum,
        "active_response": cfg.active_response,
    }
    return text, meta


def write_report(cfg, state: StateStore, text: str, meta: dict) -> None:
    """Persist latest + dated archive copies, pruning old archives."""
    reports = Path(cfg.reports_dir)
    atomic_write_text(reports / "latest.txt", text)
    atomic_write_json(reports / "latest.json", meta)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    atomic_write_text(reports / f"report_{stamp}.txt", text)
    # prune archives
    archives = sorted(reports.glob("report_*.txt"))
    for old in archives[:-ARCHIVE_KEEP]:
        try:
            old.unlink()
        except OSError:
            pass
