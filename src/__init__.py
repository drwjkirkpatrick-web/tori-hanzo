"""Tori-Hanzo — local security agent for a Hermes host.

Named for the gate (鳥居, *tori*) and the guard (半蔵, *Hanzō*):
a gate-keeper that watches the threshold of the machine.

Package layout
--------------
config       — paths + tunables (JSON-overridable, no external deps)
state        — atomic persistence, event log, secrets (salt, portal token)
definitions  — CSV-driven knowledge base (ports, processes, IPs, UDP baseline, fixes)
monitor      — read-only collectors (ss, ps, who, journalctl, file hashes)
detector     — rules engine: observations + definitions -> findings
responder    — active countermeasures (kill process, block IP) with safety rails
reporter     — daily Telegram-safe summary (hashed IPs only)
portal       — Flask admin web UI (localhost-only, token auth)
agent        — the daemon loop tying everything together
"""

__version__ = "0.1.0"
