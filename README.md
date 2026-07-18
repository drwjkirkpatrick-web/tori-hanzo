# ⛩ Tori-Hanzo

**A local security agent that stands guard over your Hermes host.**

Named for the *torii* — the gate that marks the boundary between ordinary
ground and sacred space — and *Hattori Hanzō*, the legendary guard who kept
the gate. Tori-Hanzo watches the threshold of your machine: who knocks,
who enters, who lingers, and what quietly changes in the night.

It was built with love for a single purpose: **let one person administer a
small, busy Linux box with the calm confidence of a whole security team.**

---

## What it does for you

| You asked for… | Tori-Hanzo answers with… |
|---|---|
| **Monitoring** | A daemon cycle (`ss`, `ps`, `who`, `journalctl`, file hashes) that never raises and never touches the system |
| **Web portal for admin** | A dark, dependency-free Flask UI on `127.0.0.1:9193`, token-locked, CSRF-guarded |
| **Update definitions from CSV** | Five plain-text CSVs in `data/` — edit by hand, paste in the portal, or sync from anywhere; hot-reload |
| **Fixes from CSV** | `fixes.csv` maps every finding type to `alert` / `kill_process` / `block_ip`, auto or manual |
| **Stop rogue activities** | A responder with thick safety rails: dry-run by default, protected-process list, PID floor, IP validation, full audit trail |
| **See intruders** | SSH failures (salt-hashed sources), accepted logins, logged-in users, established connections with dispositions |
| **Ignore normal UDP churn** | `udp_baseline.csv` + `ignore` dispositions — mDNS/DHCP/SSDP noise never alerts; add new ignores from the portal |
| **Daily cron report** | A Telegram-safe plain-text summary (no raw IPs, ever) wired to a Hermes cron job |

## Quickstart

```bash
cd tori-hanzo
pip install -r requirements.txt      # just Flask (+ pytest for tests)

python3 tori-hanzo.py run-once       # first cycle: learns the baseline
python3 tori-hanzo.py run-once       # second cycle: quiet — baseline known
python3 tori-hanzo.py report         # print the daily summary
python3 tori-hanzo.py portal         # admin UI on http://127.0.0.1:9193/
python3 tori-hanzo.py token          # print the portal login token
python3 tori-hanzo.py serve          # daemon + portal together
```

The first cycle deliberately flags everything as *new* — that's the agent
learning what normal looks like on your host. From the second cycle on, it
only speaks when something changes.

## The five CSVs (the agent's brain)

Everything Tori-Hanzo knows lives in `data/` as plain text — diffable,
commit-able, editable from the portal's **Definitions** page:

- **`port_definitions.csv`** — `proto,port,process,disposition,notes`
- **`process_definitions.csv`** — `name,pattern,match_type,disposition,notes`
  (ships with miner/malware/scanner signatures: xmrig, kinsing, hydra, nmap…)
- **`ip_definitions.csv`** — `cidr,disposition,notes` (longest prefix wins)
- **`udp_baseline.csv`** — `port,process,notes` — the "normal churn" list
- **`fixes.csv`** — `finding_type,action,auto,notes`

**Dispositions:** `allow` · `allow-local` (loopback fine, `0.0.0.0` = high
alert) · `ignore` (never alerts) · `alert` · `deny`.

## Safety posture (read this before flipping the switch)

Active response is **OFF by default**. Every fix — even the automatic
ones — runs as a *dry-run* rehearsal, logging the exact command it would
have executed to `state/actions.jsonl`. When you're ready:

```json
// config.local.json  (gitignored — never committed)
{ "active_response": true }
```

Even then, the responder refuses to:
- kill PIDs below 200, anything on the protected list
  (`sshd`, `systemd`, shells, `hermes`, `tori-hanzo` itself), or anything
  whose command line mentions hermes/tori-hanzo;
- block loopback, multicast, or LAN addresses without an explicit force flag.

Every attempt — applied, dry-run, or refused — is audit-logged.

## Privacy contract

- **Off-box reports never contain raw IPs.** Sources are salted SHA-256
  tokens (`state/salt`, mode `0600`).
- **Raw IPs appear only in the localhost portal** — that's what an admin
  view is for — and they never leave the machine.
- `state/` is gitignored entirely: tokens, baselines, events, findings.

## Architecture

```
tori-hanzo.py          CLI entry (run-once / daemon / portal / serve / report / defs / token)
src/
  config.py            JSON-overridable config, zero third-party deps
  state.py             atomic writes, event log, secrets
  definitions.py       the five CSVs: load, query, hot-reload, update
  monitor.py           read-only collectors (parse and execution separated)
  detector.py          pure rules engine: observation + defs -> findings
  responder.py         kill / block with safety rails + audit trail
  reporter.py          daily summary (hashed IPs) + archive
  portal.py            Flask admin UI, token auth + CSRF, no external assets
  agent.py             the boring, trustworthy daemon loop
data/                  the CSV knowledge base (committed)
state/                 runtime only (gitignored)
tests/                 69 tests, fully offline — no root, no network
```

Design vows: collectors never modify the system; the detector is a pure
function; the agent loop owns every side effect; every write is atomic
(tempfile → fsync → rename); a hung `journalctl` can't stall the agent
(25 s command timeouts); malformed CSV rows are skipped, never fatal.

## Testing

```bash
python3 -m pytest tests/ -q     # 69 passed
```

The suite fakes the command runner, so detection logic is tested end-to-end
with canned `ss`/`journalctl` output — no root, no network, no side effects.

## Roadmap

- nftables backend alongside iptables
- Definition sync from a signed upstream URL (https-only, hashed)
- Per-finding snooze/mute from the portal
- systemd unit + install script
- Optional Telegram alert on critical findings between daily reports

---

*The gate is quiet. Hanzō is awake.* ⛩
