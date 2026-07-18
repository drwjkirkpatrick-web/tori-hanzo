"""CSV-driven knowledge base for Tori-Hanzo.

The agent's *brain* is five CSV files under `data/`.  They are deliberately
plain text so they can be edited by hand, updated from the admin portal,
version-controlled in git, or synced from an upstream feed.

    data/port_definitions.csv     proto,port,process,disposition,notes
    data/process_definitions.csv  name,pattern,match_type,disposition,notes
    data/ip_definitions.csv       cidr,disposition,notes
    data/udp_baseline.csv         port,process,notes        (normal UDP churn)
    data/fixes.csv                finding_type,action,auto,notes

Dispositions
------------
allow        known-good, never alert
allow-local  fine on 127.0.0.1/::1, alert if bound to all interfaces
ignore       expected churn — never alert (used heavily for UDP)
alert        worth a medium finding when seen
deny         known-bad — high/critical finding, candidate for response

LEARN: every loader is forgiving.  A malformed row is skipped and counted,
never fatal — a hand-edited CSV with a stray comma must not take down the
security agent.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

VALID_DISPOSITIONS = {"allow", "allow-local", "ignore", "alert", "deny"}
VALID_MATCH_TYPES = {"substring", "regex", "exact"}
VALID_FIX_ACTIONS = {"alert", "kill_process", "block_ip"}

# Expected headers — used to validate portal uploads before replacing a file.
CSV_HEADERS = {
    "ports": ["proto", "port", "process", "disposition", "notes"],
    "processes": ["name", "pattern", "match_type", "disposition", "notes"],
    "ips": ["cidr", "disposition", "notes"],
    "udp_baseline": ["port", "process", "notes"],
    "fixes": ["finding_type", "action", "auto", "notes"],
}


@dataclass
class PortRule:
    proto: str
    port: int
    process: str          # "" means "any process"
    disposition: str
    notes: str = ""


@dataclass
class ProcessRule:
    name: str
    pattern: str
    match_type: str       # substring | regex | exact
    disposition: str
    notes: str = ""
    _compiled: re.Pattern | None = field(default=None, repr=False, compare=False)

    def matches(self, text: str) -> bool:
        """Match against a process command line."""
        if self.match_type == "exact":
            return text.strip() == self.pattern
        if self.match_type == "substring":
            return self.pattern.lower() in text.lower()
        # regex — compiled lazily, invalid patterns never match
        if self._compiled is None:
            try:
                self._compiled = re.compile(self.pattern, re.IGNORECASE)
            except re.error:
                return False
        return bool(self._compiled.search(text))


@dataclass
class IPRule:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    disposition: str
    notes: str = ""


@dataclass
class UDPIgnore:
    port: int             # 0 means "any port"
    process: str          # "" means "any process"
    notes: str = ""


@dataclass
class FixRule:
    finding_type: str
    action: str           # alert | kill_process | block_ip
    auto: bool            # may run unattended (still gated by active_response)
    notes: str = ""


class DefinitionStore:
    """Loads, queries, and updates the five CSV knowledge files."""

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.ports: list[PortRule] = []
        self.processes: list[ProcessRule] = []
        self.ips: list[IPRule] = []
        self.udp_baseline: list[UDPIgnore] = []
        self.fixes: dict[str, FixRule] = {}
        self.skipped_rows: dict[str, int] = {}
        self.reload()

    # ------------------------------------------------------------------
    # loading
    # ------------------------------------------------------------------
    def _path(self, kind: str) -> Path:
        names = {
            "ports": "port_definitions.csv",
            "processes": "process_definitions.csv",
            "ips": "ip_definitions.csv",
            "udp_baseline": "udp_baseline.csv",
            "fixes": "fixes.csv",
        }
        return self.data_dir / names[kind]

    @staticmethod
    def _rows(path: Path) -> tuple[list[dict], int]:
        """Return (rows, skipped) for a CSV; missing file -> ([], 0)."""
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return [], 0
        rows, skipped = [], 0
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            # Skip blank lines and rows that are all-None (ragged input).
            if not row or all(v in (None, "") for v in row.values()):
                skipped += 1
                continue
            rows.append({(k or "").strip(): (v or "").strip()
                         for k, v in row.items()})
        return rows, skipped

    def reload(self) -> None:
        """(Re)load all five CSVs.  Safe to call at any time."""
        self.ports, self.processes, self.ips = [], [], []
        self.udp_baseline, self.fixes = [], {}
        self.skipped_rows = {}

        rows, skipped = self._rows(self._path("ports"))
        self.skipped_rows["ports"] = skipped
        for r in rows:
            try:
                port = int(r["port"])
            except (KeyError, ValueError):
                self.skipped_rows["ports"] += 1
                continue
            disp = r.get("disposition", "alert")
            if disp not in VALID_DISPOSITIONS:
                self.skipped_rows["ports"] += 1
                continue
            self.ports.append(PortRule(
                proto=r.get("proto", "tcp").lower(), port=port,
                process=r.get("process", ""), disposition=disp,
                notes=r.get("notes", "")))

        rows, skipped = self._rows(self._path("processes"))
        self.skipped_rows["processes"] = skipped
        for r in rows:
            disp = r.get("disposition", "alert")
            mtype = r.get("match_type", "substring")
            if disp not in VALID_DISPOSITIONS or mtype not in VALID_MATCH_TYPES \
                    or not r.get("pattern"):
                self.skipped_rows["processes"] += 1
                continue
            self.processes.append(ProcessRule(
                name=r.get("name", r["pattern"][:24]), pattern=r["pattern"],
                match_type=mtype, disposition=disp, notes=r.get("notes", "")))

        rows, skipped = self._rows(self._path("ips"))
        self.skipped_rows["ips"] = skipped
        for r in rows:
            disp = r.get("disposition", "alert")
            try:
                net = ipaddress.ip_network(r.get("cidr", ""), strict=False)
            except ValueError:
                self.skipped_rows["ips"] += 1
                continue
            if disp not in VALID_DISPOSITIONS:
                self.skipped_rows["ips"] += 1
                continue
            self.ips.append(IPRule(network=net, disposition=disp,
                                   notes=r.get("notes", "")))

        rows, skipped = self._rows(self._path("udp_baseline"))
        self.skipped_rows["udp_baseline"] = skipped
        for r in rows:
            try:
                port = int(r.get("port", "0") or 0)
            except ValueError:
                self.skipped_rows["udp_baseline"] += 1
                continue
            self.udp_baseline.append(UDPIgnore(
                port=port, process=r.get("process", ""), notes=r.get("notes", "")))

        rows, skipped = self._rows(self._path("fixes"))
        self.skipped_rows["fixes"] = skipped
        for r in rows:
            action = r.get("action", "alert")
            ftype = r.get("finding_type", "")
            if action not in VALID_FIX_ACTIONS or not ftype:
                self.skipped_rows["fixes"] += 1
                continue
            self.fixes[ftype] = FixRule(
                finding_type=ftype, action=action,
                auto=r.get("auto", "false").lower() == "true",
                notes=r.get("notes", ""))

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------
    def port_disposition(self, proto: str, port: int, process: str) -> str:
        """Best-match disposition for a listening socket (default 'alert').

        More specific rules win: an exact proto+port+process match beats
        proto+port, which beats the built-in default.
        """
        best, best_score = None, -1
        for rule in self.ports:
            if rule.proto != proto.lower() or rule.port != port:
                continue
            score = 1
            if rule.process:
                if rule.process.lower() in (process or "").lower():
                    score = 2
                else:
                    continue
            if score > best_score:
                best, best_score = rule.disposition, score
        return best or "alert"

    def is_ignored_udp(self, port: int, process: str) -> bool:
        """True when this UDP socket is expected churn (mDNS, DHCP, …).

        Checks the explicit udp_baseline.csv first, then any port rule whose
        disposition is 'ignore'.  This is the feature that keeps routine
        UDP port changes out of the alert stream.
        """
        for entry in self.udp_baseline:
            port_ok = entry.port in (0, port)
            proc_ok = (not entry.process) or \
                      (entry.process.lower() in (process or "").lower())
            if port_ok and proc_ok:
                return True
        return self.port_disposition("udp", port, process) == "ignore"

    def process_verdicts(self, cmdline: str) -> list[ProcessRule]:
        """All process rules matching a command line (deny + alert)."""
        return [r for r in self.processes if r.matches(cmdline)]

    def ip_disposition(self, ip_str: str) -> str:
        """Disposition for an IP (default 'alert' for unknown hosts)."""
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return "alert"
        # Most specific (longest prefix) match wins.
        best, best_prefix = None, -1
        for rule in self.ips:
            if addr in rule.network and rule.network.prefixlen > best_prefix:
                best, best_prefix = rule.disposition, rule.network.prefixlen
        return best or "alert"

    def fix_for(self, finding_type: str) -> FixRule | None:
        return self.fixes.get(finding_type)

    # ------------------------------------------------------------------
    # updates (portal / CLI)
    # ------------------------------------------------------------------
    def add_udp_ignore(self, port: int, process: str = "", notes: str = "") -> None:
        """Append a row to udp_baseline.csv and reload.

        This is the portal's 'ignore this UDP chatter' button.
        """
        path = self._path("udp_baseline")
        exists = path.exists()
        with open(path, "a", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            if not exists:
                writer.writerow(CSV_HEADERS["udp_baseline"])
            # Basic CSV-injection guard: strip leading = + - @ from notes.
            safe_notes = notes.lstrip("=+-@") if notes else ""
            writer.writerow([port, process, safe_notes])
        self.reload()

    def update_from_csv(self, kind: str, text: str) -> tuple[bool, str]:
        """Replace one CSV wholesale (portal upload).  Validates the header
        and row count before touching the real file."""
        if kind not in CSV_HEADERS:
            return False, f"unknown definition kind: {kind}"
        expected = CSV_HEADERS[kind]
        try:
            reader = csv.reader(io.StringIO(text))
            header = next(reader)
        except StopIteration:
            return False, "empty CSV"
        if [h.strip() for h in header] != expected:
            return False, f"bad header {header}; expected {expected}"
        # Sanity: refuse files over 1 MB or 50k rows.
        if len(text) > 1_000_000:
            return False, "CSV too large (1 MB max)"
        self._path(kind).write_text(text, encoding="utf-8")
        self.reload()
        return True, f"{kind} definitions updated"

    # ------------------------------------------------------------------
    # introspection
    # ------------------------------------------------------------------
    def version(self) -> str:
        """Short content hash of all five files — bump = defs changed."""
        h = hashlib.sha256()
        for kind in ("ports", "processes", "ips", "udp_baseline", "fixes"):
            try:
                h.update(self._path(kind).read_bytes())
            except OSError:
                h.update(b"<missing>")
        return h.hexdigest()[:12]

    def summary(self) -> dict:
        return {
            "ports": len(self.ports),
            "processes": len(self.processes),
            "ips": len(self.ips),
            "udp_baseline": len(self.udp_baseline),
            "fixes": len(self.fixes),
            "skipped_rows": dict(self.skipped_rows),
            "version": self.version(),
        }
