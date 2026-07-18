"""Admin web portal for Tori-Hanzo (Flask).

Security posture (LEARN — the admin UI of a security tool is itself an
attack surface):
  * Binds to 127.0.0.1 ONLY.  No LAN exposure, ever, by design.
  * Token login (state/portal_token, mode 0600).  Sessions signed with the
    install salt.
  * CSRF token required on every POST form.
  * Login attempts rate-limited per session.
  * Raw IPs ARE shown here — that is the point of an admin portal — but
    they never leave the box: reports and events stay hashed.
  * No CDN/external assets: one inline stylesheet, zero JavaScript deps.
"""

from __future__ import annotations

import hmac
import html
import secrets
from functools import wraps

from flask import (Flask, abort, g, jsonify, redirect, render_template_string,
                   request, session, url_for)

from definitions import CSV_HEADERS
from state import read_json

MAX_LOGIN_ATTEMPTS = 5

# ----------------------------------------------------------------------
# templates (inline, single-file deployment)
# ----------------------------------------------------------------------
BASE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{{ title }} · Tori-Hanzo</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3;
          --dim:#8b949e; --accent:#58a6ff; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.5 -apple-system,"Segoe UI",Roboto,monospace; }
  header { background:var(--panel); border-bottom:1px solid var(--border);
           padding:12px 24px; display:flex; gap:18px; align-items:center; }
  header b { color:var(--accent); font-size:16px; }
  nav a { color:var(--dim); text-decoration:none; margin-right:14px; }
  nav a:hover { color:var(--fg); }
  main { padding:24px; max-width:1200px; margin:0 auto; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
           gap:12px; margin-bottom:20px; }
  .card { background:var(--panel); border:1px solid var(--border);
          border-radius:8px; padding:14px; }
  .card .num { font-size:22px; font-weight:600; }
  table { width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--border); border-radius:8px; margin-bottom:20px; }
  th,td { padding:8px 10px; border-bottom:1px solid var(--border);
          text-align:left; vertical-align:top; }
  th { color:var(--dim); font-weight:600; font-size:12px; text-transform:uppercase; }
  .sev-critical { color:#ff7b72; font-weight:700; }
  .sev-high { color:#ffa657; font-weight:600; }
  .sev-medium { color:#d29922; }
  .sev-low { color:#79c0ff; }
  .sev-info { color:var(--dim); }
  .pill { display:inline-block; padding:1px 8px; border-radius:10px;
          font-size:12px; border:1px solid var(--border); }
  .pill.on { color:#3fb950; border-color:#3fb950; }
  .pill.off { color:#d29922; border-color:#d29922; }
  button, .btn { background:#21262d; color:var(--fg); border:1px solid var(--border);
          border-radius:6px; padding:4px 10px; cursor:pointer; font-size:12px; }
  button:hover { border-color:var(--accent); }
  button.danger { border-color:#f85149; color:#ff7b72; }
  input[type=text],input[type=password],input[type=number],textarea {
    background:#0d1117; color:var(--fg); border:1px solid var(--border);
    border-radius:6px; padding:6px 8px; width:100%; }
  form.inline { display:inline; }
  .muted { color:var(--dim); }
  .flash { padding:10px 14px; border-radius:6px; margin-bottom:16px;
           background:#1f6feb33; border:1px solid #1f6feb; }
  h2 { margin-top:28px; border-bottom:1px solid var(--border); padding-bottom:6px; }
  pre { background:var(--panel); border:1px solid var(--border); padding:14px;
        border-radius:8px; overflow-x:auto; white-space:pre-wrap; }
</style></head><body>
<header><b>⛩ Tori-Hanzo</b>
  <nav>
    <a href="{{ url_for('dashboard') }}">Dashboard</a>
    <a href="{{ url_for('definitions_page') }}">Definitions</a>
    <a href="{{ url_for('report_page') }}">Report</a>
    <a href="{{ url_for('logout') }}">Logout</a>
  </nav></header>
<main>
{% if flash %}<div class="flash">{{ flash }}</div>{% endif %}
{{ body }}
</main></body></html>"""


def _page(title: str, body: str, flash: str = "") -> str:
    # NOTE: render_template_string does not autoescape — `body` is trusted
    # HTML we built ourselves (every dynamic value passed through _esc),
    # while `flash` may contain echoed form data and must be escaped here.
    return render_template_string(BASE, title=title, body=body,
                                  flash=_esc(flash))


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _csrf_field() -> str:
    return f'<input type="hidden" name="csrf" value="{session.get("csrf", "")}">'


# ----------------------------------------------------------------------
# app factory
# ----------------------------------------------------------------------
def create_app(cfg, state, defs, responder, agent=None) -> Flask:
    app = Flask(__name__)
    app.secret_key = state.get_salt()  # stable per-install signing key

    # ---------------- auth helpers ----------------
    def _check_csrf() -> bool:
        token = session.get("csrf")
        sent = request.form.get("csrf", "")
        return bool(token) and hmac.compare_digest(token, sent)

    def require_auth(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("auth"):
                if request.path.startswith("/api/"):
                    return jsonify({"error": "auth required"}), 401
                return redirect(url_for("login"))
            if request.method == "POST" and not _check_csrf():
                abort(403, "bad CSRF token")
            return fn(*args, **kwargs)
        return wrapper

    @app.before_request
    def _ensure_csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)

    # ---------------- auth routes ----------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = ""
        if session.get("login_fails", 0) >= MAX_LOGIN_ATTEMPTS:
            return _page("Login", "<p>Too many failed attempts. Restart the "
                                  "browser session to try again.</p>")
        if request.method == "POST":
            token = request.form.get("token", "")
            if hmac.compare_digest(token, state.get_portal_token()):
                session.clear()
                session["auth"] = True
                session["csrf"] = secrets.token_hex(16)
                state.append_event("portal_login", {"ok": True})
                return redirect(url_for("dashboard"))
            session["login_fails"] = session.get("login_fails", 0) + 1
            state.append_event("portal_login", {"ok": False})
            error = "Invalid token."
        body = f"""
        <h2>Admin Login</h2>
        <p class="muted">Token lives in <code>state/portal_token</code> —
           or run <code>python3 tori-hanzo.py token</code>.</p>
        <form method="post">{_csrf_field()}
          <input type="password" name="token" autofocus
                 placeholder="portal token">
          <p><button type="submit">Enter</button></p>
          <p class="sev-critical">{_esc(error)}</p>
        </form>"""
        return _page("Login", body)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # ---------------- data helpers ----------------
    def _last_obs() -> dict:
        return read_json(state.dir / "last_observation.json", {})

    def _finding_options(f: dict) -> str:
        """Action buttons for one finding row."""
        out = []
        if f.get("status") == "open":
            out.append(f"""<form class="inline" method="post"
              action="{url_for('ack_finding', fid=f['id'])}">{_csrf_field()}
              <button>Ack</button></form>""")
            pid = f.get("details", {}).get("pid")
            if isinstance(pid, int):
                out.append(f"""<form class="inline" method="post"
                  action="{url_for('respond_kill')}">{_csrf_field()}
                  <input type="hidden" name="pid" value="{pid}">
                  <button class="danger">Kill pid {pid}</button></form>""")
            ip = f.get("details", {}).get("connection", {}).get("remote_addr")
            if ip:
                out.append(f"""<form class="inline" method="post"
                  action="{url_for('respond_block')}">{_csrf_field()}
                  <input type="hidden" name="ip" value="{_esc(ip)}">
                  <button class="danger">Block {_esc(ip)}</button></form>""")
        return " ".join(out) or '<span class="muted">—</span>'

    # ---------------- dashboard ----------------
    @app.route("/")
    @require_auth
    def dashboard():
        obs = _last_obs()
        findings = state.load_findings()
        open_f = [f for f in findings if f.get("status") == "open"]
        actions = state.read_actions(limit=15)
        last_run = state.last_run()
        dsum = defs.summary()
        blocked = state.load_blocked_ips()

        cards = f"""
        <div class="cards">
          <div class="card"><div class="num">{len(open_f)}</div>
            <div class="muted">open findings</div></div>
          <div class="card"><div class="num">{len(obs.get('listeners', []))}</div>
            <div class="muted">listening sockets</div></div>
          <div class="card"><div class="num">{obs.get('ssh', {}).get('failed', 0)}</div>
            <div class="muted">SSH failures (24h)</div></div>
          <div class="card"><div class="num">{len(obs.get('established', []))}</div>
            <div class="muted">established conns</div></div>
          <div class="card"><div class="num">
            <span class="pill {'on' if cfg.active_response else 'off'}">
            {'ON' if cfg.active_response else 'DRY-RUN'}</span></div>
            <div class="muted">active response</div></div>
          <div class="card"><div class="num" style="font-size:14px">
            v{dsum['version']}</div>
            <div class="muted">definitions</div></div>
        </div>
        <p class="muted">Last cycle: {_esc(last_run.get('ts', 'never'))} ·
           Portal: {cfg.portal_host}:{cfg.portal_port}</p>"""

        # --- intruders panel ---
        users_rows = "".join(
            f"<tr><td>{_esc(u['user'])}</td><td>{_esc(u['tty'])}</td>"
            f"<td>{_esc(u['since'])}</td><td>{_esc(u['host'])}</td></tr>"
            for u in obs.get("users", []))
        ssh = obs.get("ssh", {})
        fail_rows = "".join(
            f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>"
            for k, v in sorted(ssh.get("failed_by_ip", {}).items(),
                               key=lambda kv: -kv[1])[:10])
        conn_rows = "".join(
            f"<tr><td>{_esc(c['remote_addr'])}:{c['remote_port']}</td>"
            f"<td>{_esc(c['local_port'])}</td>"
            f"<td>{_esc(defs.ip_disposition(c['remote_addr']))}</td>"
            f"<td>{_esc(c['process'] or '?')} ({c.get('pid') or '?'})</td></tr>"
            for c in obs.get("established", [])[:25])
        intruders = f"""
        <h2>Intruder watch</h2>
        <p>SSH: <b>{ssh.get('failed', 0)}</b> failed /
           <b>{ssh.get('success', 0)}</b> accepted (24h, sources hashed)</p>
        <table><tr><th>hashed source</th><th>failures</th></tr>{fail_rows or '<tr><td colspan=2 class=muted>none</td></tr>'}</table>
        <h3>Logged-in users</h3>
        <table><tr><th>user</th><th>tty</th><th>since</th><th>from</th></tr>
        {users_rows or '<tr><td colspan=4 class=muted>no data — run a cycle</td></tr>'}</table>
        <h3>Established connections (raw IPs — localhost view only)</h3>
        <table><tr><th>remote</th><th>local port</th><th>disposition</th><th>process</th></tr>
        {conn_rows or '<tr><td colspan=4 class=muted>none</td></tr>'}</table>"""

        # --- listeners ---
        lis_rows = "".join(
            f"<tr><td>{s['proto']}</td><td>{_esc(s['addr'])}:{s['port']}</td>"
            f"<td>{_esc(s['process'] or '?')}</td>"
            f"<td>{_esc(defs.port_disposition(s['proto'], s['port'], s['process']))}"
            f"{' <span class=pill>udp-ignored</span>' if s['proto']=='udp' and defs.is_ignored_udp(s['port'], s['process']) else ''}</td></tr>"
            for s in sorted(obs.get("listeners", []),
                            key=lambda x: (x["proto"], x["port"])))
        listeners = f"""
        <h2>Listeners</h2>
        <table><tr><th>proto</th><th>bind</th><th>process</th><th>disposition</th></tr>
        {lis_rows or '<tr><td colspan=4 class=muted>no data</td></tr>'}</table>"""

        # --- findings ---
        f_rows = "".join(
            f"<tr><td class='sev-{_esc(f['severity'])}'>{_esc(f['severity'])}</td>"
            f"<td>{_esc(f['type'])}</td><td>{_esc(f['summary'])}</td>"
            f"<td>{_esc(f['status'])}</td><td>{_finding_options(f)}</td></tr>"
            for f in findings[:50])
        findings_html = f"""
        <h2>Findings</h2>
        <form class="inline" method="post" action="{url_for('run_cycle')}">
          {_csrf_field()}<button>Run cycle now</button></form>
        <table><tr><th>sev</th><th>type</th><th>summary</th><th>status</th><th>actions</th></tr>
        {f_rows or '<tr><td colspan=5 class=muted>none — gate is quiet</td></tr>'}</table>"""

        # --- actions / blocked ---
        a_rows = "".join(
            f"<tr><td>{_esc(a.get('ts','')[:19])}</td><td>{_esc(a['action'])}</td>"
            f"<td>{_esc(a.get('result'))}</td>"
            f"<td>{'dry-run' if a.get('dry_run') else '<b>applied</b>'}</td>"
            f"<td class=muted>{_esc(a.get('detail',''))[:100]}</td></tr>"
            for a in actions)
        b_rows = "".join(
            f"<tr><td>{_esc(b['ip'])}</td><td>{_esc(b.get('reason',''))[:60]}</td>"
            f"<td><form class=inline method=post action={url_for('respond_unblock')}>"
            f"{_csrf_field()}<input type=hidden name=ip value={_esc(b['ip'])}>"
            f"<button>Unblock</button></form></td></tr>"
            for b in blocked)
        actions_html = f"""
        <h2>Response actions</h2>
        <table><tr><th>time</th><th>action</th><th>result</th><th>mode</th><th>detail</th></tr>
        {a_rows or '<tr><td colspan=5 class=muted>none</td></tr>'}</table>
        <h3>Blocked IPs</h3>
        <table><tr><th>ip</th><th>reason</th><th></th></tr>
        {b_rows or '<tr><td colspan=3 class=muted>none</td></tr>'}</table>"""

        return _page("Dashboard",
                     cards + intruders + listeners + findings_html + actions_html,
                     flash=request.args.get("flash", ""))

    # ---------------- findings actions ----------------
    @app.route("/findings/<fid>/ack", methods=["POST"])
    @require_auth
    def ack_finding(fid):
        findings = state.load_findings()
        for f in findings:
            if f.get("id") == fid:
                f["status"] = "ack"
        state.save_findings(findings, cap=cfg.max_findings)
        state.append_event("finding_ack", {"id": fid})
        return redirect(url_for("dashboard", flash=f"Finding {fid} acknowledged"))

    @app.route("/cycle/run", methods=["POST"])
    @require_auth
    def run_cycle():
        if agent is None:
            return redirect(url_for("dashboard",
                                    flash="Agent not attached to portal"))
        result = agent.run_cycle()
        return redirect(url_for(
            "dashboard",
            flash=f"Cycle complete: {len(result['findings'])} new findings"))

    # ---------------- responder endpoints ----------------
    @app.route("/respond/kill", methods=["POST"])
    @require_auth
    def respond_kill():
        try:
            pid = int(request.form.get("pid", "0"))
        except ValueError:
            pid = 0
        result = responder.kill_process(pid, reason="manual via portal")
        return redirect(url_for("dashboard",
                                flash=f"kill {pid}: {result['result']} — "
                                      f"{result.get('detail', '')}"))

    @app.route("/respond/block", methods=["POST"])
    @require_auth
    def respond_block():
        ip = request.form.get("ip", "")
        force = request.form.get("force") == "1"
        result = responder.block_ip(ip, reason="manual via portal", force=force)
        return redirect(url_for("dashboard",
                                flash=f"block {ip}: {result['result']} — "
                                      f"{result.get('detail', '')}"))

    @app.route("/respond/unblock", methods=["POST"])
    @require_auth
    def respond_unblock():
        ip = request.form.get("ip", "")
        result = responder.unblock_ip(ip)
        return redirect(url_for("dashboard",
                                flash=f"unblock {ip}: {result['result']}"))

    # ---------------- definitions page ----------------
    @app.route("/definitions")
    @require_auth
    def definitions_page():
        dsum = defs.summary()
        cards = f"""
        <div class="cards">
          <div class="card"><div class="num">{dsum['ports']}</div><div class="muted">port rules</div></div>
          <div class="card"><div class="num">{dsum['processes']}</div><div class="muted">process rules</div></div>
          <div class="card"><div class="num">{dsum['ips']}</div><div class="muted">ip rules</div></div>
          <div class="card"><div class="num">{dsum['udp_baseline']}</div><div class="muted">udp ignores</div></div>
          <div class="card"><div class="num">{dsum['fixes']}</div><div class="muted">fix rules</div></div>
          <div class="card"><div class="num" style="font-size:14px">v{dsum['version']}</div><div class="muted">version</div></div>
        </div>
        <form class="inline" method="post" action="{url_for('defs_reload')}">
          {_csrf_field()}<button>Reload from disk</button></form>"""

        udp_rows = "".join(
            f"<tr><td>{e.port or 'any'}</td><td>{_esc(e.process or 'any')}</td>"
            f"<td class=muted>{_esc(e.notes)}</td></tr>"
            for e in defs.udp_baseline)
        udp_html = f"""
        <h2>UDP ignore baseline <span class="muted">(normal churn never alerts)</span></h2>
        <table><tr><th>port</th><th>process</th><th>notes</th></tr>
        {udp_rows or '<tr><td colspan=3 class=muted>empty</td></tr>'}</table>
        <form method="post" action="{url_for('udp_ignore_add')}">{_csrf_field()}
          <div style="display:flex;gap:8px;max-width:640px">
            <input type="number" name="port" placeholder="port (0=any)" required style="width:140px">
            <input type="text" name="process" placeholder="process (optional)">
            <input type="text" name="notes" placeholder="notes">
            <button type="submit">Add ignore</button></div></form>"""

        fix_rows = "".join(
            f"<tr><td>{_esc(r.finding_type)}</td><td>{_esc(r.action)}</td>"
            f"<td>{'auto' if r.auto else 'manual'}</td>"
            f"<td class=muted>{_esc(r.notes)}</td></tr>"
            for r in defs.fixes.values())
        fixes_html = f"""
        <h2>Fixes policy (fixes.csv)</h2>
        <table><tr><th>finding type</th><th>action</th><th>mode</th><th>notes</th></tr>
        {fix_rows or '<tr><td colspan=4 class=muted>empty</td></tr>'}</table>"""

        upload_forms = ""
        for kind, header in CSV_HEADERS.items():
            upload_forms += f"""
            <h3>{_esc(kind)} <span class="muted">({', '.join(header)})</span></h3>
            <form method="post" action="{url_for('defs_upload', kind=kind)}">{_csrf_field()}
              <textarea name="csv_text" rows="4"
                placeholder="paste full CSV including header"></textarea>
              <p><button type="submit">Replace {kind} CSV</button></p></form>"""
        upload_html = f"<h2>Update definitions</h2>{upload_forms}"

        return _page("Definitions", cards + udp_html + fixes_html + upload_html,
                     flash=request.args.get("flash", ""))

    @app.route("/definitions/reload", methods=["POST"])
    @require_auth
    def defs_reload():
        defs.reload()
        state.append_event("defs_reload", {"version": defs.version()})
        return redirect(url_for("definitions_page",
                                flash=f"Definitions reloaded (v{defs.version()})"))

    @app.route("/definitions/udp-ignore", methods=["POST"])
    @require_auth
    def udp_ignore_add():
        try:
            port = int(request.form.get("port", "0"))
        except ValueError:
            port = -1
        if not (0 <= port <= 65535):
            return redirect(url_for("definitions_page", flash="Bad port"))
        defs.add_udp_ignore(port, request.form.get("process", ""),
                            request.form.get("notes", ""))
        state.append_event("udp_ignore_added", {"port": port})
        return redirect(url_for("definitions_page",
                                flash=f"UDP ignore added for port {port}"))

    @app.route("/definitions/upload/<kind>", methods=["POST"])
    @require_auth
    def defs_upload(kind):
        text = request.form.get("csv_text", "")
        ok, msg = defs.update_from_csv(kind, text)
        state.append_event("defs_upload", {"kind": kind, "ok": ok})
        return redirect(url_for("definitions_page", flash=msg))

    # ---------------- report page ----------------
    @app.route("/report")
    @require_auth
    def report_page():
        latest = read_json(state.dir / "reports" / "latest.json", {})
        try:
            text = (state.dir / "reports" / "latest.txt").read_text(
                encoding="utf-8")
        except OSError:
            text = "No report yet — generate one."
        body = f"""
        <form class="inline" method="post" action="{url_for('report_generate')}">
          {_csrf_field()}<button>Generate now</button></form>
        <pre>{_esc(text)}</pre>"""
        return _page("Report", body, flash=request.args.get("flash", ""))

    @app.route("/report/generate", methods=["POST"])
    @require_auth
    def report_generate():
        if agent is None:
            return redirect(url_for("report_page",
                                    flash="Agent not attached to portal"))
        agent.daily_report()
        return redirect(url_for("report_page", flash="Report generated"))

    # ---------------- JSON API ----------------
    @app.route("/api/status")
    @require_auth
    def api_status():
        return jsonify({
            "last_run": state.last_run(),
            "active_response": cfg.active_response,
            "definitions": defs.summary(),
            "open_findings": sum(1 for f in state.load_findings()
                                 if f.get("status") == "open"),
        })

    @app.route("/api/findings")
    @require_auth
    def api_findings():
        return jsonify(state.load_findings()[:100])

    @app.route("/api/report/latest")
    @require_auth
    def api_report():
        return jsonify(read_json(state.dir / "reports" / "latest.json", {}))

    return app
