"""Portal: auth, CSRF, dashboard, definitions updates, response buttons."""

from __future__ import annotations

import pytest

from portal import create_app
from responder import Responder


@pytest.fixture()
def client(cfg, state, defs):
    responder = Responder(cfg, state)
    app = create_app(cfg, state, defs, responder, agent=None)
    app.config["TESTING"] = True
    return app.test_client(), state


def _login(client, state):
    token = state.get_portal_token()
    resp = client.post("/login", data={"token": token},
                       follow_redirects=False)
    assert resp.status_code == 302


def _csrf(client):
    with client.session_transaction() as sess:
        return sess["csrf"]


def test_auth_required_redirects(client):
    c, _ = client
    assert c.get("/").status_code == 302
    assert "/login" in c.get("/").headers["Location"]
    assert c.get("/api/status").status_code == 401


def test_wrong_token_rejected(client):
    c, state = client
    resp = c.post("/login", data={"token": "wrong"})
    assert b"Invalid token" in resp.data


def test_dashboard_after_login(client):
    c, state = client
    _login(c, state)
    resp = c.get("/")
    assert resp.status_code == 200
    assert b"Intruder watch" in resp.data
    assert b"Findings" in resp.data
    assert b"Listeners" in resp.data


def test_api_status_json(client):
    c, state = client
    _login(c, state)
    data = c.get("/api/status").get_json()
    assert "definitions" in data and "active_response" in data
    assert data["active_response"] is False


def test_csrf_required_on_post(client):
    c, state = client
    _login(c, state)
    resp = c.post("/definitions/reload")          # no csrf field
    assert resp.status_code == 403


def test_udp_ignore_add_via_portal(client, defs):
    c, state = client
    _login(c, state)
    resp = c.post("/definitions/udp-ignore",
                  data={"csrf": _csrf(c), "port": "7777",
                        "process": "chatty", "notes": "test"},
                  follow_redirects=False)
    assert resp.status_code == 302
    assert defs.is_ignored_udp(7777, "chatty")


def test_upload_definitions_bad_header_rejected(client, defs):
    c, state = client
    _login(c, state)
    resp = c.post("/definitions/upload/ports",
                  data={"csrf": _csrf(c), "csv_text": "bad,header\n1,2\n"},
                  follow_redirects=True)
    assert b"bad header" in resp.data


def test_upload_definitions_success(client, defs):
    c, state = client
    _login(c, state)
    csv_text = ("proto,port,process,disposition,notes\n"
                "tcp,12345,demo,alert,test row\n")
    resp = c.post("/definitions/upload/ports",
                  data={"csrf": _csrf(c), "csv_text": csv_text},
                  follow_redirects=True)
    assert b"ports definitions updated" in resp.data
    assert defs.port_disposition("tcp", 12345, "demo") == "alert"


def test_ack_finding(client, state):
    c, _ = client
    _login(c, state)
    state.save_findings([{"id": "f1", "ts": "2026-07-18T00:00:00+00:00",
                          "type": "new_listener", "severity": "medium",
                          "summary": "demo", "details": {}, "status": "open"}])
    resp = c.post("/findings/f1/ack", data={"csrf": _csrf(c)})
    assert resp.status_code == 302
    assert state.load_findings()[0]["status"] == "ack"


def test_manual_block_ip_dry_run_when_inactive(client, state):
    c, _ = client
    _login(c, state)
    resp = c.post("/respond/block",
                  data={"csrf": _csrf(c), "ip": "203.0.113.7"},
                  follow_redirects=True)
    assert b"dry_run" in resp.data or b"dry-run" in resp.data
    actions = state.read_actions()
    assert actions[0]["action"] == "block_ip"
    assert actions[0]["result"] == "dry_run"


def test_kill_refusal_surfaced(client, state):
    c, _ = client
    _login(c, state)
    resp = c.post("/respond/kill",
                  data={"csrf": _csrf(c), "pid": "4"},
                  follow_redirects=True)
    assert b"refused" in resp.data


def test_report_page_and_generate_without_agent(client):
    c, state = client
    _login(c, state)
    assert c.get("/report").status_code == 200
    resp = c.post("/report/generate", data={"csrf": _csrf(c)},
                  follow_redirects=True)
    assert b"Agent not attached" in resp.data
