"""KERBEROS on a 3x-ui server, end to end (tech.md §7.6, K11)."""

import json
from datetime import timedelta

import pytest
from helpers import make_app, seen, typed

from kerberos.copy import t
from kerberos.demo.xui import XUI_DOMAIN, XUI_IP
from kerberos.fixes.journal import RunStore
from kerberos.flow import EXIT_OK, EXIT_PARTIAL
from kerberos.panel.client import PanelClient
from kerberos.panel.errors import PanelError
from kerberos.panel.xui import XuiClient
from kerberos.panel.xui_fake import FakeXui, raw_inbound

CHOOSE = ["down", "enter"]  # S2: 3x-ui is the second panel of the demo server
LOGIN = typed("admin") + ["enter"] + typed("pw") + ["enter"]
TO_REPORT = CHOOSE + LOGIN + ["enter", "enter"]  # S2 summary, S4 summary (S3 is skipped)
TO_PLAN = TO_REPORT + ["enter"]
# «Проверка»: S4 first says what it installs on this server.
CHECK_REPORT = CHOOSE + LOGIN + ["enter", "enter", "enter"]
# S7 rows of the demo server (K23), groups folded: the access to the server, the new SSH
# port, the holes for scanners, the panel, watch; then its own domain, the last row.
TO_PORT, TO_STEAL = ["home", "down"], ["end"]
APPLY = ["enter", "enter"]
ROLLBACK = ["enter", "enter", "enter"] + LOGIN + ["x"]


def xui_app(keys, height=44, state=None):
    app, term = make_app(keys, panel_kind=None, height=height, state=state)
    return app, term


def last_run(app):
    return RunStore(app.env.state, app.env.clock).runs()[0]


def reality(app):
    return app.env.xui_transport.stream(1)["realitySettings"]


def local_node(app):
    return app.env.transport.nodes["127.0.0.1"]


def steal(domain=XUI_DOMAIN):
    return TO_STEAL + ["d"] + list(domain) + ["enter"]


def test_choice_of_panel_then_check():
    app, term = xui_app(CHECK_REPORT + ["enter"])
    assert app.run("check") == EXIT_OK
    assert seen(term, t("panel.choose")) and seen(term, t("panel.kind.3x-ui"))
    run = last_run(app)
    assert run["panel"]["kind"] == "3x-ui" and run["panel"]["api"] == ""
    failing = {f["checkId"] for f in run["findings"] if not f["ok"]}
    assert {"reality.foreign_sni", "ssh.password", "kernel.mptcp", "ports.public",
            "xui.panel_exposed"} <= failing  # fmt: skip
    assert not failing & {"profile.template", "reserve.missing", "panel_server.ssh"}
    ports = next(f for f in run["findings"] if f["checkId"] == "ports.public")
    assert ports["evidence"]["ports"] == ["3306/tcp"], "panel, subscription and inbounds stay"
    assert app.env.xui_transport.mutations == [], "«Проверка» changes nothing"
    assert not any(cmd.startswith("apply") for _a, cmd in app.env.transport.log)


def test_local_access_needs_no_password_and_is_restricted():
    app, term = xui_app(CHECK_REPORT + ["enter"])
    app.run("check")
    node = local_node(app)
    line = next(k for k in node.authorized_keys if "kerberos" in k or "command=" in k)
    assert line.startswith('from="127.0.0.1",command="/usr/local/sbin/kerberos-agent",restrict')
    record = app.env.state.node("local")
    assert record.ssh_address == "127.0.0.1" and record.address == XUI_IP
    assert app.env.state.pinned("127.0.0.1", 22) == node.host_key.blob
    assert ("127.0.0.1", "open_root") not in app.env.transport.log, "no password, no ssh -tt"
    assert not seen(term, t("access.hostkey", node="panel", fingerprint="")[:12])


def test_fix_moves_reality_to_the_own_domain():
    app, term = xui_app(TO_PLAN + steal() + APPLY + ["enter"])
    assert app.run("fix") == EXIT_OK
    after = reality(app)
    assert after["target"] == "127.0.0.1:8445"
    assert after["serverNames"] == [XUI_DOMAIN, "www.example.net"]
    assert after["privateKey"] == "DEMO_KEY_XUI" and after["shortIds"] == ["", "a1b2c3d4"]
    clients = app.env.xui_transport.inbound(1)["settings"]["clients"]
    assert [c["email"] for c in clients] == ["demo-user-1", "demo-user-2", "demo-user-3"]
    facts = local_node(app).state["facts"]
    assert facts["ssh"]["passwordAuthentication"] is False and facts["mptcp"]["enabled"] is False
    run = last_run(app)
    pending = run["pending"][0]
    assert pending["panel"] == "3x-ui" and pending["inbounds"] == ["1"]
    assert "DEMO_KEY_XUI" not in json.dumps(run), "the Reality key stays out of run.json"
    assert run["scoreAfter"] > run["scoreBefore"]
    assert seen(term, t("plan.finalize.xui")[:40])


def test_fix_rollback_returns_reality_and_ssh():
    app, _term = xui_app(TO_PLAN + steal() + APPLY + ["enter"])
    app.run("fix")
    before_names = ["www.example.net"]
    app.env.terminal.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_OK
    back = reality(app)
    assert back["target"] == "www.example.net:443" and back["serverNames"] == before_names
    assert local_node(app).state["facts"]["ssh"]["passwordAuthentication"] is True


def test_finalize_leaves_only_the_domain():
    app, _term = xui_app(TO_PLAN + steal() + APPLY + ["enter"])
    app.run("fix")
    app.env.clock.advance(timedelta(hours=25).total_seconds())
    app.env.terminal.feed(*LOGIN, "enter", "x")
    assert app.run("finalize") == EXIT_OK
    assert reality(app)["serverNames"] == [XUI_DOMAIN]
    assert last_run(app)["pending"] == []


@pytest.mark.parametrize("answer, code", [("enter", EXIT_OK), ("esc", EXIT_PARTIAL)])
def test_new_ssh_port_is_tried_from_outside(answer, code):
    keys = TO_PLAN + TO_PORT + ["space"] + APPLY + [answer, "enter"]
    app, term = xui_app(keys)
    assert app.run("fix") == code
    change = next(c for c in last_run(app)["changes"] if c["fixId"] == "ssh.port")
    port = change["details"]["newPort"]
    assert seen(term, t("apply.outside", port=port, command=f"ssh -p {port} root@{XUI_IP}"))
    ssh = local_node(app).state["facts"]["ssh"]
    if answer == "enter":
        assert change["state"] == "confirmed" and ssh["ports"] == [port]
        assert app.env.state.node("local").ssh_port == port
    else:
        assert change["state"] == "rolled_back" and change["error"] == "port_closed"
        assert ssh["ports"] == [22]


def test_panel_error_while_writing_reality_undoes_it():
    app, _term = xui_app(TO_PLAN + steal() + APPLY + ["enter"])
    app.env.xui_transport.fail("POST", "panel/api/inbounds/update/1", 500)
    assert app.run("fix") == EXIT_PARTIAL
    assert reality(app)["target"] == "www.example.net:443"
    steal_changes = [c for c in last_run(app)["changes"]
                     if c["fixId"] in ("self_steal.site", "xui.reality")]  # fmt: skip
    assert {c["state"] for c in steal_changes} <= {"rolled_back", "failed"}
    assert local_node(app).state["site"] is None


# -- the client against the contract of 3x-ui -----------------------------------------
class Clock:
    def sleep(self, _seconds):
        pass


def client_for(panel, domain=None):
    return XuiClient("http://127.0.0.1:2053" + panel.base, panel, Clock(), domain)


def test_csrf_and_session_of_v3():
    panel = FakeXui(base="/secret/")
    stream = {"security": "reality", "realitySettings": {"target": "a:443"}}
    panel.inbounds = [raw_inbound(1, 443, "vless", stream)]
    client = client_for(panel)
    with pytest.raises(PanelError) as err:
        client.inbounds()
    assert err.value.code == "unauthorized"
    with pytest.raises(PanelError) as err:
        client.login("admin", "wrong")
    assert err.value.code == "unauthorized"
    client.login("admin", "admin-password")
    assert [i["id"] for i in client.inbounds()] == [1]
    moved = {"security": "reality", "realitySettings": {"target": "b:443"}}
    after = client.update_inbound(1, moved)
    assert after["streamSettings"]["realitySettings"]["target"] == "b:443"


def test_v2_panel_without_csrf_and_string_fields():
    panel = FakeXui(version=2)
    panel.inbounds = [raw_inbound(1, 443, "vless", {"security": "none"})]
    client = client_for(panel)
    client.login("admin", "admin-password")
    assert client.csrf is None and client.inbounds()[0]["streamSettings"] == {"security": "none"}


def test_domain_of_the_panel_goes_to_host():
    panel = FakeXui(domain="panel.example.com")
    with pytest.raises(PanelError) as err:
        client_for(panel).login("admin", "admin-password")
    assert err.value.code == "forbidden"
    client_for(panel, "panel.example.com").login("admin", "admin-password")


def test_inbounds_of_other_nodes_are_left_alone():
    panel = FakeXui()
    remote = raw_inbound(2, 443, "vless", {"security": "none"})
    remote["nodeId"] = 7
    panel.inbounds = [raw_inbound(1, 443, "vless", {"security": "none"}), remote]
    client = client_for(panel)
    client.login("admin", "admin-password")
    assert [i["id"] for i in client.inbounds()] == [1]


def test_two_factor_code():
    panel = FakeXui(two_factor="123456")
    client = client_for(panel)
    with pytest.raises(PanelError):
        client.login("admin", "admin-password")
    client.login("admin", "admin-password", "123456")


def test_remnawave_client_still_has_its_own_transport():
    assert PanelClient is not XuiClient
