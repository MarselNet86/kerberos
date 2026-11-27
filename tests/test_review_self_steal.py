"""Review K13, self-steal, reserves and panel rollback: each test replays a review scenario."""

import json
from types import SimpleNamespace

from helpers import make_app, on, seen, typed
from test_review_logic import (
    APPLY,
    DONE,
    NL1,
    NL2,
    ROLLBACK,
    Hooked,
    changes_of,
    domain_keys,
    fix,
    fix_run,
    fleet,
    profile_of,
    raw_node,
)

from kerberos.clock import FakeClock
from kerberos.copy import t
from kerberos.demo.fleet import build_panel
from kerberos.demo.fleet import reality as reality_inbound
from kerberos.demo.xui import XUI_DOMAIN, reality_stream
from kerberos.fixes import xhttp
from kerberos.fixes.panel_changes import digest, undo
from kerberos.fixes.panel_fixes import PanelFixes
from kerberos.fixes.plan import PlanItem
from kerberos.flow import EXIT_OK, EXIT_PARTIAL, EXIT_ROLLBACK_FAILED
from kerberos.panel.client import PanelClient
from kerberos.panel.fake import FakePanel, raw_host
from kerberos.panel.xui_fake import raw_inbound

X_TO_REPORT = ["down", "enter"] + typed("admin") + ["enter"] + typed("pw") + ["enter"]
X_TO_REPORT += ["enter"]  # S4 summary: S2 does not stop (K25)
X_TO_PLAN = X_TO_REPORT + ["enter"]
X_STEAL = ["end", "d"] + list(XUI_DOMAIN) + ["enter"]  # its own domain: the last row of S7


def add_inbound(panel, name, inbound):
    profile = profile_of(panel, name)
    profile["config"]["inbounds"].append(inbound)
    FakePanel._sync_inbounds(profile)
    raw_node(panel, name)["configProfile"]["activeInbounds"] = [
        {"uuid": i["uuid"], "tag": i["tag"]} for i in profile["inbounds"]
    ]
    return profile


def logged_in(panel):
    client = PanelClient("http://127.0.0.1:3000/api", panel, FakeClock())
    client.set_token(panel.add_api_token())
    return client


def reserve_keys():
    keys = domain_keys(NL1, "nl-1.example.com") + ["r", "down", "enter"]  # nl-1 → nl-2
    return keys + domain_keys(NL2, "nl-2.example.com")


# -- app 2, app 12: a reserve pair links only two nodes that both moved to their domains -----
def test_reserve_is_refused_when_one_side_of_the_pair_failed():
    panel, nodes = fleet()
    nodes["nl-1"].state["certbot_fails"] = True  # the main's self-steal is undone
    app, _term, code = fix(reserve_keys() + APPLY + DONE, panel, nodes)
    assert code == EXIT_PARTIAL
    run = fix_run(app)
    reserve = changes_of(run, "reserve")[0]
    assert (reserve["state"], reserve["error"]) == ("failed", "pair_not_ready")
    copies = changes_of(run, "self_steal.hosts", raw_node(panel, "nl-2")["uuid"])[0]
    hosts = {h["uuid"]: h for h in panel.hosts}
    visible = [
        hosts[u] for u in copies["details"]["created"] if hosts[u]["remark"] == "NL-2 Reality"
    ]
    assert visible and visible[0]["isHidden"] is False, "nl-2 stays in the subscriptions"


def test_a_reserve_cannot_get_its_own_reserve():
    panel, nodes = fleet()
    keys = domain_keys(NL1, "nl-1.example.com") + ["r", "down", "enter"]  # nl-1 → nl-2
    keys += on(NL2, "self_steal", "r", "x")  # r on nl-2: a notice, no menu
    app, term, _code = fix(keys + ["esc", "q", "enter"], panel, nodes)  # S7 → S6 → quit
    assert seen(term, t("plan.reserve.is_reserve", node="nl-2", main="nl-1"))
    pairs = [i for i in app.session.data["plan"] if i.fix_id == "reserve"]
    assert [(i.node_uuid, i.params["reserve"]) for i in pairs] == [
        (raw_node(panel, "nl-1")["uuid"], raw_node(panel, "nl-2")["uuid"])
    ]


def test_reserve_guard_refuses_a_chain_and_a_pair_without_copies():
    a_b = PlanItem("reserve", "node:a", "a", {"reserve": "b"}, selected=True)
    b_c = PlanItem("reserve", "node:b", "b", {"reserve": "c"}, selected=True)
    copies = [
        {"fixId": "self_steal.hosts", "state": "applied", "error": None, "params": {"node": n},
         "details": {"created": [f"{n}-copy"]}}
        for n in "abc"
    ]  # fmt: skip
    engine = SimpleNamespace(env=None, session=SimpleNamespace(panel=None), queue=[a_b, b_c],
                             run={"changes": copies})  # fmt: skip
    fixes = PanelFixes(engine)
    assert fixes.pair_problem(a_b) == fixes.pair_problem(b_c) == "reserve_chain"
    engine.queue = [a_b]
    assert fixes.pair_problem(a_b) is None
    copies[1]["error"] = "rollback_failed"  # b's copies failed and stayed: not a pair
    assert fixes.pair_problem(a_b) == "pair_not_ready"


# -- app 3: only hosts of the inbounds the template replaced get the new SNI ------------------
def test_self_steal_leaves_hosts_of_other_inbounds_alone():
    panel, nodes = fleet()
    ws = {"tag": "VLESS-WS-NL1", "port": 8443, "listen": "0.0.0.0", "protocol": "vless",
          "settings": {"clients": [], "decryption": "none"},
          "streamSettings": {"network": "ws", "security": "tls",
                             "tlsSettings": {"serverName": "ws.example.com"},
                             "wsSettings": {"path": "/ws"}}}  # fmt: skip
    profile = add_inbound(panel, "nl-1", ws)
    panel.hosts.append(raw_host("tags", profile, "VLESS-WS-NL1", "NL WS", "ws.example.com",
                                sni="ws.example.com", port=8443, fingerprint="chrome"))  # fmt: skip
    app, _term, code = fix(domain_keys(NL1, "nl-1.example.com") + APPLY + DONE, panel, nodes)
    assert code == EXIT_OK
    inbound = next(i["uuid"] for i in profile["inbounds"] if i["tag"] == "VLESS-WS-NL1")
    hosts = [h for h in panel.hosts if h["inbound"]["configProfileInboundUuid"] == inbound]
    assert [(h["sni"], h["isDisabled"]) for h in hosts] == [("ws.example.com", False)]


# -- app 7: the check after self-steal judges only the inbounds it changed --------------------
def test_second_reality_inbound_does_not_undo_self_steal():
    panel, nodes = fleet()
    second = reality_inbound("VLESS-REALITY-NL1-B", "www.example.net:443", ["www.example.net"],
                             "DEMO_KEY_NL1B")  # fmt: skip
    second["port"] = 8443
    add_inbound(panel, "nl-1", second)
    app, _term, code = fix(domain_keys(NL1, "nl-1.example.com") + APPLY + DONE, panel, nodes)
    assert code == EXIT_OK
    steps = [c for c in fix_run(app)["changes"] if c["fixId"].startswith("self_steal.")]
    assert steps and {c["state"] for c in steps} == {"applied"}


def test_disabled_3xui_reality_is_no_finding_and_does_not_undo_self_steal():
    app, _term = make_app(X_TO_PLAN + X_STEAL + APPLY + DONE, panel_kind=None, height=44)
    old = reality_stream()
    old["realitySettings"].update(serverNames=["old.example.net"], target="old.example.net:443")
    app.env.xui_transport.inbounds.append(
        raw_inbound(3, 8443, "vless", old, remark="old reality", enable=False)
    )
    assert app.run("fix") == EXIT_OK
    run = fix_run(app)
    assert not [f for f in run["findings"] if f["checkId"] == "reality.foreign_sni"
                and f["evidence"]["inbound"] == "inbound-8443"]  # fmt: skip
    assert changes_of(run, "xui.reality")[0]["state"] == "applied"


# -- app 10: the findings after «Исправление» do not keep what an undone check saw ------------
def test_findings_after_an_undone_self_steal_forget_its_probes():
    base, nodes = fleet()
    nl1 = profile_of(base, "nl-1")["uuid"]

    def hook(method, path, n, body):
        if (method, path) == ("PATCH", "/config-profiles") and body["uuid"] == nl1:
            raw_node(base, "nl-1")["isConnected"] = False  # TLS answers, the node is gone
        return None

    app, _term, code = fix(domain_keys(NL1, "nl-1.example.com") + APPLY + DONE,
                           Hooked(base, hook), nodes)  # fmt: skip
    assert code == EXIT_PARTIAL
    target = f"node:{raw_node(base, 'nl-1')['uuid']}"
    after = [f for f in fix_run(app)["findingsAfter"]
             if f["checkId"] == "probe.no_sni" and f["target"] == target]  # fmt: skip
    assert after and after[0]["ok"] is False


def test_score_after_on_3xui_reads_the_panel_again():
    from kerberos.screens.fix import refresh_snapshot

    # «Проверка» first says what S4 installs (one more Enter), then S4 summary and S6.
    app, _term = make_app(X_TO_REPORT[:-1] + ["enter", "enter", "enter"], panel_kind=None,
                          height=44)  # fmt: skip
    assert app.run("check") == EXIT_OK
    xui = app.env.xui_transport
    stream = xui.stream(1)
    stream["realitySettings"]["target"] = "127.0.0.1:8445"
    xui.inbound(1)["streamSettings"] = stream  # the panel changed after the first read
    refresh_snapshot(app, app.session)
    inbound = app.session.snapshot.profiles[0].config["inbounds"][0]
    assert inbound["streamSettings"]["realitySettings"]["target"] == "127.0.0.1:8445"
    assert app.session.data["input"].snapshot is app.session.snapshot


# -- app 8: undo takes back only what KERBEROS wrote, and asks about later edits --------------
def test_squad_rollback_keeps_inbounds_added_later():
    panel, nodes = fleet()
    app, _term, code = fix(domain_keys(NL1, "nl-1.example.com") + APPLY + DONE, panel, nodes)
    assert code == EXIT_OK
    squad = panel.squads[0]
    mine = next(i for i in profile_of(panel, "nl-1")["inbounds"] if i["type"] == "hysteria")
    later = next(i for i in profile_of(panel, "de-1")["inbounds"] if i["type"] == "hysteria")
    squad["inbounds"].append(dict(later))  # the admin adds de-1's Hysteria2 by hand
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_OK
    uuids = [i["uuid"] for i in squad["inbounds"]]
    assert later["uuid"] in uuids and mine["uuid"] not in uuids


def test_rollback_asks_before_overwriting_a_host_template_edited_later():
    panel, nodes = fleet()
    app, _term, code = fix(APPLY + DONE, panel, nodes)
    assert code == EXIT_OK
    templates = {tpl["name"]: tpl["uuid"] for tpl in panel.templates}
    host = next(h for h in panel.hosts if h["remark"] == "DE Reality")
    assert host["xrayJsonTemplateUuid"] == templates["KERBEROS single"]
    host["xrayJsonTemplateUuid"] = templates["KERBEROS"]  # chosen by hand after KERBEROS
    app.env.terminal.feed(*ROLLBACK, "esc", "esc", "x")  # leave the diff, refuse, close
    assert app.run("rollback") == EXIT_ROLLBACK_FAILED
    assert host["xrayJsonTemplateUuid"] == templates["KERBEROS"]
    assert seen(app.env.terminal, t("rb.diff.question"))


def test_reserve_undo_asks_when_a_host_changed_after_kerberos():
    panel = build_panel()
    client = logged_in(panel)
    host = next(h for h in panel.hosts if h["remark"] == "DE Reality")
    template = host["xrayJsonTemplateUuid"]
    before = {"tags": ["DE1"], "isHidden": False, "xrayJsonTemplateUuid": template}
    written = {"tags": ["KRB_DE_1_VLESS"], "isHidden": False, "xrayJsonTemplateUuid": template}
    host["tags"] = ["MANUAL"]  # neither what was there nor what KERBEROS wrote
    details = {"hosts": {host["uuid"]: before}, "written": {host["uuid"]: written}, "tags": {}}
    change = {"fixId": "reserve", "params": {}, "details": details}
    asked = []
    assert undo(client, change, ask=lambda diff: asked.append(diff) or False) == "changed_in_panel"
    assert host["tags"] == ["MANUAL"] and "MANUAL" in asked[0]
    assert undo(client, change, ask=lambda diff: True) is None
    assert host["tags"] == ["DE1"]


def test_template_undo_asks_when_edited_after_kerberos(tmp_path):
    panel = build_panel()
    client = logged_in(panel)
    template = panel.templates[0]
    previous, written = {"dns": {"servers": ["a"]}}, {"dns": {"servers": ["b"]}}
    (tmp_path / "previous.json").write_text(json.dumps(previous))
    (tmp_path / "written.json").write_text(json.dumps(written))
    info = {"created": False, "previousPath": str(tmp_path / "previous.json"),
            "written": digest(written), "writtenPath": str(tmp_path / "written.json")}  # fmt: skip
    change = {"fixId": "sub.templates", "params": {},
              "details": {"templates": {template["uuid"]: info}}}  # fmt: skip
    template["templateJson"] = {"dns": {"servers": ["edited"]}}
    assert undo(client, change, ask=lambda diff: False) == "changed_in_panel"
    assert template["templateJson"] == {"dns": {"servers": ["edited"]}}
    template["templateJson"] = written  # as KERBEROS left it: goes back without a question
    assert undo(client, change) is None and template["templateJson"] == previous


# -- app 9: padding goes from the server and the clients together ----------------------------
def test_padding_rollback_after_an_approved_diff_keeps_both_sides_equal():
    panel, nodes = fleet()
    app, _term, code = fix(APPLY + DONE, panel, nodes)
    assert code == EXIT_OK
    inbound = next(i for i in profile_of(panel, "fi-1")["config"]["inbounds"]
                   if i["tag"] == "XHTTP-FI1")  # fmt: skip
    host = next(h for h in panel.hosts if h["remark"] == "FI CDN")
    # The admin rotated the key on the server and on the client, consistently.
    inbound["streamSettings"]["xhttpSettings"]["extra"]["xPaddingKey"] = "rotated"
    host["xhttpExtraParams"]["xPaddingKey"] = "rotated"
    app.env.terminal.feed(*ROLLBACK, "enter", "enter", "x")  # the diff, «yes», the result
    assert app.run("rollback") == EXIT_OK
    inbound = next(i for i in profile_of(panel, "fi-1")["config"]["inbounds"]
                   if i["tag"] == "XHTTP-FI1")  # fmt: skip
    server = xhttp.padding_of(inbound["streamSettings"]["xhttpSettings"].get("extra"))
    assert server == xhttp.padding_of(host["xhttpExtraParams"]) == {}
