"""Subscription templates, ping-type, fingerprint and reserves (tech.md §10.5, §10.9, K7)."""

from helpers import S4_KEYS, login_keys, make_app, on, seen
from hypothesis import given
from hypothesis import strategies as st

from kerberos.checks.rules import probe_interval, ru_direct
from kerberos.copy import t
from kerberos.demo.fleet import build_nodes, build_panel
from kerberos.fixes import subscription
from kerberos.fixes.journal import RunStore
from kerberos.fixes.profile import remaining
from kerberos.flow import EXIT_OK

TO_PLAN = login_keys() + ["enter"] + S4_KEYS + ["enter", "enter"]  # S3, S4, admin key
TO_PLAN += ["enter", "enter", "enter"]  # S4 summary, whois, S6 → S7
APPLY = ["enter", "enter", "enter"]
ROLLBACK = ["enter", "enter", "enter", "x"]  # the panel: the token saved by the fix run
NL1, NL2 = "nl-1", "nl-2"  # rows of the block «Свой домен» of S7 (K23)


def run_fix(extra, panel=None, nodes=None, state=None):
    panel = panel or build_panel()
    nodes = nodes or {n.name: n for n in build_nodes()}
    app, term = make_app(TO_PLAN + list(extra), panel=panel, nodes=list(nodes.values()),
                         height=46, state=state)  # fmt: skip
    return app, term, app.run("fix"), panel, nodes


def templates_by_name(panel):
    return {tpl["name"]: tpl for tpl in panel.templates}


def test_kerberos_templates_are_filled():
    domains = ["nl-1.example.com", "de-1.example.com", "shop.example.net"]
    for kind in ("reserve", "single"):
        built = subscription.build(kind, domains)
        assert remaining(built) == []
        assert all(ru_direct(built).values())
    reserve = subscription.build("reserve", domains)
    assert probe_interval(reserve) == 60
    local = next(s for s in reserve["dns"]["servers"] if isinstance(s, dict)
                 and s.get("address") == "localhost")  # fmt: skip
    assert local["domains"] == ["domain:example.com", "domain:example.net"]
    assert "balancers" not in subscription.build("single", domains)["routing"]


@given(st.lists(st.from_regex(r"[a-z]{1,8}(\.[a-z]{1,8}){1,3}", fullmatch=True), max_size=6))
def test_own_domains_are_zones(domains):
    zones = subscription.own_domains(domains)
    assert zones == sorted(set(zones))
    assert all(z.startswith("domain:") and z.count(".") == 1 for z in zones)
    assert remaining(subscription.build("reserve", domains)) == []


def test_ping_type_is_added_and_nothing_else_changes():
    app, term, code, panel, _nodes = run_fix(APPLY)
    assert code == EXIT_OK
    assert panel.sub_settings["customResponseHeaders"] == {
        "profile-update-interval": "12",
        "ping-type": "proxy-head",
    }
    app.env.terminal.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_OK
    assert panel.sub_settings["customResponseHeaders"] == {"profile-update-interval": "12"}


def test_hosts_move_to_kerberos_templates_and_back():
    app, term, code, panel, _nodes = run_fix(APPLY)
    by_name = templates_by_name(panel)
    user = by_name["Default"]
    assert user["templateJson"]["observatory"]["probeInterval"] == "30s", "theirs stays intact"
    assert {subscription.RESERVE_NAME, subscription.SINGLE_NAME} <= set(by_name)
    moved = {h["remark"]: h["xrayJsonTemplateUuid"] for h in panel.hosts
             if h["remark"] in ("NL Reality", "DE Reality")}  # fmt: skip
    # NL-1 has a hidden reserve on NL-2: «KERBEROS»; DE-1 has none: «KERBEROS single».
    assert moved["NL Reality"] == by_name[subscription.RESERVE_NAME]["uuid"]
    assert moved["DE Reality"] == by_name[subscription.SINGLE_NAME]["uuid"]
    app.env.terminal.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_OK
    back = {h["remark"]: h["xrayJsonTemplateUuid"] for h in panel.hosts
            if h["remark"] in ("NL Reality", "DE Reality")}  # fmt: skip
    assert back == {"NL Reality": user["uuid"], "DE Reality": user["uuid"]}


def test_templates_are_made_once_and_hand_edits_are_asked_about():
    app, _term, _code, panel, nodes = run_fix(APPLY)
    count = len(panel.templates)
    tpl = templates_by_name(panel)[subscription.SINGLE_NAME]
    tpl["templateJson"]["log"] = {"loglevel": "debug"}  # edited by hand in the panel
    for host in panel.hosts:  # the findings come back so the template is needed again
        host["xrayJsonTemplateUuid"] = templates_by_name(panel)["Default"]["uuid"]
    keys = ["esc", "esc"]  # leave the diff, keep the hand edits
    app2, term2, code, _p, _n = run_fix(APPLY[:2] + keys + APPLY[2:], panel=panel, nodes=nodes)
    assert len(panel.templates) == count
    assert seen(term2, t("tpl.diff.question"))
    assert tpl["templateJson"]["log"] == {"loglevel": "debug"}


def test_fingerprint_of_one_host():
    keys = on("host", "host.fingerprint", "space") + APPLY
    app, term, code, panel, _nodes = run_fix(keys)
    host = next(h for h in panel.hosts if h["remark"] == "NL Reality")
    assert host["fingerprint"] == "firefox"
    app.env.terminal.feed(*ROLLBACK)
    app.run("rollback")
    assert next(h for h in panel.hosts if h["remark"] == "NL Reality")["fingerprint"] == ""


def reserve_keys():
    keys = on(NL1, "self_steal", "d", *"nl-1.example.com", "enter")
    keys += ["r", "down", "enter"]  # the reserve of nl-1 is nl-2
    keys += on(NL2, "self_steal", "d", *"nl-2.example.com", "enter")
    return keys


def test_main_and_reserve_share_tags_and_the_reserve_is_hidden():
    app, term, code, panel, _nodes = run_fix(reserve_keys() + APPLY)
    assert code == EXIT_OK
    assert seen(term, t("plan.reserve", node="nl-1"))
    run = RunStore(app.env.state, app.env.clock).runs()[0]
    copies = {}
    for change in run["changes"]:
        if change["fixId"] == "self_steal.hosts":
            name = app.env.state.nodes()[change["params"]["node"]].name
            copies[name] = change["details"]["created"]
    hosts = {h["uuid"]: h for h in panel.hosts}
    reserve_tpl = templates_by_name(panel)[subscription.RESERVE_NAME]["uuid"]
    main = [hosts[u] for u in copies["nl-1"]]
    spare = [hosts[u] for u in copies["nl-2"]]
    assert {tag for h in main for tag in h["tags"]} == {"KRB_NL_1_VLESS", "KRB_NL_1_HY2"}
    assert {tag for h in spare for tag in h["tags"]} == {"KRB_NL_1_VLESS", "KRB_NL_1_HY2"}
    assert all(not h["isHidden"] for h in main) and all(h["isHidden"] for h in spare)
    assert all(h["xrayJsonTemplateUuid"] == reserve_tpl for h in main + spare)
    app.env.terminal.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_OK
    assert not any(u in {h["uuid"] for h in panel.hosts} for u in copies["nl-1"])


def test_without_reserve_the_copies_get_the_single_template():
    keys = on(NL1, "self_steal", "d", *"nl-1.example.com", "enter")
    app, _term, code, panel, _nodes = run_fix(keys + APPLY)
    run = RunStore(app.env.state, app.env.clock).runs()[0]
    created = next(c for c in run["changes"] if c["fixId"] == "self_steal.hosts")
    single = templates_by_name(panel)[subscription.SINGLE_NAME]["uuid"]
    hosts = {h["uuid"]: h for h in panel.hosts}
    assert all(hosts[u]["xrayJsonTemplateUuid"] == single for u in created["details"]["created"])
    assert all(hosts[u]["tags"] == ["NL1"] or hosts[u]["tags"] == []
               for u in created["details"]["created"])  # fmt: skip
