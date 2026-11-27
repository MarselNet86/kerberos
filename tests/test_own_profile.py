"""A node's own profile (tech.md §10.4, K24): «новая нода под ключ».

Found on the owner's fleet: a new node on a shared profile could not get its own domain,
and the owner made its profile, hosts and squads in the panel by hand. Remnawave 2.8.1
and 3.4.11 keep inbound tags unique across the panel, so the node's own profile has new
tags, new hosts and a place in the squads; the Reality key comes along.
"""

import copy
import json

import pytest
from demo_input import demo_snapshot, grant_access
from helpers import S4_KEYS, flat, login_keys, make_app, seen
from hypothesis import given
from hypothesis import strategies as st

from kerberos.app import Env
from kerberos.checks import run_checks
from kerberos.checks.collect import Collector, Progress
from kerberos.clock import FakeClock
from kerberos.copy import t
from kerberos.demo.fleet import attach, build_nodes, build_panel
from kerberos.demo.nodes import auth_methods_of, build_prober
from kerberos.fixes.journal import RunStore
from kerberos.fixes.own_profile import NAME_RE, flag, profile_name
from kerberos.fixes.panel_changes import undo_squads
from kerberos.fixes.plan import build_plan
from kerberos.fixes.profile import unique_tag
from kerberos.flow import EXIT_OK, EXIT_PARTIAL, EXIT_ROLLBACK_FAILED
from kerberos.mask import Masker
from kerberos.panel.fake import new_uuid
from kerberos.screens.fix import plan_rows as layout

TO_PLAN = login_keys() + ["enter"] + S4_KEYS + ["enter", "enter"]  # S3, S4, admin key
TO_PLAN += ["enter", "enter", "enter"]  # S4 summary, whois, S6 → S7
APPLY = ["enter", "enter", "enter"]  # S7 → consent → accept → S9 Enter
ROLLBACK = ["enter", "enter", "enter"] + list("admin") + ["enter"] + list("pw") + ["enter", "x"]


# -- the fleets ------------------------------------------------------------------------------
def node_of(panel, name):
    return next(n for n in panel.nodes if n["name"] == name)


def profile_of(panel, name):
    ref = node_of(panel, name)["configProfile"]["activeConfigProfileUuid"]
    return next((p for p in panel.profiles if p["uuid"] == ref), None)


def reality_of(profile):
    return next(i for i in profile["config"]["inbounds"] if i["protocol"] == "vless"
                and i["streamSettings"]["security"] == "reality")  # fmt: skip


def move(panel, name, onto, tags=None):
    """`name` runs the profile of `onto` (its `tags`, else all of them); its hosts go onto
    the inbound of the same kind there and its own profile leaves the panel."""
    target = profile_of(panel, onto)
    own = profile_of(panel, name)
    running = [i for i in target["inbounds"] if tags is None or i["tag"] in tags]
    node_of(panel, name)["configProfile"] = {
        "activeConfigProfileUuid": target["uuid"],
        "activeInbounds": [{"uuid": i["uuid"], "tag": i["tag"]} for i in running],
    }
    by_type = {i["type"]: i["uuid"] for i in target["inbounds"]}
    kinds = {i["uuid"]: i["type"] for i in own["inbounds"]}
    for host in panel.hosts:
        ref = host["inbound"]
        if ref["configProfileUuid"] == own["uuid"]:
            host["inbound"] = {"configProfileUuid": target["uuid"],
                               "configProfileInboundUuid": by_type[kinds[ref[
                                   "configProfileInboundUuid"]]]}  # fmt: skip
    gone = {i["uuid"] for i in own["inbounds"]}
    for squad in panel.squads:
        squad["inbounds"] = [i for i in squad["inbounds"] if i["uuid"] not in gone]
    panel.profiles.remove(own)


def shared_fleet():
    """nl-2 runs the profile of nl-1, as a beginner's two nodes on one profile."""
    panel = build_panel()
    move(panel, "nl-2", "nl-1")
    return panel


def state_of(panel):
    """What the self-steal of a node may touch. Other fixes of the run (fi-1's padding, the
    templates of hosts) change profiles and hosts too: those are not compared."""
    shared = profile_of(panel, "nl-1")
    return json.loads(json.dumps({
        "profiles": [(p["uuid"], p["name"]) for p in panel.profiles],
        "shared": shared["config"] if shared else None,
        "nodes": panel.nodes,
        "hosts": [(h["uuid"], h["isDisabled"], h["inbound"]) for h in panel.hosts],
        "squads": panel.squads,
    }))  # fmt: skip


def plan_of(panel, nodes=None):
    """The plan S7 shows for this fleet, built as the flow builds it."""
    env = Env(terminal=None, clock=FakeClock(), masker=Masker(), demo=True)
    attach(env)
    env.panel_transport = copy.deepcopy(panel)
    if nodes is not None:
        from kerberos.nodes.fake import FakeTransport

        env.transport = FakeTransport(copy.deepcopy(list(nodes.values())), env.state)
    env.prober = build_prober(env.panel_transport, list(env.transport.nodes.values()))
    env.prober.auth = auth_methods_of(list(env.transport.nodes.values()))
    grant_access(env)
    _client, snapshot = demo_snapshot(env)
    selected = [n.uuid for n in snapshot.nodes if not n.is_disabled]
    reachable = {n.address for n in env.transport.nodes.values() if n.reachable}
    access = {n.uuid: "ok" if n.address in reachable else "none" for n in snapshot.nodes}
    data = Collector(env, snapshot, selected, access, True, Progress()).run()
    admin = {"mode": "mine", "keys": ["ssh-ed25519 AAAA admin@laptop"]}
    names = {n.node.uuid: n.node.name for n in data.nodes}
    return build_plan(run_checks(data), data, admin, {}), names


def domain_row(panel, name, *keys, nodes=None):
    """The keys to the row of `name` in the block «Свой домен», then `keys` there."""
    items, names = plan_of(panel, nodes)
    upper, domains = layout(items, set())
    rows = upper + domains
    index = next(n for n, r in enumerate(rows) if r.kind == "domain"
                 and names.get(items[r.indexes[0]].node_uuid) == name)  # fmt: skip
    return ["home"] + ["down"] * index + list(keys)


def item_of(app, name):
    names = {n.uuid: n.name for n in app.session.snapshot.nodes}
    return next(i for i in app.session.data["plan"]
                if i.fix_id == "self_steal" and names.get(i.node_uuid) == name)  # fmt: skip


def run_fix(keys, panel, nodes=None, height=46):
    nodes = nodes or {n.name: n for n in build_nodes()}
    app, term = make_app(TO_PLAN + list(keys), panel=panel, nodes=list(nodes.values()),
                         height=height)  # fmt: skip
    return app, term, app.run("fix")


def steal(panel, name, domain, nodes=None, extra=()):
    keys = domain_row(panel, name, "d", *domain, "enter", nodes=nodes) + list(extra) + APPLY
    return run_fix(keys, panel, nodes)


def run_of(app):
    store = RunStore(app.env.state, app.env.clock)
    return store.load(store.runs()[0]["runId"])


# -- the plan ----------------------------------------------------------------------------------
def test_a_node_on_a_shared_profile_is_no_longer_blocked():
    items, names = plan_of(shared_fleet())
    steals = {names[i.node_uuid]: i for i in items if i.fix_id == "self_steal"}
    assert steals["nl-2"].blocked is None and steals["nl-1"].blocked is None
    assert steals["nl-2"].params["ownProfile"] == "KERBEROS NL-2"
    assert steals["nl-1"].params["ownProfile"] == "KERBEROS NL-1"
    assert steals["nl-2"].params["sharedProfile"] == "NL-1"
    items, names = plan_of(build_panel())
    nl1 = next(i for i in items if i.fix_id == "self_steal" and names[i.node_uuid] == "nl-1")
    assert "ownProfile" not in nl1.params, "a profile of its own already"


def test_a_node_running_other_inbounds_on_a_shared_profile_is_blocked():
    panel = build_panel()
    move(panel, "nl-2", "fi-1")  # nl-2 would run fi-1's XHTTP behind the CDN too
    items, names = plan_of(panel)
    nl2 = next(i for i in items if i.fix_id == "self_steal" and names[i.node_uuid] == "nl-2")
    assert nl2.blocked == "shared_other" and nl2.params["otherInbounds"] == ["XHTTP-FI1"]
    _app, term, _code = run_fix(domain_row(panel, "nl-2") + ["esc", "q", "enter"], panel)
    assert seen(term, t("plan.blocked.shared_other", tags="XHTTP-FI1"))


def test_a_node_running_only_the_reality_of_a_shared_profile_may_leave_it():
    panel = build_panel()
    move(panel, "nl-2", "fi-1", tags=["VLESS-REALITY-FI1"])
    items, names = plan_of(panel)
    nl2 = next(i for i in items if i.fix_id == "self_steal" and names[i.node_uuid] == "nl-2")
    assert nl2.blocked is None and nl2.params["ownProfile"] == "KERBEROS NL-2"


# -- the run -------------------------------------------------------------------------------------
def test_the_node_gets_its_own_profile_and_the_shared_one_stays():
    panel = shared_fleet()
    shared = copy.deepcopy(profile_of(panel, "nl-1"))
    nl1 = copy.deepcopy(node_of(panel, "nl-1"))
    old_key = reality_of(shared)["streamSettings"]["realitySettings"]
    before = {h["uuid"]: copy.deepcopy(h) for h in panel.hosts}
    app, term, code = steal(panel, "nl-2", "nl-2.example.com")
    assert code == EXIT_OK
    own = profile_of(panel, "nl-2")
    assert own["name"] == "KERBEROS NL-2" and own["uuid"] != shared["uuid"]
    settings = reality_of(own)["streamSettings"]["realitySettings"]
    assert settings["privateKey"] == old_key["privateKey"]
    assert settings["shortIds"] == old_key["shortIds"]
    assert settings["serverNames"] == ["nl-2.example.com", "www.example.net"]
    assert {i["tag"] for i in own["inbounds"]} == {"VLESS-REALITY-NL-2", "HY2-NL-2"}
    running = node_of(panel, "nl-2")["configProfile"]["activeInbounds"]
    assert {i["uuid"] for i in running} == {i["uuid"] for i in own["inbounds"]}
    # The shared profile and the node left on it are as they were.
    assert profile_of(panel, "nl-1") == shared and node_of(panel, "nl-1") == nl1
    new = {i["uuid"] for i in own["inbounds"]}
    assert new <= {i["uuid"] for i in panel.squads[0]["inbounds"]}
    created = [h for h in panel.hosts if h["uuid"] not in before]
    assert {h["inbound"]["configProfileUuid"] for h in created} == {own["uuid"]}
    assert {h["address"] for h in created} == {"203.0.113.11"}, "nl-2's hosts only"
    for uuid, old in before.items():
        host = next(h for h in panel.hosts if h["uuid"] == uuid)
        mine = old["address"] == "203.0.113.11" and not old["isDisabled"]
        assert host["isDisabled"] is (True if mine else old["isDisabled"]), old["remark"]
    assert seen(term, t("fix.own_profile.warning", node="nl-2", shared="NL-1",
                        profile="KERBEROS NL-2"))  # fmt: skip
    run = run_of(app)
    assert run["pending"][0]["profileUuid"] == own["uuid"]
    assert "DEMO_KEY" not in json.dumps(run)


def test_the_users_are_in_the_squads_before_the_node_runs_the_new_inbounds():
    panel = shared_fleet()
    _app, _term, code = steal(panel, "nl-2", "nl-2.example.com")
    assert code == EXIT_OK
    calls = [(m, p) for m, p, _b in panel.mutations]
    created = calls.index(("POST", "/config-profiles"))
    squads = calls.index(("PATCH", "/internal-squads"))
    moved = calls.index(("PATCH", "/nodes"))
    hosts = calls.index(("POST", "/hosts"))
    assert created < squads < moved < hosts


def test_a_host_whose_domain_points_at_the_node_is_the_nodes():
    panel = shared_fleet()
    host = next(h for h in panel.hosts if h["remark"] == "NL-2 Reality")
    host["address"] = "nl-2.example.com"  # resolves to nl-2's address in the demo DNS
    _app, _term, code = steal(panel, "nl-2", "nl-2.example.com")
    assert code == EXIT_OK
    assert host["isDisabled"] is True
    own = profile_of(panel, "nl-2")["uuid"]
    copies = [h for h in panel.hosts if h["remark"] == "NL-2 Reality"
              and h["inbound"]["configProfileUuid"] == own]  # fmt: skip
    assert copies and copies[0]["address"] == "nl-2.example.com"
    assert next(h for h in panel.hosts if h["remark"] == "NL Reality")["isDisabled"] is False


def test_a_new_tag_never_repeats_one_of_another_profile():
    panel = shared_fleet()
    # Another profile already holds the tag the template would give (409 in the panel).
    other = profile_of(panel, "kz-1")
    other["config"]["inbounds"][0]["tag"] = "VLESS-REALITY-NL-2"
    other["inbounds"][0]["tag"] = "VLESS-REALITY-NL-2"
    _app, _term, code = steal(panel, "nl-2", "nl-2.example.com")
    assert code == EXIT_OK
    assert {i["tag"] for i in profile_of(panel, "nl-2")["inbounds"]} == {
        "VLESS-REALITY-NL-2-2", "HY2-NL-2"}  # fmt: skip


def test_the_hysteria_tag_of_a_patched_profile_is_unique_too():
    panel = build_panel()
    other = profile_of(panel, "kz-1")
    other["config"]["inbounds"].append({"tag": "HY2-NL-1", "protocol": "hysteria",
                                        "port": 8443, "settings": {}})  # fmt: skip
    other["inbounds"].append({"uuid": new_uuid(), "profileUuid": other["uuid"],
                              "tag": "HY2-NL-1", "type": "hysteria", "port": 8443})  # fmt: skip
    _app, _term, code = steal(panel, "nl-1", "nl-1.example.com")
    assert code == EXIT_OK
    assert "HY2-NL-1-2" in {i["tag"] for i in profile_of(panel, "nl-1")["inbounds"]}


# -- a node without hosts ------------------------------------------------------------------------
def test_a_node_without_hosts_gets_a_reality_and_a_hysteria_host():
    panel = build_panel()
    panel.hosts = [h for h in panel.hosts if h["remark"] != "NL Reality"]
    before = {h["uuid"] for h in panel.hosts}
    _app, _term, code = steal(panel, "nl-1", "nl-1.example.com")
    assert code == EXIT_OK
    created = [h for h in panel.hosts if h["uuid"] not in before]
    remarks = sorted(h["remark"] for h in created)
    assert remarks == ["🇳🇱 nl-1", "🇳🇱 nl-1 Hysteria2"]
    single = next(tpl["uuid"] for tpl in panel.templates if tpl["name"] == "KERBEROS single")
    for host in created:
        assert host["address"] == "203.0.113.10" and host["port"] == 443
        assert host["sni"] == "nl-1.example.com" and host["fingerprint"] == "firefox"
        assert host["xrayJsonTemplateUuid"] == single and not host["isDisabled"]


# -- squads ----------------------------------------------------------------------------------------
def squadless(panel, name):
    """No squad holds the inbounds of `name`: its users would not see it."""
    gone = {i["uuid"] for i in profile_of(panel, name)["inbounds"]}
    for squad in panel.squads:
        squad["inbounds"] = [i for i in squad["inbounds"] if i["uuid"] not in gone]


def test_the_only_squad_of_the_panel_gets_the_node_without_a_question():
    panel = build_panel()
    squadless(panel, "nl-1")
    items, names = plan_of(panel)
    nl1 = next(i for i in items if i.fix_id == "self_steal" and names[i.node_uuid] == "nl-1")
    assert nl1.params["squads"] == [panel.squads[0]["uuid"]]
    _app, _term, code = steal(panel, "nl-1", "nl-1.example.com")
    assert code == EXIT_OK
    profile = profile_of(panel, "nl-1")
    assert {i["uuid"] for i in profile["inbounds"]} <= {i["uuid"] for i in
                                                        panel.squads[0]["inbounds"]}  # fmt: skip


def two_squads(panel):
    panel.squads.append({"uuid": new_uuid(), "name": "Paid", "inbounds": [],
                         "info": {"membersCount": 12, "inboundsCount": 0}})  # fmt: skip
    panel.squads[0]["info"] = {"membersCount": 40, "inboundsCount": 5}
    return panel


def test_with_several_squads_the_row_waits_for_u():
    panel = two_squads(build_panel())
    squadless(panel, "nl-1")
    keys = domain_row(panel, "nl-1", "d", *"nl-1.example.com", "enter", "enter")
    app, term, _code = run_fix(keys + ["esc", "q", "enter"], panel)
    assert seen(term, t("plan.domain.squads"))
    item = item_of(app, "nl-1")
    assert item.params["pickSquads"] and not item.selected
    assert all(m[1] != "/config-profiles" for m in panel.mutations)


def test_u_lists_the_squads_with_their_users_and_marks_those_of_other_nodes():
    panel = two_squads(build_panel())
    squadless(panel, "nl-1")
    keys = domain_row(panel, "nl-1", "d", *"nl-1.example.com", "enter", "u", "enter")
    app, term, code = run_fix(keys + APPLY, panel)
    assert code == EXIT_OK
    assert seen(term, t("plan.squads.title", node="nl-1")) and seen(term, "Paid")
    assert seen(term, "40")
    default, paid = panel.squads
    inbounds = {i["uuid"] for i in profile_of(panel, "nl-1")["inbounds"]}
    assert inbounds <= {i["uuid"] for i in default["inbounds"]}, "marked: other nodes are there"
    assert not paid["inbounds"]


# -- failures and rollback ---------------------------------------------------------------------
@pytest.mark.parametrize(
    ("method", "path", "kind"),
    [
        ("POST", "/config-profiles", 500),
        ("POST", "/config-profiles", "lost"),
        ("PATCH", "/internal-squads", 500),
        ("PATCH", "/nodes", 500),
        ("PATCH", "/nodes", "lost"),
        ("POST", "/hosts", 500),
        ("POST", "/hosts/bulk/disable", 500),
    ],
)
def test_a_failure_at_any_step_leaves_the_panel_as_it_was(method, path, kind):
    panel = shared_fleet()
    before = state_of(panel)
    panel.fail(method, path, kind, times=4)
    _app, _term, code = steal(panel, "nl-2", "nl-2.example.com")
    assert code == EXIT_PARTIAL
    assert state_of(panel) == before


def test_rollback_puts_the_node_back_and_deletes_its_profile():
    panel = shared_fleet()
    before = state_of(panel)
    app, _term, code = steal(panel, "nl-2", "nl-2.example.com")
    assert code == EXIT_OK
    own = profile_of(panel, "nl-2")["uuid"]
    app.env.terminal.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_OK
    assert state_of(panel) == before
    calls = [(m, p) for m, p, _b in panel.mutations]
    moved_back = max(i for i, call in enumerate(calls) if call == ("PATCH", "/nodes"))
    assert moved_back < calls.index(("DELETE", f"/config-profiles/{own}")), (
        "the node goes back before its profile is deleted: deleting would stop it"
    )


@pytest.mark.parametrize("version", ["2.8.1", "3.4.11"])
def test_the_profile_is_deleted_on_both_panels(version):
    from kerberos.panel.client import PanelClient

    panel = build_panel()
    panel.version, panel.major = version, int(version.split(".")[0])
    client = PanelClient("http://127.0.0.1:3000/api", panel, FakeClock())
    client.set_token(panel.add_api_token())
    created = client.create_profile(
        "KERBEROS X", {"inbounds": [{"tag": "X-1", "protocol": "vless", "port": 443}]}
    )
    assert created.name == "KERBEROS X" and [i.tag for i in created.inbounds] == ["X-1"]
    client.delete_profile(created.uuid)
    assert all(p["uuid"] != created.uuid for p in panel.profiles)


def test_a_profile_another_node_moved_onto_stays():
    panel = shared_fleet()
    app, _term, code = steal(panel, "nl-2", "nl-2.example.com")
    assert code == EXIT_OK
    own = profile_of(panel, "nl-2")
    kz1 = node_of(panel, "kz-1")
    kz1["configProfile"] = {"activeConfigProfileUuid": own["uuid"], "activeInbounds": []}
    app.env.terminal.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_ROLLBACK_FAILED
    assert any(p["uuid"] == own["uuid"] for p in panel.profiles), "kz-1 still runs it"
    assert seen(app.env.terminal, t("error.profile_in_use"))
    assert profile_of(panel, "nl-2")["name"] == "NL-1", "nl-2 itself went back"


def test_a_second_run_creates_no_profile():
    panel = shared_fleet()
    nodes = {n.name: n for n in build_nodes()}
    _app, _term, code = steal(panel, "nl-2", "nl-2.example.com", nodes=nodes)
    assert code == EXIT_OK
    count = len(panel.profiles)
    items, names = plan_of(panel, nodes)
    assert not [i for i in items if i.fix_id == "self_steal" and names[i.node_uuid] == "nl-2"]
    assert len(panel.profiles) == count


# -- the fake panel keeps the contract ------------------------------------------------------------
def client_of(panel):
    from kerberos.panel.client import PanelClient

    client = PanelClient("http://127.0.0.1:3000/api", panel, FakeClock())
    client.set_token(panel.add_api_token())
    return client


def test_the_fake_panel_refuses_a_taken_tag_or_name():
    from kerberos.panel.errors import PanelError

    panel = build_panel()
    client = client_of(panel)
    taken = {"inbounds": [{"tag": "VLESS-REALITY-NL1", "protocol": "vless", "port": 443}]}
    with pytest.raises(PanelError) as error:
        client.create_profile("KERBEROS A", taken)
    assert error.value.status == 409
    with pytest.raises(PanelError) as error:
        client.create_profile("NL-1", {"inbounds": [{"tag": "A-1", "protocol": "vless"}]})
    assert error.value.status == 409
    with pytest.raises(PanelError) as error:
        client.create_profile("Default-Profile", {"inbounds": [{"tag": "A-2"}]})
    assert error.value.status == 400
    nl1 = profile_of(panel, "nl-1")
    with pytest.raises(PanelError) as error:
        client.patch_profile(nl1["uuid"], taken | {"inbounds": [
            {"tag": "VLESS-REALITY-NL2", "protocol": "vless", "port": 443}]})  # fmt: skip
    assert error.value.status == 409


def test_deleting_a_profile_stops_its_nodes_and_keeps_their_hosts():
    panel = build_panel()
    nl1 = profile_of(panel, "nl-1")
    hosts = [h["uuid"] for h in panel.hosts if h["inbound"]["configProfileUuid"] == nl1["uuid"]]
    client_of(panel).delete_profile(nl1["uuid"])
    node = node_of(panel, "nl-1")
    assert node["configProfile"]["activeConfigProfileUuid"] is None and not node["isConnected"]
    assert all(panel.host(u)["inbound"]["configProfileUuid"] is None for u in hosts)


def test_undo_takes_out_of_a_squad_only_what_it_lacked():
    class Client:
        def __init__(self):
            from kerberos.panel.model import Squad

            self.squad = Squad("s", "Default", ["old-reality", "new-reality", "new-hy2", "later"])
            self.patched = None

        def squads(self):
            return [self.squad]

        def patch_squad(self, uuid, inbounds):
            self.patched = inbounds

    client = Client()
    details = {"squads": {"s": ["old-reality", "new-reality"]}, "added": ["new-reality", "new-hy2"]}
    undo_squads(client, details)
    assert client.patched == ["old-reality", "new-reality", "later"]
    client = Client()
    undo_squads(client, {"squads": {"s": ["old-reality"]}, "added": "new-hy2"})  # before v29
    assert client.patched == ["old-reality", "new-reality", "later"]


# -- pure functions ------------------------------------------------------------------------------
@given(st.text(min_size=0, max_size=60), st.sets(st.text(max_size=32), max_size=20))
def test_a_profile_name_fits_the_panel_and_is_free(node_name, taken):
    name = profile_name(node_name, taken)
    assert NAME_RE.fullmatch(name) and len(name) <= 30 and name not in taken


@given(st.text(min_size=1, max_size=40), st.sets(st.text(max_size=44), max_size=20))
def test_a_new_tag_is_free(base, taken):
    assert unique_tag(base, taken) not in taken


def test_a_flag_is_drawn_only_for_a_country():
    assert flag("NL") == "🇳🇱" and flag("nl") == "🇳🇱"
    assert flag("XX") == "" and flag("") == "" and flag("N1") == "" and flag("НЛ") == ""


# -- the screens -----------------------------------------------------------------------------------
def test_s7_and_consent_name_the_own_profile():
    panel = shared_fleet()
    keys = domain_row(panel, "nl-2", "d", *"nl-2.example.com", "enter") + ["enter"]
    _app, term, _code = run_fix(keys + ["esc", "esc", "q", "enter"], panel)
    details = t("plan.own_profile", profile="KERBEROS NL-2", shared="NL-1", nodes="nl-1")
    assert seen(term, details)
    consent = next(f for f in term.frames if t("consent.title") in f.splitlines()[0])
    assert t("consent.own_profile", profiles="nl-2 → KERBEROS NL-2") in flat(consent)


def test_s9_and_the_report_name_the_profile_made():
    panel = shared_fleet()
    keys = domain_row(panel, "nl-2", "d", *"nl-2.example.com", "enter")
    app, term, code = run_fix(keys + ["enter", "enter", "space", "enter"], panel)
    assert code == EXIT_OK
    label = t("fix.self_steal.own_profile.label", profile="KERBEROS NL-2")
    assert seen(term, label)
    store = RunStore(app.env.state, app.env.clock)
    assert label in store.report_text(run_of(app)["runId"])


def test_the_plan_reads_at_80_columns_without_colour():
    panel = two_squads(build_panel())
    squadless(panel, "nl-1")
    keys = domain_row(panel, "nl-1", "d", *"nl-1.example.com", "enter")
    nodes = {n.name: n for n in build_nodes()}
    app, term = make_app(TO_PLAN + keys + ["esc", "q", "enter"], panel=panel,
                         nodes=list(nodes.values()), width=80, height=30)  # fmt: skip
    app.run("fix")
    plan = [
        f for f in term.frames if f.splitlines()[0].startswith("/// kerberos  " + t("plan.title"))
    ]
    last = plan[-1]
    assert all(len(line) <= 80 for line in last.splitlines())
    assert t("plan.domain.squads") in last and "u " + t("keys.squads") in last.splitlines()[-1]


# -- a node without a profile ----------------------------------------------------------------------
def profileless(panel, name):
    """The profile of `name` was deleted in the panel: the node keeps none (SetNull)."""
    own = profile_of(panel, name)
    gone = {i["uuid"] for i in own["inbounds"]}
    node_of(panel, name)["configProfile"] = {"activeConfigProfileUuid": None, "activeInbounds": []}
    panel.hosts = [h for h in panel.hosts if h["inbound"]["configProfileUuid"] != own["uuid"]]
    for squad in panel.squads:
        squad["inbounds"] = [i for i in squad["inbounds"] if i["uuid"] not in gone]
    panel.profiles.remove(own)


def test_a_node_without_a_profile_gets_one_with_a_new_key():
    panel = build_panel()
    profileless(panel, "nl-2")
    items, names = plan_of(panel)
    nl2 = next(i for i in items if i.fix_id == "self_steal" and names[i.node_uuid] == "nl-2")
    assert nl2.checks == ["node.no_profile"]
    assert nl2.params["ownProfile"] == "KERBEROS NL-2" and nl2.params["sharedProfile"] is None
    app, term, code = steal(panel, "nl-2", "nl-2.example.com")
    assert code == EXIT_OK
    own = profile_of(panel, "nl-2")
    key = reality_of(own)["streamSettings"]["realitySettings"]["privateKey"]
    assert key and not key.startswith("DEMO_KEY")
    assert seen(term, t("fix.own_profile.warning.none", node="nl-2", profile="KERBEROS NL-2"))
    assert sorted(h["remark"] for h in panel.hosts
                  if h["inbound"]["configProfileUuid"] == own["uuid"]) == [
        "🇳🇱 nl-2", "🇳🇱 nl-2 Hysteria2"]  # fmt: skip
    app.env.terminal.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_OK
    assert node_of(panel, "nl-2")["configProfile"]["activeConfigProfileUuid"] is None
    assert all(p["name"] != "KERBEROS NL-2" for p in panel.profiles)


# -- finalization ----------------------------------------------------------------------------------
def test_finalization_leaves_only_the_domain_in_the_own_profile():
    panel = shared_fleet()
    shared = copy.deepcopy(profile_of(panel, "nl-1"))
    app, _term, code = steal(panel, "nl-2", "nl-2.example.com")
    assert code == EXIT_OK
    app.env.clock.advance(24 * 3600)
    app.env.terminal.feed("enter", "x")
    app.run("finalize")
    names = reality_of(profile_of(panel, "nl-2"))["streamSettings"]["realitySettings"]
    assert names["serverNames"] == ["nl-2.example.com"]
    assert profile_of(panel, "nl-1") == shared


# -- found on the stand: KERBEROS's own template is not a hand edit -----------------------------
@pytest.mark.parametrize("kind", ["reserve", "single"])
def test_a_template_kerberos_wrote_for_other_zones_is_its_own(kind):
    from kerberos.fixes import subscription

    assert subscription.own_write(kind, subscription.build(kind, []))
    assert subscription.own_write(kind, subscription.build(kind, ["nl-1.example.net"]))
    edited = subscription.build(kind, ["nl-1.example.net"])
    edited["log"] = {"loglevel": "debug"}
    assert not subscription.own_write(kind, edited)
    assert not subscription.own_write(kind, {})


def test_a_new_zone_brings_the_templates_up_to_date_without_a_question():
    """The stand: the second node's domain in another zone made KERBEROS ask whether its own
    templates of the first run were edited by hand, under the hints of the quit question."""
    from kerberos.fixes import subscription

    panel = build_panel()
    old = {}
    for kind, name in (("reserve", subscription.RESERVE_NAME),
                       ("single", subscription.SINGLE_NAME)):  # fmt: skip
        old[name] = subscription.build(kind, ["nl-1.example.net"])
        panel.templates.append({"uuid": new_uuid(), "name": name, "templateType": "XRAY_JSON",
                                "templateJson": copy.deepcopy(old[name])})  # fmt: skip
    _app, term, code = steal(panel, "nl-1", "nl-1.example.com")
    assert code == EXIT_OK
    assert not seen(term, t("tpl.diff.question"))
    for template in panel.templates:
        if template["name"] in old:
            assert template["templateJson"] != old[template["name"]], "brought up to date"
            assert "domain:example.com" in json.dumps(template["templateJson"])


def test_the_question_about_a_hand_edit_names_its_own_keys():
    from kerberos.fixes import subscription

    panel = build_panel()
    edited = subscription.build("single", ["nl-1.example.net"])
    edited["log"] = {"loglevel": "debug"}
    panel.templates.append({"uuid": new_uuid(), "name": subscription.SINGLE_NAME,
                            "templateType": "XRAY_JSON", "templateJson": edited})  # fmt: skip
    keys = domain_row(panel, "nl-1", "d", *"nl-1.example.com", "enter") + ["enter", "enter"]
    _app, term, _code = run_fix(keys + ["esc", "esc", "enter"], panel)
    question = next(f for f in term.frames if t("tpl.diff.question") in f)
    assert t("tpl.diff.yes") in question and t("quit.yes") not in question
