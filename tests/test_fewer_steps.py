"""K25: fewer steps (tech.md v31, §5.4, §6, §8.5, §10.4).

One panel on the server asks nothing and S2 does not stop; the host keys of the new
nodes are confirmed in one table; the answers about the administrator key and whois
are kept in answers.json; S7 fills in a domain that already points to the node; old
names leave by the timer unless the person says otherwise.
"""

import json
import stat

import pytest
from helpers import S4_KEYS, flat, login_keys, make_app, seen, typed
from hypothesis import given
from hypothesis import strategies as st

from kerberos.copy import t
from kerberos.demo.fleet import build_nodes, build_panel
from kerberos.fixes.journal import RunStore
from kerberos.nodes.keys import demo_blob
from kerberos.panel.discover import XUI_DB
from kerberos.state import State
from kerberos.ui.terminal import ScriptExhausted

QUIT = ["q", "enter"]
ADMIN = ["enter", "enter"]  # «Мои ключи» and its list
# A later run with everything remembered: S3, kz-1's port, the summary of S4, S6 → S7.
AGAIN_TO_PLAN = ["enter", "esc", "enter", "enter"]
TO_PLAN = login_keys() + ["enter"] + S4_KEYS + ADMIN + ["enter", "enter", "enter"]
NL1 = "203.0.113.10"


def one_panel_app(keys, **kwargs):
    """The demo panel server with Remnawave only: 3x-ui is not found here."""
    app, term = make_app(keys, panel_kind=None, **kwargs)
    app.env.host.databases.pop(XUI_DB)
    return app, term


def frames_titled(term, key):
    head = "/// kerberos  " + t(key)
    return [f for f in term.frames if f.splitlines()[0].startswith(head)]


def starts(term, text):
    """How many times a screen with `text` came up: runs of frames count once."""
    shown = [text in flat(f) for f in term.frames]
    return sum(1 for i, on in enumerate(shown) if on and (i == 0 or not shown[i - 1]))


def node_of(nodes, name):
    return next(n for n in nodes if n.name == name)


def plan_item(app, name, fix_id="self_steal"):
    uuid = next(n.uuid for n in app.session.snapshot.nodes if n.name == name)
    return next(i for i in app.session.data["plan"]
                if i.fix_id == fix_id and i.node_uuid == uuid)  # fmt: skip


# -- S2: one panel found asks nothing, and S2 does not stop ------------------------------
def test_one_panel_on_the_server_is_not_asked_about():
    app, term = one_panel_app(login_keys() + ["esc"])
    app.run("check")
    assert not seen(term, t("panel.choose"))
    s3 = frames_titled(term, "s3.title")[0]
    assert t("panel.ok", nodes=6, hosts=10) in s3 and "Remnawave 2.8.1" in s3


def test_two_panels_on_the_server_are_asked_about():
    app, term = make_app(["esc"], panel_kind=None)
    app.run("check")
    assert seen(term, t("panel.choose"))


def test_esc_on_the_login_opens_the_choice_it_skipped():
    app, term = one_panel_app(["esc", "esc"])
    app.run("check")
    login = next(i for i, f in enumerate(term.frames) if t("panel.admin.login") in flat(f))
    assert any(t("panel.choose") in flat(f) for f in term.frames[login:])


def test_s2_goes_straight_on_to_s3_and_esc_there_leaves():
    app, term = make_app(login_keys() + ["esc"])
    assert app.run("check") == 0
    connected = t("panel.ok", nodes=6, hosts=10)
    assert not any(connected in f for f in frames_titled(term, "s2.title")), "no stop on S2"
    assert any(connected in f for f in frames_titled(term, "s3.title"))
    assert term.remaining == []


# -- S4: one table of host keys ---------------------------------------------------------
def test_one_enter_confirms_every_new_host_key():
    nodes = build_nodes()
    app, term = make_app(login_keys() + ["enter"] + S4_KEYS + ["enter", "x"] + QUIT, nodes=nodes)
    app.run("check")
    assert starts(term, t("access.hostkeys")) == 1
    for name in ("nl-1", "nl-2", "de-1", "fi-1"):
        assert app.env.state.find_node(name).access == "ok", name
    assert not seen(term, t("access.hostkey_changed", node="nl-1"))


def test_an_unmarked_node_gets_nothing():
    nodes = build_nodes()
    keys = login_keys() + ["enter", "esc", "down", "space", "enter", "enter", "enter", "x"]
    app, term = make_app(keys + QUIT, nodes=nodes)
    app.run("check")
    nl2 = node_of(nodes, "nl-2")
    assert nl2.agent_sha is None and not any("kerberos-agent" in k for k in nl2.authorized_keys)
    assert not any(addr == nl2.address and not cmd.startswith("keyscan")
                   for addr, cmd in app.env.transport.log)  # fmt: skip
    uuid = next(n.uuid for n in app.session.snapshot.nodes if n.name == "nl-2")
    assert app.session.data["access_reason"][uuid] == t("access.reason.declined")
    assert app.env.state.pinned(nl2.address, 22) is None
    assert app.env.state.find_node("nl-1").access == "ok"


def test_the_table_fits_80_columns_without_cutting_a_fingerprint():
    keys = login_keys() + ["enter"] + S4_KEYS + ["enter", "x"] + QUIT
    app, term = make_app(keys, width=80, height=24)
    app.run("check")
    table = frames_titled(term, "access.title")
    table = next(f for f in table if t("access.hostkeys") in flat(f))
    assert all(len(line) <= 80 for line in table.splitlines())
    for node in app.env.transport.nodes.values():
        if node.reachable and node.name in ("nl-1", "de-1", "fi-1"):
            assert node.host_key.fingerprint.removeprefix("SHA256:") in table, node.name


# -- answers.json ---------------------------------------------------------------------------
def first_fix(keys_after=("esc", "q", "enter"), keys=TO_PLAN):
    """A first «Исправление» up to S7 and out; the fleet stays for the next run."""
    nodes = build_nodes()
    app, _term = make_app(list(keys) + list(keys_after), nodes=nodes)
    app.run("fix")
    return app, nodes


def again(first, keys, **kwargs):
    """A later run on the same panel server and the same fleet."""
    app, nodes = first
    return make_app(keys, state=app.env.state, nodes=nodes, **kwargs)


def test_answers_are_kept_0600_as_fingerprints_only():
    app, _nodes = first_fix()
    path = app.env.state.answers_file
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["whois"] is True and data["admin"]["mode"] == "mine"
    assert data["admin"]["keys"] and all(k.startswith("SHA256:") for k in data["admin"]["keys"])
    text = path.read_text(encoding="utf-8")
    assert "admin@laptop" not in text and "ssh-ed25519" not in text


def test_a_second_run_asks_neither_the_admin_key_nor_whois():
    app, term = again(first_fix(), AGAIN_TO_PLAN + ["esc", "q", "enter"])
    app.run("fix")
    assert frames_titled(term, "plan.title"), "S7 with four keys"
    assert not seen(term, t("access.admin.later"))
    assert not seen(term, t("s5.whois.question"))
    assert app.session.data["admin"]["mode"] == "mine" and app.session.data["admin"]["keys"]
    assert app.env.whois.queries, "whois still runs: it was allowed"
    summary = next(f for f in term.frames if t("access.answer.whois.yes") in flat(f))
    assert t("access.answer.admin.mine", n=1) in flat(summary)
    assert "k " + t("keys.admin_key") in summary.splitlines()[-1]


def test_w_turns_whois_off_for_this_run_and_the_next():
    app, term = again(first_fix(), ["enter", "esc", "w", "enter", "enter", "esc", "q", "enter"])
    state = app.env.state
    app.run("fix")
    assert state.answers()["whois"] is False
    assert seen(term, t("access.answer.whois.no"))
    assert app.env.whois.queries == [], "no whois in this run"


def test_k_asks_the_admin_key_again_and_keeps_the_new_answer():
    keys = ["enter", "esc", "k", "down", "enter", "enter", "enter", "esc", "q", "enter"]
    app, term = again(first_fix(), keys)  # «Создать ключ на сервере панели»
    state = app.env.state
    app.run("fix")
    assert seen(term, t("access.admin.later"))
    assert app.session.data["admin"]["mode"] == "create"
    assert state.answers()["admin"] == {"mode": "create", "keys": []}


def test_a_key_gone_from_the_panel_server_asks_again():
    keys = ["enter", "esc"] + ADMIN + ["enter", "enter", "esc", "q", "enter"]
    app, term = again(first_fix(), keys)
    other = f"ssh-ed25519 {demo_blob('pc')} other@pc\n"
    app.env.host.files["/root/.ssh/authorized_keys"] = other
    app.run("fix")
    assert seen(term, t("access.admin.later")), "the remembered key is not there any more"


def test_skip_is_not_remembered():
    keys = login_keys() + ["enter"] + S4_KEYS + ["esc", "enter", "enter", "enter"]
    first = first_fix(keys=keys)
    assert "admin" not in first[0].env.state.answers()
    app, term = again(first, ["enter", "esc", "esc", "enter", "enter", "esc", "q", "enter"])
    app.run("fix")
    assert seen(term, t("access.admin.later")), "asked again: the password login stays"


def test_back_to_s4_keeps_the_answer_of_this_run():
    keys = login_keys() + ["enter"] + S4_KEYS + ADMIN + ["esc", "enter", "esc", "enter"]
    app, term = make_app(keys + ["enter", "enter", "esc", "q", "enter"])
    app.run("fix")
    assert starts(term, t("access.admin.later")) == 1


@given(st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=8),
                    lambda inner: st.lists(inner, max_size=3)
                    | st.dictionaries(st.sampled_from(["whois", "admin", "mode", "keys", "x"]),
                                      inner, max_size=4), max_leaves=12))  # fmt: skip
def test_answers_read_any_file_and_give_back_only_good_values(tmp_path_factory, value):
    state = State(tmp_path_factory.mktemp("answers"))
    state.ensure()
    state.answers_file.write_text(json.dumps(value), encoding="utf-8")
    answers = state.answers()
    assert set(answers) <= {"whois", "admin"}
    assert isinstance(answers.get("whois", True), bool)
    if "admin" in answers:
        assert answers["admin"]["mode"] in ("mine", "create")
        assert all(k.startswith("SHA256:") for k in answers["admin"]["keys"])


# -- S7: the domain the person need not type ------------------------------------------------
def fix_to_plan(panel=None, dns=None, state=None, keys=TO_PLAN, nodes=None):
    app, term = make_app(list(keys) + ["esc", "q", "enter"], panel=panel or build_panel(),
                         state=state, height=40, nodes=nodes)  # fmt: skip
    if dns:
        app.env.prober.dns.update(dns)
    app.run("fix")
    return app, term


def panel_with_host_address(address):
    panel = build_panel()
    next(h for h in panel.hosts if h["remark"] == "NL Reality")["address"] = address
    return panel


def test_the_address_of_a_host_that_points_to_the_node_is_filled_in():
    app, term = fix_to_plan(panel_with_host_address("nl-1.example.com"))
    item = plan_item(app, "nl-1")
    assert item.params["domain"] == "nl-1.example.com" and item.params["dns"] == "ok"
    assert item.selected, "marked as after typing it"
    where = t("plan.domain.from.host", host="NL Reality")
    assert app.session.data["domain_from"][item.node_uuid] == where


def test_the_address_of_the_node_comes_first():
    panel = build_panel()
    next(n for n in panel.nodes if n["name"] == "nl-1")["address"] = "nl-1.example.com"
    app, _term = fix_to_plan(panel)
    item = plan_item(app, "nl-1")
    assert item.params["domain"] == "nl-1.example.com"
    assert app.session.data["domain_from"][item.node_uuid] == t("plan.domain.from.node")


@pytest.mark.parametrize("address,dns", [
    ("panel.example.com", {"panel.example.com": [NL1]}),  # the panel's own domain
    ("www.example.net", {}),  # resolves elsewhere: the foreign site
    ("late.example.com", {}),  # does not resolve at all
])  # fmt: skip
def test_a_domain_is_filled_in_only_when_it_points_to_the_node(address, dns):
    app, _term = fix_to_plan(panel_with_host_address(address), dns=dns)
    item = plan_item(app, "nl-1")
    assert item.params["domain"] is None and item.params["dns"] == "none"
    assert not item.selected
    assert item.node_uuid not in app.session.data.get("domain_from", {})


def test_the_domain_of_the_last_run_comes_back():
    nodes = build_nodes()
    app, _term = fix_to_plan(nodes=nodes)
    state = app.env.state
    store = RunStore(state, app.env.clock)
    run = store.new_run("fix", {}, [])
    uuid = plan_item(app, "nl-1").node_uuid
    run["changes"].append({"changeId": "c1", "fixId": "self_steal.site", "target": f"node:{uuid}",
                           "state": "rolled_back", "params": {"domain": "nl-1.example.com",
                                                               "node": uuid},
                           "before": None, "details": {}, "error": None,
                           "startedAt": run["startedAt"], "finishedAt": None})  # fmt: skip
    store.save(run)
    app, _term = fix_to_plan(state=state, keys=AGAIN_TO_PLAN, nodes=nodes)
    item = plan_item(app, "nl-1")
    assert item.params["domain"] == "nl-1.example.com" and item.selected
    assert app.session.data["domain_from"][item.node_uuid] == t("plan.domain.from.last")


def test_typing_another_domain_forgets_where_the_first_came_from():
    app, term = fix_to_plan(panel_with_host_address("nl-1.example.com"))
    item = plan_item(app, "nl-1")
    assert app.session.data["domain_from"].get(item.node_uuid)
    from kerberos.screens.fix import ask_domain

    term.feed(*(["backspace"] * 20 + typed("nl-1b.example.com") + ["enter"]))
    app.env.prober.dns["nl-1b.example.com"] = [NL1]
    ask_domain(app, app.session, item)
    assert item.params["domain"] == "nl-1b.example.com"
    assert item.node_uuid not in app.session.data["domain_from"]


# -- the number of keys (§21 K25) -----------------------------------------------------------
def reaches_the_plan(keys, state=None, nodes=None):
    """True when exactly `keys` take «Исправление» to S7: one key less stops before it,
    one key more would have left it."""
    app, term = one_panel_app(keys, state=state, nodes=nodes)
    try:
        app.run("fix")
    except ScriptExhausted:
        pass
    return term.frames[-1].splitlines()[0].startswith("/// kerberos  " + t("plan.title"))


def test_the_first_run_takes_11_keys_and_a_later_one_4():
    # Typed: the admin's login and password (K30), not counted. The keys: Tab to the
    # password, Enter, then S3 to S7. One key more than a pasted token took (10 after
    # K25), and no trip to the browser to make that token.
    login, password = typed("admin"), typed("admin-password")
    first = ["tab", "enter", "enter"] + S4_KEYS + ADMIN + ["enter", "enter", "enter"]
    assert len(first) == 11, "was 15 before K25 and 10 with a token from the browser (§21)"
    typing = login + first[:1] + password + first[1:]
    assert reaches_the_plan(typing)
    nodes = build_nodes()
    app, _term = one_panel_app(typing + ["esc", "q", "enter"], nodes=nodes)
    app.run("fix")
    assert len(AGAIN_TO_PLAN) == 4, "was 9 before K25 (§21)"
    assert reaches_the_plan(AGAIN_TO_PLAN, state=app.env.state, nodes=nodes)
