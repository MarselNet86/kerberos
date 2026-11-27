"""SSH only from the panel server in the app (tech.md §6 S7, S9, §10.2, §10.3, K28)."""

from helpers import S4_KEYS, login_keys, make_app, on, on_group, seen

from kerberos.checks import run_checks
from kerberos.copy import t
from kerberos.demo.fleet import build_nodes
from kerberos.fixes.journal import RunStore
from kerberos.fixes.plan import build_plan
from kerberos.flow import EXIT_OK

TO_PLAN = login_keys() + ["enter"] + S4_KEYS + ["enter", "enter"]  # S3, S4, admin key
TO_PLAN += ["enter", "enter", "enter"]  # S4 summary, whois, S6 → S7
APPLY = ["enter", "enter", "enter"]  # S7 → consent → accept, S9
ROLLBACK = ["enter", "enter", "enter", "x"]  # the run, all changes, consent; the saved token
PANEL = "198.51.100.5"  # where the demo nodes see KERBEROS come from


def run_fix(keys, nodes=None, height=46):
    nodes = nodes or build_nodes()
    app, term = make_app(TO_PLAN + list(keys), nodes=nodes, height=height)
    return app, term, app.run("fix"), nodes


def items_of(app, fix_id="ssh.panel_only"):
    return [i for i in app.session.data["plan"] if i.fix_id == fix_id]


def test_the_row_is_the_persons_own_choice():
    app, term, _code, _nodes = run_fix(["a", "esc", "q", "enter"])
    rows = items_of(app)
    assert rows and not any(i.selected for i in rows), "neither by default nor by `a`"
    assert seen(term, t("area.ssh_panel"))


def test_consent_warns_and_the_way_in_is_saved_on_s9():
    nodes = build_nodes()
    app, term, code, nodes = run_fix(on("nl-1", "ssh.panel_only", "space") + APPLY, nodes=nodes)
    assert code == EXIT_OK
    assert seen(term, t("fix.ssh_panel.warning")[:60])
    change = next(c for c in RunStore(app.env.state, app.env.clock).runs()[0]["changes"]
                  if c["fixId"] == "ssh.panel_only")  # fmt: skip
    assert change["state"] == "confirmed", "confirmed by a new connection of KERBEROS"
    nl1 = next(n for n in nodes if n.name == "nl-1")
    assert nl1.state["facts"]["ssh"]["guarded"] == nl1.state["facts"]["ssh"]["ports"]
    command = f"ssh -J root@{PANEL} root@203.0.113.10"
    assert seen(term, t("s9.save.ssh_panel", node="nl-1", command=command))
    uuid = next(n.uuid for n in app.session.snapshot.nodes if n.name == "nl-1")
    after = [f for f in app.session.data["findings_after"]
             if f["checkId"] == "ssh.open" and f["target"] == f"node:{uuid}"]  # fmt: skip
    assert after and after[0]["ok"], "the check passes after the fix"
    app.env.terminal.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_OK
    assert not nl1.state["facts"]["ssh"].get("guarded")


def test_the_group_marks_the_key_of_the_person_with_it():
    app, _term, _code, _nodes = run_fix(on_group("ssh_panel", "space") + ["esc", "q", "enter"])
    by_target = {}
    for item in app.session.data["plan"]:
        by_target.setdefault(item.target, {})[item.fix_id] = item
    for fixes in by_target.values():
        if "ssh.panel_only" in fixes and "access.admin_keys" in fixes:
            assert fixes["ssh.panel_only"].selected and fixes["access.admin_keys"].selected


def test_a_node_that_is_the_panel_server_is_blocked():
    from demo_input import demo_input

    _env, data = demo_input()
    node = next(n for n in data.nodes if n.node.name == "nl-1")
    items = build_plan(run_checks(data), data, {"mode": "mine", "keys": []},
                       {node.node.uuid: node.ipv4})  # fmt: skip
    item = next(i for i in items if i.fix_id == "ssh.panel_only" and i.node_uuid == node.node.uuid)
    assert item.blocked == "panel_local" and not item.selected


def test_without_a_key_of_the_person_the_row_is_blocked():
    from demo_input import demo_input

    _env, data = demo_input()
    for item in data.nodes:
        if item.facts:
            item.facts["ssh"]["adminKeys"] = 0
    items = build_plan(run_checks(data), data, {"mode": "skip", "keys": []}, {})
    rows = [i for i in items if i.fix_id == "ssh.panel_only"]
    assert rows and all(i.blocked == "no_admin_key" for i in rows)


def test_the_check_is_only_info_and_only_for_remnawave():
    from kerberos.checks import spec

    rule = spec("ssh.open")
    assert rule.risk == "info" and rule.fix_id == "ssh.panel_only"
    assert rule.panels == ("remnawave",), "on 3x-ui the panel server is the node itself"
