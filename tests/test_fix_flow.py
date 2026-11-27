"""«Исправление» end to end on the demo fleet (tech.md §6 S7-S9, §11, K4)."""

import pytest
from helpers import S4_KEYS, login_keys, make_app, plan_rows, seen
from test_review_screens import short_state

from kerberos.copy import t
from kerberos.demo.fleet import build_nodes
from kerberos.fixes.journal import RunStore
from kerberos.flow import EXIT_INTERRUPTED, EXIT_OK, EXIT_PARTIAL, EXIT_ROLLBACK_FAILED

# S2 login, S2 → S3 → S4; S4: five host keys (de-1 also installs python3), kz-1 skipped;
# admin key: «Мои ключи» and the checklist; S4 summary; whois yes; S6 → S7.
TO_PLAN = login_keys() + ["enter"] + S4_KEYS + ["enter", "enter"]  # S3, S4, admin key
TO_PLAN += ["enter", "enter", "enter"]  # S4 summary, whois, S6 → S7
APPLY = ["enter", "enter"]  # S7 → consent → accept
# Marked by default on the demo fleet: nl-1: 7, nl-2: 3, de-1: 1, fi-1: 3 on the nodes, then
# sub.template, sub.ping_type, xhttp.padding (fi-1) and xhttp.uplink_get («FI CDN») in the
# panel; the journal also gets sub.templates.
ALL_ITEMS = 18
ALL_CHANGES = 19
ROLLBACK_LOGIN = ["enter", "enter", "enter"] + list("admin") + ["enter"] + list("pw") + ["enter"]


def fix_run(extra, nodes=None, height=40, state=None):
    # A later run with a saved token: S2 asks nothing (§7.3), so no login is typed.
    saved = state is not None and state.read_panel_token() is not None
    keys = (TO_PLAN[len(login_keys()) :] if saved else TO_PLAN) + list(extra)
    app, term = make_app(keys, nodes=nodes, height=height, state=state)
    code = app.run("fix")
    return app, term, code


def last_run(app):
    return RunStore(app.env.state, app.env.clock).runs()[0]


def demo_nodes():
    return {n.name: n for n in build_nodes()}


def test_full_fix_applies_rechecks_and_reports():
    app, term, code = fix_run(APPLY + ["enter"])
    assert code == EXIT_OK
    run = last_run(app)
    assert run["mode"] == "fix"
    states = {c["state"] for c in run["changes"]}
    assert states <= {"applied", "confirmed"} and run["changes"]
    assert run["scoreAfter"] > run["scoreBefore"]
    assert all(c["finishedAt"] for c in run["changes"])
    report = RunStore(app.env.state, app.env.clock).report_text(run["runId"])
    assert t("report.changes") in report and "rollback " + run["runId"] in report
    assert seen(term, t("done.title"))
    assert seen(term, t("score.before_after", before=run["scoreBefore"], score=run["scoreAfter"]))


def test_nothing_changes_before_consent():
    keys = APPLY[:1] + ["x", "esc", "q", "enter"]  # consent → plan → S6 → quit
    app, term, _code = fix_run(keys)
    agent_calls = [cmd for _a, cmd in app.env.transport.log if cmd.startswith("apply")]
    assert agent_calls == [] and app.env.panel_transport.mutations == []
    assert seen(term, t("consent.title"))


def test_consent_shows_the_warning_of_section_15():
    app, term, _code = fix_run(APPLY[:1] + ["x", "esc", "q", "enter"])
    assert seen(term, t("fix.key_only.warning"))


def test_apply_roll_back_apply_again():
    nodes = demo_nodes()
    app, _term, code = fix_run(APPLY + ["enter"], nodes=list(nodes.values()))
    assert code == EXIT_OK
    facts = nodes["nl-1"].state["facts"]
    assert facts["mptcp"]["enabled"] is False and facts["ssh"]["passwordAuthentication"] is False
    first = last_run(app)
    term = app.env.terminal
    term.feed(*ROLLBACK_LOGIN, "x")  # the run, all changes, consent, the panel, the notice
    assert app.run("rollback") == EXIT_OK
    assert facts["mptcp"]["enabled"] is True and facts["ssh"]["passwordAuthentication"] is True
    assert nodes["nl-1"].state["facts"]["listening"][-1]["firewalled"] is False
    rolled = RunStore(app.env.state, app.env.clock).load(first["runId"])
    assert {c["state"] for c in rolled["changes"]} == {"rolled_back"}
    pinned = app.env.state.pinned("203.0.113.10", 22)
    assert pinned == nodes["nl-1"].host_key.blob, "the old host key is pinned again"
    term.feed(*(["2"] + TO_PLAN[:0]))
    app2, _term2, code = fix_run(APPLY + ["enter"], nodes=list(nodes.values()),
                                 state=app.env.state)  # fmt: skip
    assert code == EXIT_OK
    assert facts["mptcp"]["enabled"] is False


def test_key_only_refused_by_the_agent_without_an_admin_key():
    nodes = demo_nodes()
    # The panel saw a key, but it is gone when the change runs: the agent refuses.
    original = nodes["de-1"].handlers["apply"]

    def apply(node, args, params):
        if args[0] == "ssh.key_only":
            node.state["facts"]["ssh"]["adminKeys"] = 0
        return original(node, args, params)

    nodes["de-1"].handlers["apply"] = apply
    app, _term, code = fix_run(APPLY + ["enter"], nodes=list(nodes.values()))
    assert code == EXIT_PARTIAL
    refused = [c for c in last_run(app)["changes"] if c["error"] == "no_admin_key"]
    assert len(refused) == 1 and refused[0]["state"] == "failed"
    assert nodes["de-1"].state["facts"]["ssh"]["passwordAuthentication"] is True


def test_confirm_never_comes_and_the_change_is_rolled_back():
    nodes = demo_nodes()
    nodes["de-1"].state["confirm_fails"] = True
    app, term, code = fix_run(APPLY + ["enter"], nodes=list(nodes.values()))
    assert code == EXIT_PARTIAL
    run = last_run(app)
    de1 = [c for c in run["changes"] if c["fixId"] == "ssh.key_only" and
           c["state"] != "confirmed"]  # fmt: skip
    assert de1 and de1[0]["state"] == "rolled_back" and de1[0]["error"] == "confirm_failed"
    assert nodes["de-1"].state["facts"]["ssh"]["passwordAuthentication"] is True
    assert app.env.clock.slept and sum(app.env.clock.slept) >= 55


def test_agent_error_is_shown_and_counted():
    nodes = demo_nodes()
    nodes["nl-2"].state["fail"] = {"mptcp.guard": "mptcp_absent"}
    app, term, code = fix_run(APPLY + ["enter"], nodes=list(nodes.values()))
    assert code == EXIT_PARTIAL
    failed = [c for c in last_run(app)["changes"] if c["state"] == "failed"]
    assert failed[0]["error"] == "mptcp_absent"
    assert seen(term, t("apply.rolled_back", reason=t("error.mptcp_absent")))


def test_recheck_failure_rolls_back():
    nodes = demo_nodes()
    from kerberos.nodes import fake_fixes

    def noop_fix(node, params, change_id):
        return {}, lambda: None

    model = dict(fake_fixes.MODEL, **{"ports.drop": noop_fix})
    fake_fixes.give_fixes(nodes["nl-1"], model)
    app, _term, code = fix_run(APPLY + ["enter"], nodes=list(nodes.values()))
    assert code == EXIT_PARTIAL
    ports = [c for c in last_run(app)["changes"] if c["fixId"] == "ports.drop"]
    assert ports[0]["state"] == "rolled_back" and ports[0]["error"] == "recheck_failed"


def test_ctrl_c_stops_before_the_next_change():
    app, term, code = fix_run(APPLY + ["ctrl-c", "enter", "enter"])
    assert code == EXIT_INTERRUPTED
    run = last_run(app)
    assert run["interrupted"] is True
    assert {c["state"] for c in run["changes"]} <= {"applied", "confirmed"}
    assert 1 <= len(run["changes"]) < ALL_CHANGES
    assert seen(term, t("apply.interrupted"))


def test_ctrl_c_can_be_declined():
    app, term, code = fix_run(APPLY + ["ctrl-c", "esc", "enter"])
    assert code == EXIT_OK
    assert len(last_run(app)["changes"]) == ALL_CHANGES


@pytest.mark.parametrize("fail_on", ["rollback_fails"])
def test_rollback_that_fails_exits_with_5(fail_on):
    nodes = demo_nodes()
    app, _term, _code = fix_run(APPLY + ["enter"], nodes=list(nodes.values()))
    nodes["nl-1"].state[fail_on] = True
    app.env.terminal.feed(*ROLLBACK_LOGIN, "x")
    assert app.run("rollback") == EXIT_ROLLBACK_FAILED
    run = last_run(app)
    assert run["mode"] == "rollback"


def test_s9_snapshot_and_s7_rows(monkeypatch):
    import re

    from helpers import assert_snapshot

    # Where the repository is checked out must not wrap the rollback line.
    monkeypatch.setattr("kerberos.screens.fix.launcher", lambda: "/opt/kerberos/kerberos")
    app, term, _code = fix_run(APPLY + ["enter"], height=40, state=short_state())
    run = last_run(app)
    s9 = next(
        f for f in term.frames if f.splitlines()[0].startswith("/// kerberos  " + t("done.title"))
    )
    text = re.sub(r"\S*kerberos-test-\S*", "<state>", s9)
    text = re.sub(r"sudo \S+ rollback", "sudo <launcher> rollback", text)
    text = re.sub(r"SHA256:\S+", "SHA256:<new>", text)
    assert_snapshot("s9", text.replace(run["runId"], "<run>"))
    s7 = next(f for f in term.frames if t("plan.title") in f.splitlines()[0])
    assert t("area.scanners") in s7 and t("fix.mptcp.guard.short") in s7
    # K23: the four own domains are a block of their own, waiting for a domain. Not marked
    # in the groups: ssh.port and ssh.panel_only (4 nodes each, K28), host.fingerprint (low),
    # watch.install (by choice, 2 nodes), cdn.edge_only waiting for its nets.
    assert t("plan.block.auto.note", n=ALL_ITEMS, total=ALL_ITEMS + 12) in s7
    assert len(plan_rows()) == ALL_ITEMS + 16
