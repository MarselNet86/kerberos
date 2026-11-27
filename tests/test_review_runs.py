"""Review K13, finalization, the lock and exit codes: each test replays a review scenario."""

from helpers import make_app
from test_review_logic import (
    APPLY,
    DONE,
    NL1,
    ROLLBACK,
    TO_PLAN,
    domain_keys,
    fix,
    fix_run,
    fleet,
)

from kerberos.demo.fleet import build_host
from kerberos.fixes.finalize import unattended
from kerberos.fixes.journal import RunStore
from kerberos.flow import EXIT_OK
from kerberos.host import CommandResult


def store_of(app):
    return RunStore(app.env.state, app.env.clock)


# -- app 16 (v19): the timer signs in with the saved API token; KERBEROS makes no token ------
def test_failed_timer_is_not_reported_and_no_token_is_made():
    panel, nodes = fleet()
    app, _term, _code = fix(domain_keys(NL1, "nl-1.example.com") + APPLY + DONE,
                            panel, nodes)  # fmt: skip
    run = fix_run(app)
    assert any(c[:1] == ("systemd-run",) for c in app.env.host.calls)  # the demo host has none
    assert run["finalizeTimer"] is None
    assert not (store_of(app).path(run["runId"]) / "finalize.token").exists()
    assert not any(path.startswith("/tokens") for _m, path, _b in panel.log)


def test_timer_of_a_rolled_back_run_finds_nothing_to_do():
    panel, nodes = fleet()
    host = build_host()
    host.on(["systemd-run"], CommandResult(0))
    keys = TO_PLAN + domain_keys(NL1, "nl-1.example.com") + APPLY + DONE
    app, _term = make_app(keys, panel=panel, nodes=list(nodes.values()), height=46, host=host)
    app.run("fix")
    run = fix_run(app)
    assert run["finalizeTimer"]
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_OK
    writes = len(panel.mutations)
    app.env.clock.advance(24 * 3600 + 1)  # the timer fires: nothing is due any more
    assert unattended(store_of(app), panel, app.env.clock, run["runId"]) == 0
    assert len(panel.mutations) == writes
    assert app.env.state.read_panel_token(), "the person's token stays for the next run"


# -- app 17: KERBEROS's own finalization is not a hand edit for a later rollback --------------
def test_rollback_after_finalization_does_not_ask():
    import json

    from helpers import flat
    from test_review_logic import profile_of

    from kerberos.copy import t

    panel, nodes = fleet()
    before = json.loads(json.dumps(profile_of(panel, "nl-1")["config"]))
    app, _term, code = fix(domain_keys(NL1, "nl-1.example.com") + APPLY + DONE, panel, nodes)
    assert code == EXIT_OK
    app.env.clock.advance(25 * 3600)
    app.env.terminal.feed(*list("admin"), "enter", *list("pw"), "enter", "enter", "x")
    assert app.run("finalize") == EXIT_OK
    mark = len(app.env.terminal.frames)
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_OK
    assert not any(t("rb.diff.question") in flat(f) for f in app.env.terminal.frames[mark:])
    assert profile_of(panel, "nl-1")["config"] == before
    profile = next(c for c in fix_run(app)["changes"] if c["fixId"] == "self_steal.profile")
    assert "DEMO_KEY" not in json.dumps(profile), "the finalized profile stays in a 0600 file"


# -- app 19: the timer's finalization takes the lock like every KERBEROS ----------------------
def test_unattended_finalize_takes_the_lock(tmp_path, monkeypatch):
    import kerberos.__main__ as cli
    from kerberos.state import State

    state = State(tmp_path)
    monkeypatch.setattr(cli, "FINALIZE_LOCK_WAIT", 0, raising=False)
    options = cli.Options(command="finalize", arg="20261116T120000Z-a1b2")
    with state.lock():  # a rollback of the same run is open in a terminal
        assert cli.finalize_unattended(options, state) == 2
    assert cli.finalize_unattended(options, state) == 0


def test_lock_waits_for_the_other_kerberos(tmp_path):
    import pytest

    from kerberos.state import Locked, State

    state = State(tmp_path)
    other = state.lock()
    other.__enter__()  # another KERBEROS holds the lock
    slept = []

    def sleep(seconds):
        slept.append(seconds)
        if len(slept) == 2:
            other.__exit__(None, None, None)  # it ends while this one waits

    with state.lock(wait=30, sleep=sleep):
        pass
    assert slept == [5.0, 5.0]
    other = state.lock()
    other.__enter__()
    with pytest.raises(Locked):
        with state.lock(wait=12, sleep=slept.append):
            pass
    other.__exit__(None, None, None)
    assert slept[2:] == [5.0, 5.0, 2.0], "it gives up after `wait` seconds"


# -- app 20: `sudo ./kerberos` exits with what its flows ended with ---------------------------
def test_menu_returns_the_last_failure_of_its_flows():
    from kerberos.flow import EXIT_PARTIAL

    panel, nodes = fleet()
    nodes["nl-2"].state["fail"] = {"mptcp.guard": "mptcp_absent"}
    keys = ["down", "enter"] + TO_PLAN + APPLY + DONE + ["q", "enter"]  # «Исправление», then quit
    app, _term = make_app(keys, panel=panel, nodes=list(nodes.values()), height=46)
    assert app.run() == EXIT_PARTIAL


def test_menu_keeps_the_outcome_when_the_person_quits_on_s9():
    from kerberos.flow import EXIT_PARTIAL

    panel, nodes = fleet()
    nodes["nl-2"].state["fail"] = {"mptcp.guard": "mptcp_absent"}
    keys = ["down", "enter"] + TO_PLAN + APPLY + ["q", "enter"]  # q on S9 itself
    app, _term = make_app(keys, panel=panel, nodes=list(nodes.values()), height=46)
    assert app.run() == EXIT_PARTIAL


def test_timer_with_an_unreadable_token_file_does_not_crash(tmp_path):
    from kerberos.clock import FakeClock
    from kerberos.state import State

    store = RunStore(State(tmp_path), FakeClock())
    run = store.new_run("fix", {"version": "2.8.1"}, [])
    store.save(run)
    (store.path(run["runId"]) / "finalize.token").write_text('{"uuid": "only"}')
    assert unattended(store, None, FakeClock(), run["runId"]) == 0
