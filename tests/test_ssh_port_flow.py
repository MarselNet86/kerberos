"""ssh.port end to end (tech.md §10.3, K5)."""

import random

from helpers import login_keys, make_app, on, seen
from hypothesis import given
from hypothesis import strategies as st

from kerberos.copy import t
from kerberos.demo.fleet import build_nodes
from kerberos.fixes.journal import RunStore
from kerberos.fixes.plan import choose_port
from kerberos.flow import EXIT_OK, EXIT_PARTIAL

TO_PLAN = login_keys() + ["enter", "enter"] + ["enter"] * 5 + ["esc"] + ["enter", "enter"]
TO_PLAN += ["enter", "enter", "enter"]


def all_and_ports(*names):
    """`a` marks everything but the SSH ports (§6): those the person marks by hand."""
    keys = ["a"]
    for name in names:
        keys += on(name, "ssh.port", "space")
    return keys + ["enter", "enter"]  # consent, accept


def run_fix(extra, nodes):
    app, term = make_app(TO_PLAN + list(extra), nodes=list(nodes.values()), height=44)
    return app, term, app.run("fix")


def port_changes(app):
    run = RunStore(app.env.state, app.env.clock).runs()[0]
    return [c for c in run["changes"] if c["fixId"] == "ssh.port"]


def test_new_port_after_login_on_it_old_one_closed():
    nodes = {n.name: n for n in build_nodes()}
    app, term, code = run_fix(all_and_ports("nl-1") + ["enter"], nodes)
    assert code == EXIT_OK
    change = next(c for c in port_changes(app) if c["target"].endswith(
        next(u for u, r in app.env.state.nodes().items() if r.name == "nl-1")))  # fmt: skip
    port = change["details"]["newPort"]
    assert change["state"] == "confirmed" and 20000 <= port <= 32767
    assert nodes["nl-1"].state["facts"]["ssh"]["ports"] == [port]
    assert nodes["nl-1"].ssh_port == port, "the old port is closed"
    assert app.env.state.find_node("nl-1").ssh_port == port
    assert app.env.state.pinned("203.0.113.10", port) is not None
    confirms = [
        cmd
        for addr, cmd in app.env.transport.log
        if addr == "203.0.113.10" and cmd.startswith(f"confirm {change['changeId']}")
    ]
    assert confirms == [f"confirm {change['changeId']} (fresh)"]
    assert seen(term, t("fix.ssh_port.warning", port=port))
    assert seen(term, t("s9.save.ssh", node="nl-1", command=f"ssh -p {port} root@203.0.113.10"))
    report = RunStore(app.env.state, app.env.clock).report_text(
        RunStore(app.env.state, app.env.clock).runs()[0]["runId"]
    )
    assert t("report.ssh_port", port=port, command=f"ssh -p {port} root@203.0.113.10") in report


def test_port_closed_by_the_hoster_is_rolled_back():
    nodes = {n.name: n for n in build_nodes()}
    nodes["fi-1"].state["hoster_firewall"] = True
    app, term, code = run_fix(all_and_ports("fi-1") + ["enter"], nodes)
    assert code == EXIT_PARTIAL
    fi = next(c for c in port_changes(app) if c["error"])
    assert fi["state"] == "rolled_back" and fi["error"] == "port_closed"
    assert nodes["fi-1"].state["facts"]["ssh"]["ports"] == [22]
    assert nodes["fi-1"].ssh_port == 22
    assert app.env.state.find_node("fi-1").ssh_port == 22
    assert seen(term, t("apply.rolled_back", reason=t("error.port_closed")))


def test_rollback_returns_the_old_port():
    nodes = {n.name: n for n in build_nodes()}
    app, _term, _code = run_fix(all_and_ports("nl-1") + ["enter"], nodes)
    app.env.terminal.feed(
        "enter", "enter", "enter", *list("admin"), "enter", *list("pw"), "enter", "x"
    )
    assert app.run("rollback") == EXIT_OK
    assert nodes["nl-1"].state["facts"]["ssh"]["ports"] == [22]
    assert app.env.state.find_node("nl-1").ssh_port == 22


@given(st.sets(st.integers(1, 65535), max_size=300), st.integers(0, 2**32))
def test_chosen_port_is_in_range_and_free(busy, seed):
    facts = {"listening": [{"port": p} for p in busy]}
    port = choose_port(facts, random.Random(seed))
    assert 20000 <= port <= 32767 and port not in busy
