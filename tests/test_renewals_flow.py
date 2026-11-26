"""Renewals on port 80 in the screens and files of KERBEROS (tech.md §10.4, §13, K16).

The demo 3x-ui server carries what its installer leaves: the panel's 6-day IP
certificate from acme.sh --standalone. Self-steal moves its renewal to nginx.
"""

import copy

import pytest
from helpers import seen
from test_xui_flow import (
    APPLY,
    ROLLBACK,
    TO_PLAN,
    TO_STEAL,
    last_run,
    local_node,
    reality,
    steal,
    xui_app,
)

from kerberos.checks import CheckInput, NodeData
from kerberos.checks.collect import node_names
from kerberos.copy import t
from kerberos.demo.xui import XUI_IP
from kerberos.fixes.journal import RunStore
from kerberos.flow import EXIT_OK
from kerberos.nodes import schema

MOVED = f"{XUI_IP} (acme.sh)"


def test_plan_and_consent_say_which_renewals_move():
    # consent → back to the plan → S6 → quit: nothing is applied
    app, term = xui_app(TO_PLAN + steal() + ["enter", "x", "esc", "q", "enter"])
    app.run("fix")
    assert seen(term, t("plan.renewals", names=MOVED))
    # The line of the node on the consent screen, whatever the node is called.
    assert seen(term, t("consent.renewals", node="", names=MOVED).lstrip(": "))


def test_s9_report_and_run_name_the_moved_renewals():
    # S9 (K23): Space opens «Свой домен», the first area KERBEROS changed.
    app, term = xui_app(TO_PLAN + steal() + APPLY + ["space", "enter"])
    assert app.run("fix") == EXIT_OK
    run = last_run(app)
    site = next(c for c in run["changes"] if c["fixId"] == "self_steal.site")
    assert site["details"]["renewals"] == [{"tool": "acme.sh", "name": XUI_IP, "names": [XUI_IP]}]
    assert seen(term, t("s9.renewals", names=MOVED))
    report = RunStore(app.env.state, app.env.clock).report_text(run["runId"])
    assert t("report.renewals", names=MOVED) in report
    assert local_node(app).state["facts"]["acme"] == []


def test_rollback_brings_the_renewal_back():
    app, _term = xui_app(TO_PLAN + steal() + APPLY + ["enter"])
    app.run("fix")
    app.env.terminal.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_OK
    assert [r["name"] for r in local_node(app).state["facts"]["acme"]] == [XUI_IP]


def test_nginx_without_the_probe_rolls_self_steal_back():
    app, term = xui_app(TO_PLAN + steal() + APPLY + ["enter"])
    local_node(app).state["acme_fails"] = True
    app.run("fix")
    site = next(c for c in last_run(app)["changes"] if c["fixId"] == "self_steal.site")
    assert site["error"] == "acme_check_failed" and site["state"] != "applied"
    assert seen(term, t("error.acme_check_failed"))
    assert reality(app)["target"] == "www.example.net:443"  # Reality was never moved
    assert [r["name"] for r in local_node(app).state["facts"]["acme"]] == [XUI_IP]


def test_a_renewal_that_cannot_move_blocks_self_steal():
    keys = TO_PLAN + TO_STEAL + ["esc", "q", "enter"]  # the row, its details, out
    app, term = xui_app(keys)
    local_node(app).state["facts"]["acme"][0]["blocked"] = "cli.ini"
    app.run("fix")
    assert seen(term, t("plan.blocked.acme_standalone"))
    applies = [cmd for _a, cmd in app.env.transport.log if cmd.startswith("apply")]
    assert applies == []


def test_masking_learns_the_names_of_renewals():
    app, _term = xui_app([])
    facts = copy.deepcopy(local_node(app).state["facts"])
    facts["acme"].append({"tool": "certbot", "name": "panel.example.org",
                          "names": ["panel.example.org", "www.panel.example.org"],
                          "notAfter": None})  # fmt: skip
    data = CheckInput(snapshot=None, nodes=[NodeData(node=None, facts=facts)])
    assert {"panel.example.org", "www.panel.example.org"} <= set(node_names(data))


def answer(**facts):
    base = {"protocol": 1, "os": {}, "ipv4": [], "ipv6": [], "listening": [],
            "ssh": {"ports": [22]}, "fail2ban": {}, "mptcp": {}, "nodeApi": {}, "nftTables": [],
            "hostKeys": [], "firewall": {}, "remnanode": {}, "nginx": {}, "certbot": {},
            "watch": {}}  # fmt: skip
    return {**base, **facts}


def test_facts_of_an_older_agent_have_no_renewals():
    assert schema.facts(answer())["acme"] == []


@pytest.mark.parametrize("acme", ["no", [{"names": "203.0.113.50"}], [{"names": [1]}], [1]])
def test_malformed_renewals_stop_the_facts(acme):
    with pytest.raises(schema.BadAnswer):
        schema.facts(answer(acme=acme))
