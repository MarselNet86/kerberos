"""Renewals that already run into port 80 (tech.md §10.2, §10.4, K17).

`acme.port80`: a certificate renews by its own listener on :80, with no hook that frees the
port, while another program holds it over IPv4. `acme.stop_hook`: a pre-hook of every certbot
renewal stops nginx on a node with the site of KERBEROS. Both give a finding only where that
is so: a fleet without such trouble keeps its score, the demo's 38 → 77 included.
"""

import pytest
from demo_input import demo_input
from helpers import seen
from test_xui_flow import TO_PLAN, TO_STEAL, local_node, xui_app

from kerberos.agent import SITE_CONF
from kerberos.checks import spec
from kerberos.copy import t
from kerberos.fixes.plan import self_steal_blocker

RENEWAL = {"tool": "acme.sh", "name": "203.0.113.10", "names": ["203.0.113.10"],
           "notAfter": "2026-11-24T00:00:00Z", "freesPort": False}  # fmt: skip


@pytest.fixture
def data():
    return demo_input()[1]


def results(data, check_id):
    return [f for f in spec(check_id).rule(data) if f["checkId"] == check_id]


def with_facts(data):
    return [n for n in data.nodes if n.facts is not None]


def listening80(process, address="0.0.0.0"):
    return {"proto": "tcp", "address": address, "port": 80, "process": process,
            "docker": False, "firewalled": False}  # fmt: skip


def site(name):
    return {"file": SITE_CONF, "serverNames": [name], "listen": ["80", "[::]:80"]}


def test_the_demo_fleet_gives_no_renewal_findings(data):
    # the demo has neither renewals on :80 nor the site of KERBEROS: its score stays (§12.4)
    assert results(data, "acme.port80") == [] and results(data, "acme.stop_hook") == []


@pytest.mark.parametrize("holder, address", [("nginx", "0.0.0.0"), ("caddy", "*"),
                                             ("docker-proxy", "203.0.113.10")])  # fmt: skip
def test_a_renewal_behind_a_busy_port_is_found(data, holder, address):
    node = with_facts(data)[0]
    node.facts["acme"] = [RENEWAL]
    node.facts["listening"].append(listening80(holder, address))
    [found] = results(data, "acme.port80")
    assert found["ok"] is False and found["target"] == f"node:{node.node.uuid}"
    assert found["evidence"] == {"names": ["203.0.113.10"], "holders": [holder]}
    assert found["fixId"] is None  # manual: self-steal moves it only where it runs anyway


@pytest.mark.parametrize(
    "renewal, listener",
    [
        (RENEWAL, None),  # port 80 is free
        ({**RENEWAL, "freesPort": True}, listening80("caddy")),  # its hook stops the holder
        ({k: v for k, v in RENEWAL.items() if k != "freesPort"}, listening80("caddy")),  # old agent
        (RENEWAL, listening80("nginx", "::")),  # IPv6 only: the IPv4 bind still works
        (RENEWAL, listening80("socat")),  # the renewal itself, caught mid-run
        (RENEWAL, listening80("certbot")),
    ],
)
def test_no_finding_where_the_renewal_gets_its_port(data, renewal, listener):
    node = with_facts(data)[0]
    node.facts["acme"] = [renewal]
    node.facts["listening"] = [s for s in node.facts["listening"] if s["port"] != 80]
    if listener:
        node.facts["listening"].append(listener)
    assert results(data, "acme.port80") == []


def test_a_moved_renewal_leaves_no_finding(data):
    node = with_facts(data)[0]
    node.facts["listening"].append(listening80("nginx"))
    node.facts["acme"] = []  # self-steal moved it to nginx
    assert results(data, "acme.port80") == []


def test_a_hook_that_stops_nginx_is_found_on_a_node_with_the_site(data):
    node = with_facts(data)[0]
    node.facts["nginx"]["sites"].append(site("nl-1.example.com"))
    node.facts["certbot"]["stopsNginx"] = True
    [found] = results(data, "acme.stop_hook")
    assert found["ok"] is False and found["evidence"] == {"names": ["nl-1.example.com"]}
    node.facts["certbot"]["stopsNginx"] = False
    assert results(data, "acme.stop_hook") == []
    del node.facts["certbot"]["stopsNginx"]  # an agent before 0.10: no data, no finding
    assert results(data, "acme.stop_hook") == []


def test_a_hook_on_a_node_without_the_site_is_not_this_check(data):
    node = with_facts(data)[0]
    node.facts["certbot"]["stopsNginx"] = True
    assert results(data, "acme.stop_hook") == []


def test_the_hook_blocks_self_steal(data):
    node = next(n for n in with_facts(data) if self_steal_blocker(data, n) is None)
    node.facts["certbot"]["stopsNginx"] = True
    assert self_steal_blocker(data, node) == "certbot_hook"


def test_plan_shows_why_self_steal_is_off():
    keys = TO_PLAN + TO_STEAL + ["esc", "q", "enter"]  # the row, its details, out
    app, term = xui_app(keys)
    local_node(app).state["facts"]["certbot"]["stopsNginx"] = True
    app.run("fix")
    assert seen(term, t("plan.blocked.certbot_hook"))
    assert [cmd for _a, cmd in app.env.transport.log if cmd.startswith("apply")] == []
