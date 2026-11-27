"""The cut share of `node.blocked` needs a sample worth the name (tech.md §10.2, K18).

Found on a live server: a quiet port or a few web connections gave a «block» of high risk.
"""

import pytest
from demo_input import demo_input

from kerberos.checks import spec


def watch(connections: int, cut: int) -> dict:
    return {"protocol": 1, "port": 443, "ports": [443],
            "v4": {"connections": connections, "clientIps": connections, "cut": cut,
                   "cutNets": []},
            "v6": {"connections": 0, "clientIps": 0, "cut": 0, "cutNets": []},
            "xray": {}}  # fmt: skip


def finding_of(data, node):
    found = [f for f in spec("node.blocked").rule(data) if f["target"] == f"node:{node.node.uuid}"]
    return found[0] if found else None


@pytest.fixture
def data():
    return demo_input()[1]


def lone_node(data):
    """A node that has no reserve: only the cut share can speak for it."""
    from kerberos.checks.rules import reserves_of

    return next(n for n in data.nodes if n.watch is not None and not n.node.is_disabled
                and not reserves_of(data, n))  # fmt: skip


def test_one_cut_connection_of_one_is_not_a_block(data):
    node = lone_node(data)
    node.watch = watch(1, 1)
    assert finding_of(data, node) is None


def test_a_real_sample_with_many_cut_connections_is(data):
    node = lone_node(data)
    node.watch = watch(40, 10)
    found = finding_of(data, node)
    assert found["ok"] is False and found["evidence"]["cutShare"] == 0.25


def test_a_real_sample_with_few_cut_connections_passes(data):
    node = lone_node(data)
    node.watch = watch(40, 1)
    assert finding_of(data, node)["ok"] is True


# -- K27: frozen after the first 16 KB ----------------------------------------------------
def stalled_watch(connections: int, stalled: int) -> dict:
    found = watch(connections, 0)
    found["v4"].update(stalled=stalled, stalledNets=[])
    return found


def test_many_connections_frozen_after_16_kb_are_a_block(data):
    node = lone_node(data)
    node.watch = stalled_watch(40, 6)
    found = finding_of(data, node)
    assert found["ok"] is False and found["evidence"]["stallShare"] == 0.15


def test_few_frozen_connections_or_a_small_sample_are_not(data):
    node = lone_node(data)
    node.watch = stalled_watch(40, 2)
    assert finding_of(data, node)["ok"] is True
    node.watch = stalled_watch(10, 10)
    assert finding_of(data, node) is None


def test_an_agent_before_0_11_sends_no_stalled_count(data):
    node = lone_node(data)
    node.watch = watch(40, 1)  # no `stalled` at all
    found = finding_of(data, node)
    assert found["ok"] is True and found["evidence"]["stallShare"] == 0.0
