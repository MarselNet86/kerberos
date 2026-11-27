"""Plan of «Исправление» (tech.md §6 S7, §10.1)."""

from demo_input import demo_input

from kerberos.checks import run_checks
from kerberos.fixes.plan import NODE_ORDER, build_plan, follow_admin_key

PANEL_IP = "198.51.100.5"


def plan(admin=None):
    _env, data = demo_input()
    findings = run_checks(data)
    ips = {n.node.uuid: PANEL_IP for n in data.nodes}
    return data, build_plan(findings, data, admin, ips)


def by_node(data, items):
    names = {n.node.uuid: n.node.name for n in data.nodes}
    result = {}
    for item in items:
        if item.node_uuid is not None:
            result.setdefault(names[item.node_uuid], []).append(item)
    return result


def test_order_follows_section_10_1():
    data, items = plan({"mode": "mine", "keys": ["ssh-ed25519 AAAA admin@laptop"]})
    for node_items in by_node(data, items).values():
        order = [NODE_ORDER.index(i.fix_id) for i in node_items]
        assert order == sorted(order)
    names = [n.node.name for n in data.nodes]
    node_items = [i for i in items if i.node_uuid is not None]
    seen = [
        names.index(next(n.node.name for n in data.nodes if n.node.uuid == i.node_uuid))
        for i in node_items
    ]
    assert seen == sorted(seen)
    first_panel = next(k for k, i in enumerate(items) if i.node_uuid is None)
    assert all(i.node_uuid is None for i in items[first_panel:]), "panel fixes after the nodes"


def test_admin_key_goes_before_key_only_when_chosen():
    data, items = plan({"mode": "mine", "keys": ["ssh-ed25519 AAAA admin@laptop"]})
    nl1 = [i.fix_id for i in by_node(data, items)["nl-1"]]
    assert nl1.index("access.admin_keys") < nl1.index("ssh.key_only")
    admin = next(i for i in by_node(data, items)["nl-1"] if i.fix_id == "access.admin_keys")
    assert admin.params["keys"] == ["ssh-ed25519 AAAA admin@laptop"]


def test_key_only_is_blocked_without_an_admin_key():
    data, items = plan({"mode": "skip", "keys": []})
    key_only = next(i for i in by_node(data, items)["nl-1"] if i.fix_id == "ssh.key_only")
    assert key_only.blocked == "no_admin_key" and not key_only.selected
    de1 = next(i for i in by_node(data, items)["de-1"] if i.fix_id == "ssh.key_only")
    assert de1.blocked is None and de1.selected  # de-1 already has a key of its own


def test_defaults_and_params():
    data, items = plan({"mode": "create", "keys": []})
    nl1 = {i.fix_id: i for i in by_node(data, items)["nl-1"]}
    assert all(
        i.selected
        for k, i in nl1.items()
        if k not in ("ssh.port", "ssh.panel_only", "self_steal", "watch.install")
    )
    assert not nl1["ssh.panel_only"].selected, "SSH only from the panel is the person's (K28)"
    assert nl1["ssh.panel_only"].params == {"panelIp": PANEL_IP}
    assert not nl1["watch.install"].selected, "the watch is installed by choice (§10.2)"
    assert nl1["self_steal"].params["domain"] is None and not nl1["self_steal"].selected
    assert nl1["ports.drop"].params == {"ports": ["8080/tcp"]}
    assert nl1["fail2ban.sshd"].params == {"sshPorts": [22], "panelIp": PANEL_IP}
    assert nl1["node_api.panel_only"].params == {"port": 2222, "panelIp": PANEL_IP}
    assert nl1["access.admin_keys"].params["create"] is True
    assert not nl1["ssh.port"].selected, "ssh.port is marked by the person only (§6 S7)"
    assert 20000 <= nl1["ssh.port"].params["port"] <= 32767


def test_bridge_network_is_blocked():
    data, _items = plan()
    nl2 = next(n for n in data.nodes if n.node.name == "nl-2")
    nl2.facts["remnanode"]["network"] = "bridge"
    findings = run_checks(data)
    items = build_plan(findings, data, None, {})
    api = next(i for i in items if i.node_uuid == nl2.node.uuid and
               i.fix_id == "node_api.panel_only")  # fmt: skip
    assert api.blocked == "bridge_network" and not api.selected


def test_nodes_without_access_get_no_items():
    data, items = plan()
    kz = next(n for n in data.nodes if n.node.name == "kz-1")
    assert all(i.node_uuid != kz.node.uuid for i in items)


def test_admin_key_follows_key_only():
    data, items = plan({"mode": "mine", "keys": ["ssh-ed25519 AAAA a"]})
    nl1 = {i.fix_id: i for i in by_node(data, items)["nl-1"]}
    nl1["ssh.key_only"].selected = False
    follow_admin_key(items)
    assert nl1["access.admin_keys"].selected is False
