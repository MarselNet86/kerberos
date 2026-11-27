"""3x-ui read as a panel (tech.md §7.6): discovery, snapshot, which checks apply."""

import json

import pytest

from kerberos.checks import CheckInput, NodeData, run_checks
from kerberos.host import CommandResult, FakeHost
from kerberos.panel import xui_model
from kerberos.panel.discover import XUI_BIN, XUI_DB, discover_xui
from kerberos.panel.errors import PanelError

REALITY = {
    "network": "tcp",
    "security": "reality",
    "realitySettings": {
        "show": False,
        "target": "www.example.net:443",
        "serverNames": ["www.example.net"],
        "privateKey": "DEMO_PRIVATE_KEY",
        "shortIds": ["", "0123abcd"],
        "settings": {"publicKey": "DEMO_PUBLIC", "fingerprint": "chrome", "serverName": ""},
    },
}


def raw_inbound(ident=1, port=443, stream=None, enable=True, protocol="vless"):
    return {
        "id": ident,
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": f"in-{ident}",
        "enable": enable,
        "expiryTime": 0,
        "listen": "",
        "port": port,
        "protocol": protocol,
        "settings": json.dumps({"clients": [], "decryption": "none"}),
        "streamSettings": json.dumps(stream if stream is not None else REALITY),
        "tag": f"inbound-{port}",
        "sniffing": json.dumps({"enabled": True}),
    }


INFO = {"port": 2053, "secretPath": False, "tls": False, "listen": "", "subPort": 2096,
        "twoFactor": False}  # fmt: skip


def snapshot(*raws, info=INFO):
    inbounds = [xui_model.inbound(r) for r in raws]
    return xui_model.snapshot("2.6.2", inbounds, "203.0.113.50", "vpn-1", info)


def test_discovery_reads_only_named_settings():
    host = FakeHost(databases={XUI_DB: {
        "webPort": "54321", "webBasePath": "secret-path", "webCertFile": "/etc/ssl/panel.pem",
        "webListen": "", "subEnable": "true", "subPort": "2096", "username": "admin",
        "password": "hunter2", "secret": "s3cr3t",
    }})  # fmt: skip
    host.on([XUI_BIN, "-v"], CommandResult(0, "2.6.2\n"))
    location = discover_xui(host)
    assert location.kind == "3x-ui" and location.version == "2.6.2"
    assert location.api == "https://127.0.0.1:54321/secret-path/"
    assert location.info == {"port": 54321, "secretPath": True, "tls": True, "listen": "",
                             "subPort": 2096, "twoFactor": False, "db": XUI_DB,
                             "dbFolder": "", "envPort": False,
                             "routing": {"happ": False, "enabled": False, "rules": "",
                                         "json": False, "jsonRules": ""}}  # fmt: skip
    assert "hunter2" not in repr(location) and "s3cr3t" not in repr(location)


def test_no_database_no_3x_ui():
    assert discover_xui(FakeHost()) is None


def test_snapshot_one_node_hosts_from_inbounds():
    snap = snapshot(raw_inbound(1, 443), raw_inbound(2, 8443, enable=False))
    assert snap.kind == "3x-ui" and [n.uuid for n in snap.nodes] == [xui_model.LOCAL]
    node = snap.nodes[0]
    assert node.address == "203.0.113.50" and node.name == "vpn-1"
    hosts = {h.uuid: h for h in snap.hosts}
    assert hosts["xui-1"].sni == "www.example.net" and hosts["xui-1"].fingerprint == "chrome"
    assert hosts["xui-2"].is_disabled
    assert snap.open_ports[xui_model.LOCAL] == [(443, "tcp"), (2053, "tcp"), (2096, "tcp")]
    reality = snap.profiles[0].inbound_config("inbound-443")["streamSettings"]["realitySettings"]
    assert reality["target"] == "www.example.net:443"


@pytest.mark.parametrize("bad", [
    {"id": "1", "port": 443, "protocol": "vless"},
    {"id": 1, "port": 0, "protocol": "vless"},
    {"id": 1, "port": 443, "protocol": ""},
    {"id": 1, "port": 443, "protocol": "vless", "streamSettings": "{not json"},
    {"id": 1, "port": 443, "protocol": "vless", "settings": "[1, 2]"},
    "inbound",
])  # fmt: skip
def test_bad_inbounds_stop_the_run(bad):
    with pytest.raises(PanelError) as err:
        xui_model.inbound(bad)
    assert err.value.code == "bad_response"


def facts(listening=(), password=False):
    return {
        "ssh": {"ports": [22], "passwordAuthentication": password, "kbdInteractive": False,
                "permitRootLogin": "prohibit-password", "adminKeys": 1, "socketActivated": False},
        "listening": [{"proto": p, "address": "0.0.0.0", "port": n, "process": "x",
                       "docker": False, "firewalled": False} for n, p in listening],
        "nodeApi": {"port": None}, "nginx": {"sites": []}, "fail2ban": {}, "mptcp": {},
        "watch": {"installed": True}, "ipv4": ["203.0.113.50"], "ipv6": [],
        "remnanode": {"present": False}, "hostKeys": [], "certbot": {"certs": []},
    }  # fmt: skip


def checked(snap, node_facts):
    node = NodeData(snap.nodes[0], access="ok", ipv4="203.0.113.50", facts=node_facts)
    return run_checks(CheckInput(snapshot=snap, nodes=[node]))


def test_panel_ports_are_not_extra_ports():
    snap = snapshot(raw_inbound(1, 443))
    found = checked(snap, facts([(443, "tcp"), (2053, "tcp"), (2096, "tcp"), (8080, "tcp")]))
    ports = next(f for f in found if f["checkId"] == "ports.public")
    assert ports["evidence"]["ports"] == ["8080/tcp"]


def test_remnawave_checks_stay_out():
    found = {f["checkId"] for f in checked(snapshot(raw_inbound(1, 443)), facts())}
    for check_id in ("profile.template", "reserve.missing", "panel_server.ssh", "panel.public",
                     "host.fingerprint", "sub.ru_direct", "client.ping_type"):  # fmt: skip
        assert check_id not in found
    assert "reality.foreign_sni" in found and "xui.panel_exposed" in found


@pytest.mark.parametrize("info, exposed, clear", [
    (INFO, True, True),
    ({**INFO, "port": 54321, "secretPath": True, "tls": True}, False, False),
    ({**INFO, "port": 54321, "secretPath": True, "tls": False}, False, True),
    ({**INFO, "port": 54321, "secretPath": False, "tls": True}, True, False),
    ({**INFO, "listen": "127.0.0.1"}, False, False),
])  # fmt: skip
def test_panel_exposed(info, exposed, clear):
    """v20: the port and the path are xui.panel_exposed, TLS is xui.panel_tls on its own."""
    found = checked(snapshot(raw_inbound(1, 443), info=info), facts())
    panel = next(f for f in found if f["checkId"] == "xui.panel_exposed")
    assert panel["ok"] is not exposed
    assert set(panel["evidence"]) == {"port", "secretPath"}, "no secret path in reports"
    tls = next(f for f in found if f["checkId"] == "xui.panel_tls")
    assert tls["ok"] is not clear
