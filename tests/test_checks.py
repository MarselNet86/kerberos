"""Checks of tech.md §10.2 on the demo fleet (K3 acceptance).

Every check finds something on the demo fleet and passes once the data is
fixed. Explanations (host.ip_check, dpi.fragment, dpi.mtu) are always shown.
"""

import copy
import ipaddress

import pytest
from demo_input import demo_input

from kerberos.checks import REGISTRY, run_checks, spec
from kerberos.checks.rules import profile_differences
from kerberos.probe import HttpResult, TlsResult
from kerberos.templates import PROFILE, load
from kerberos.whois import AsInfo

EXPLANATIONS = {"host.ip_check", "dpi.fragment", "dpi.mtu"}
SECTION_10_2 = {
    "fleet.same_asn", "fleet.same_24", "fleet.shared_hostkey", "fleet.one_zone", "host.ip_check",
    "reality.foreign_sni", "probe.no_sni", "hy2.foreign_masquerade", "profile.template",
    "site.same_template", "ssh.password", "ssh.port_default", "ssh.fail2ban", "kernel.mptcp",
    "node_api.public", "ports.public", "cdn.origin_direct", "panel.public", "panel_server.ssh",
    "client.ping_type", "node.icmp", "xhttp.padding", "xhttp.uplink_get", "xhttp.post_size",
    "xhttp.extra_outer", "host.fingerprint", "dpi.fragment", "dpi.mtu", "sub.ru_direct",
    "sub.probe_interval", "exit.ru_traffic", "reserve.missing", "reserve.same_asn",
    "node.blocked", "watch.missing", "ssh.open",
}  # fmt: skip
XUI_ONLY = {"xui.panel_exposed", "xui.panel_tls", "xui.panel_2fa", "xui.sub_ru_direct"}  # §7.6
# K17: findings only on nodes with renewals on :80 or the site of KERBEROS; the demo fleet has
# neither, so its score (38 → 77, §12.4) stays. Covered in test_renewal_checks.py.
RENEWALS = {"acme.port80", "acme.stop_hook"}
# K24: a finding only on a node whose profile was deleted; the demo fleet has none, so its
# score stays. Covered in test_own_profile.py.
PROFILELESS = {"node.no_profile"}
# K26: a finding only on a node whose network is registered in Russia; the demo fleet has
# none, so its score stays. Covered in test_no_common_signature.py.
RU_HOSTER = {"host.ru_hoster"}


@pytest.fixture(scope="module")
def demo():
    return demo_input()


def results(data, check_id):
    return [f for f in spec(check_id).rule(data) if f["checkId"] == check_id]


def test_registry_is_section_10_2():
    run_checks(demo_input()[1])  # registers the rules
    others = XUI_ONLY | RENEWALS | PROFILELESS | RU_HOSTER
    assert {item.check_id for item in REGISTRY} == SECTION_10_2 | others


@pytest.mark.parametrize("check_id", sorted(SECTION_10_2))
def test_every_check_finds_something_on_the_demo_fleet(demo, check_id):
    _env, data = demo
    found = results(data, check_id)
    assert any(not f["ok"] for f in found), check_id


# -- fixing the data, check by check ---------------------------------------
def nodes(data):
    return [n for n in data.nodes if n.facts is not None]


def fix_facts(data, update):
    for item in nodes(data):
        update(item.facts)


def own_domain(data, item):
    name = f"{item.node.name}.example.com"
    data.dns[name] = [item.ipv4]
    return name


def fix_profiles(data):
    """Every node profile becomes the template with its own domain."""
    for item in data.nodes:
        profile = data.snapshot.node_profile(item.node)
        domain = own_domain(data, item)
        config = load(PROFILE)
        reality, hy2 = config["inbounds"]
        old = profile.config["inbounds"]
        reality["tag"] = old[0].get("tag")
        reality["streamSettings"]["realitySettings"]["serverNames"] = [domain]
        old_hy2 = [i["tag"] for i in old if i.get("protocol") == "hysteria"]
        hy2["tag"] = old_hy2[0] if old_hy2 else f"HY2-{item.node.name.upper()}"
        hy2["streamSettings"]["tlsSettings"]["certificates"][0] = {
            "keyFile": f"/etc/letsencrypt/live/{domain}/privkey.pem",
            "certificateFile": f"/etc/letsencrypt/live/{domain}/fullchain.pem",
        }
        hy2["streamSettings"]["hysteriaSettings"]["masquerade"]["url"] = f"https://{domain}"
        extra = [i for i in profile.config["inbounds"] if i.get("protocol") not in ("vless",
                 "hysteria") or i["streamSettings"].get("network") == "xhttp"]  # fmt: skip
        config["inbounds"] += copy.deepcopy(extra)
        profile.config = config


def fix_same_24(data):
    for i, item in enumerate(data.nodes):
        item.ipv4 = f"198.18.{i * 4}.1"  # benchmarking range: far apart /24s


def fix_asn(data):
    for i, item in enumerate(data.nodes):
        data.asn[item.ipv4] = AsInfo(str(64496 + i), f"AS{i}", item.node.country)


def fix_hostkeys(data):
    for item in nodes(data):
        item.facts["hostKeys"] = [{"type": "ED25519", "fingerprint": f"SHA256:{item.node.name}"}]


def fix_zone(data):
    data.dns["kz-1.example.com"] = []


def fix_no_sni(data):
    for item in data.nodes:
        domain = own_domain(data, item)
        data.tls[item.ipv4] = TlsResult(True, [domain])
        data.pages[(item.ipv4, 443, domain, "/")] = HttpResult(200)


def fix_sites(data):
    for i, item in enumerate(data.nodes):
        for site in item.sites.values():
            site["template"] = f"template-{i}"


def fix_ports(data):
    for item in nodes(data):
        item.facts["listening"] = [s for s in item.facts["listening"] if s["port"] != 8080]


def fix_cdn(data):
    data.pages = {k: v for k, v in data.pages.items() if k[3] not in ("/api/stream", "/cdn-check")}


def fix_xhttp(key, value):
    def fix(data):
        for host in data.snapshot.hosts:
            if host.xhttp_extra is not None:
                host.xhttp_extra[key] = value

    return fix


def fix_padding(data):
    fix_xhttp("xPaddingBytes", "100-1000")(data)
    for profile in data.snapshot.profiles:
        for inbound in profile.config.get("inbounds", []):
            settings = inbound.get("streamSettings", {}).get("xhttpSettings")
            if settings is not None:
                settings.setdefault("extra", {})["xPaddingBytes"] = "100-1000"


def fix_extra_outer(data):
    for profile in data.snapshot.profiles:
        for inbound in profile.config.get("inbounds", []):
            settings = inbound.get("streamSettings", {}).get("xhttpSettings")
            if settings is not None:
                settings.pop("scMaxEachPostBytes", None)


def fix_fingerprints(data):
    for host in data.snapshot.hosts:
        host.fingerprint = host.fingerprint or "firefox"


def fix_templates(data):
    for template in data.snapshot.templates:
        template.json = load("subscription-reserve.json")


def fix_reserves(data):
    for item in data.nodes:
        for host in data.snapshot.node_hosts(item.node):
            if not host.is_hidden:
                host.tags = ["PAIR"]
    for host in data.snapshot.hosts:
        if host.is_hidden:
            host.tags = ["PAIR"]


def fix_blocked(data):
    for node in data.snapshot.nodes:
        node.users_online = max(node.users_online, 1)
    for item in data.nodes:
        if item.watch:
            item.watch["v4"]["cut"] = 0


FIXERS = {
    "fleet.same_asn": fix_asn,
    "fleet.same_24": fix_same_24,
    "fleet.shared_hostkey": fix_hostkeys,
    "fleet.one_zone": fix_zone,
    "reality.foreign_sni": fix_profiles,
    "probe.no_sni": fix_no_sni,
    "hy2.foreign_masquerade": fix_profiles,
    "profile.template": fix_profiles,
    "site.same_template": fix_sites,
    "ssh.password": lambda d: fix_facts(d, lambda f: f["ssh"].update(
        passwordAuthentication=False, kbdInteractive=False, permitRootLogin="prohibit-password")),
    "ssh.port_default": lambda d: fix_facts(d, lambda f: f["ssh"].update(ports=[24622])),
    "ssh.fail2ban": lambda d: fix_facts(d, lambda f: f.update(fail2ban={
        "installed": True, "sshdJail": True, "jailPorts": f["ssh"]["ports"]})),
    "kernel.mptcp": lambda d: fix_facts(d, lambda f: f["mptcp"].update(enabled=False)),
    "node_api.public": lambda d: fix_facts(d, lambda f: f["nodeApi"].update(panelOnly=True)),
    "ports.public": fix_ports,
    "cdn.origin_direct": fix_cdn,
    "panel.public": lambda d: setattr(d, "panel_page", HttpResult(401)),
    "panel_server.ssh": lambda d: d.panel_ssh.update(passwordauthentication="no"),
    "client.ping_type": lambda d: d.snapshot.sub_settings.headers.update(
        {"ping-type": "proxy-head"}),
    "node.icmp": lambda d: d.pings.update({ip: False for ip in d.pings}),
    "xhttp.padding": fix_padding,
    "xhttp.uplink_get": fix_xhttp("uplinkHTTPMethod", "GET"),
    "xhttp.post_size": fix_xhttp("scMaxEachPostBytes", 1000000),
    "xhttp.extra_outer": fix_extra_outer,
    "host.fingerprint": fix_fingerprints,
    "sub.ru_direct": fix_templates,
    "sub.probe_interval": fix_templates,
    "exit.ru_traffic": lambda d: [n.watch["xray"].update(ruShare=0.0) for n in d.nodes if n.watch],
    "reserve.missing": fix_reserves,
    "reserve.same_asn": fix_asn,
    "node.blocked": fix_blocked,
    "watch.missing": lambda d: fix_facts(d, lambda f: f.update(watch={"installed": True})),
    "ssh.open": lambda d: fix_facts(d, lambda f: f["ssh"].update(guarded=f["ssh"]["ports"])),
}  # fmt: skip


def test_fixers_cover_every_check_but_explanations():
    assert set(FIXERS) == SECTION_10_2 - EXPLANATIONS


@pytest.mark.parametrize("check_id", sorted(FIXERS))
def test_check_passes_after_the_data_is_fixed(check_id):
    _env, data = demo_input()
    FIXERS[check_id](data)
    found = results(data, check_id)
    assert found, f"{check_id}: no finding left to judge"
    assert all(f["ok"] for f in found), [f for f in found if not f["ok"]]


def test_template_profile_has_no_differences():
    config = load(PROFILE)
    config["inbounds"][1]["streamSettings"]["tlsSettings"]["certificates"][0] = {
        "keyFile": "/etc/letsencrypt/live/a.example.com/privkey.pem",
        "certificateFile": "/etc/letsencrypt/live/a.example.com/fullchain.pem",
    }
    config["inbounds"][1]["streamSettings"]["hysteriaSettings"]["masquerade"]["url"] = (
        "https://a.example.com"
    )
    assert profile_differences(config) == []


def test_nodes_without_access_get_only_panel_side_checks():
    _env, data = demo_input()
    kz = next(f for f in run_checks(data) if f["target"].endswith(
        next(n.node.uuid for n in data.nodes if n.node.name == "kz-1")))  # fmt: skip
    agent_checks = {"ssh.password", "kernel.mptcp", "ports.public", "watch.missing"}
    kz_uuid = next(n.node.uuid for n in data.nodes if n.node.name == "kz-1")
    kz_checks = {f["checkId"] for f in run_checks(data) if f["target"] == f"node:{kz_uuid}"}
    assert kz and not kz_checks & agent_checks
    assert "reality.foreign_sni" in kz_checks


def test_without_whois_no_as_checks():
    _env, data = demo_input(whois=False)
    ids = {f["checkId"] for f in run_checks(data)}
    assert "fleet.same_asn" not in ids and "reserve.same_asn" not in ids


def test_evidence_has_no_secrets():
    env, data = demo_input()
    text = repr(run_checks(data))
    assert "DEMO_KEY" not in text and "admin-password" not in text
    for item in data.nodes:
        assert all(ipaddress.ip_address(ip) for ip in data.node_ips(item))
