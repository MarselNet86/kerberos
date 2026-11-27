"""The checks of tech.md §10.2, topic by topic. Pure functions of CheckInput."""

from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import urlsplit

from kerberos import templates
from kerberos.checks import (
    CheckInput,
    NodeData,
    check,
    finding,
    host_target,
    hysteria_inbounds,
    is_ip,
    node_target,
    reality_inbounds,
    reality_settings,
    stream,
    xhttp_inbounds,
)
from kerberos.fixes.model import Finding
from kerberos.fixes.xhttp import effective, inbound_extra
from kerberos.panel.model import Host, PanelSnapshot

# Hosts, templates, squads, reserves and subscription settings exist only in
# Remnawave; with 3x-ui these checks have nothing to look at (tech.md §7.6).
REMNAWAVE = ("remnawave",)
LOCAL_DEST = re.compile(r"^(127\.0\.0\.1|localhost|\[::1\]|::1):\d+$|^/|^@")


def ssh_ports(data: NodeData) -> list:
    return list((data.facts or {}).get("ssh", {}).get("ports") or [])


def with_facts(data: CheckInput) -> list[NodeData]:
    return [n for n in data.nodes if n.facts is not None]


def zone_of(name: str) -> str:
    labels = name.lower().rstrip(".").split(".")
    return ".".join(labels[-2:])


def seconds(value) -> Optional[float]:
    """Xray durations: 60s, 1m, 500ms, 1h, or a number of seconds."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h)?\s*", str(value or ""))
    if not match:
        return None
    number = float(match.group(1))
    return number * {"ms": 0.001, "s": 1, "m": 60, "h": 3600, None: 1}[match.group(2)]


def node_hosts(data: CheckInput, node_data: NodeData) -> list[Host]:
    return data.snapshot.node_hosts(node_data.node)


def behind_cdn(data: CheckInput, node_data: NodeData, host: Host) -> bool:
    """A host whose address is not the node itself: an edge server in front of it."""
    if not host.address:
        return False
    ips = data.node_ips(node_data)
    if is_ip(host.address):
        return host.address not in ips
    return not data.resolves_to(host.address, ips)


# == Topic 1. Hosting and AS ===================================================
@check("fleet.same_asn", "hosting", "medium", None, "manual")
def same_asn(data: CheckInput) -> list[Finding]:
    if data.asn is None:
        return []
    groups: dict = {}
    for item in data.nodes:
        info = data.asn.get(item.ipv4 or "")
        if info is not None:
            groups.setdefault((item.node.country, info.asn), []).append(item)
    result = []
    for (country, asn), members in groups.items():
        names = [m.node.name for m in members]
        for member in members:
            evidence = {"asn": asn, "country": country, "nodes": names}
            result.append(finding("fleet.same_asn", node_target(member.node), len(members) < 2,
                                  evidence))  # fmt: skip
    return result


@check("host.ru_hoster", "hosting", "medium", None, "manual")
def ru_hoster(data: CheckInput) -> list[Finding]:
    """K26: the network of the node is registered in Russia (the CC of whois), while the
    panel puts the node elsewhere: its hoster answers to Russian law. A finding only where
    it is so, so the score of other fleets stays; a node the panel puts in Russia (the
    entry of a cascade) is meant to be there."""
    if data.asn is None:
        return []
    result = []
    for item in data.nodes:
        info = data.asn.get(item.ipv4 or "")
        if info is None or info.country.upper() != "RU" or item.node.country.upper() == "RU":
            continue
        result.append(finding("host.ru_hoster", node_target(item.node), False,
                              {"asn": info.asn, "name": info.name}))  # fmt: skip
    return result


@check("fleet.same_24", "hosting", "medium", None, "manual")
def same_24(data: CheckInput) -> list[Finding]:
    nets = {}
    for item in data.nodes:
        if item.ipv4:
            nets[item.node.uuid] = int(ipaddress.IPv4Address(item.ipv4)) >> 8
    result = []
    for item in data.nodes:
        if item.node.uuid not in nets:
            continue
        mine = nets[item.node.uuid]
        close = [
            other.node.name
            for other in data.nodes
            if other is not item
            and other.node.uuid in nets
            and abs(nets[other.node.uuid] - mine) <= 1
        ]
        net = str(ipaddress.ip_network(f"{item.ipv4}/24", strict=False))
        result.append(finding("fleet.same_24", node_target(item.node), not close,
                              {"net": net, "with": close}))  # fmt: skip
    return result


@check("fleet.shared_hostkey", "hosting", "medium", "hostkeys.regenerate", "fix")
def shared_hostkey(data: CheckInput) -> list[Finding]:
    keys: dict = {}
    for item in with_facts(data):
        for key in item.facts.get("hostKeys", []):
            if key.get("type") == "ED25519":
                keys.setdefault(key["fingerprint"], []).append(item.node.name)
    result = []
    for item in with_facts(data):
        fingerprint = next((k["fingerprint"] for k in item.facts.get("hostKeys", [])
                            if k.get("type") == "ED25519"), None)  # fmt: skip
        if fingerprint is None:
            continue
        others = [n for n in keys[fingerprint] if n != item.node.name]
        result.append(finding("fleet.shared_hostkey", node_target(item.node), not others,
                              {"fingerprint": fingerprint, "with": others}))  # fmt: skip
    return result


@check("fleet.one_zone", "hosting", "medium", None, "manual")
def one_zone(data: CheckInput) -> list[Finding]:
    if len(data.nodes) < 3:
        return []
    zones: dict = {}
    for item in data.nodes:
        for zone in {zone_of(d) for d in data.own_domains(item)}:
            zones.setdefault(zone, []).append(item.node.name)
    crowded = {z: names for z, names in zones.items() if len(names) >= 3}
    if not crowded:
        return [finding("fleet.one_zone", "fleet", True)]
    return [
        finding("fleet.one_zone", "fleet", False, {"zone": zone, "nodes": names})
        for zone, names in sorted(crowded.items())
    ]


@check("host.ip_check", "hosting", "info", None, "explain")
def ip_check(data: CheckInput) -> list[Finding]:
    return [finding("host.ip_check", "fleet", False)] if data.nodes else []


# == Topic 2. Own SNI instead of a foreign one =================================
@check("reality.foreign_sni", "sni", "high", "self_steal", "fix")
def foreign_sni(data: CheckInput) -> list[Finding]:
    result = []
    for item in data.nodes:
        for inbound in reality_inbounds(data.snapshot, item.node):
            settings = reality_settings(inbound)
            dest = str(settings.get("dest") or settings.get("target") or "")
            names = [n for n in settings.get("serverNames") or [] if isinstance(n, str)]
            own = [n for n in names if data.resolves_to(n, data.node_ips(item))]
            ok = bool(LOCAL_DEST.match(dest)) and bool(own)
            evidence = {"inbound": inbound.get("tag"), "dest": dest, "serverNames": names}
            result.append(finding("reality.foreign_sni", node_target(item.node), ok, evidence))
    return result


@check("probe.no_sni", "sni", "medium", "self_steal", "fix")
def no_sni(data: CheckInput) -> list[Finding]:
    result = []
    for item in data.nodes:
        if not item.ipv4 or not reality_inbounds(data.snapshot, item.node):
            continue
        tls = data.tls.get(item.ipv4)
        if tls is None:
            continue
        own = [n for n in tls.names if data.resolves_to(n, data.node_ips(item))]
        status = None
        if own:
            page = data.pages.get((item.ipv4, 443, own[0], "/"))
            status = page.status if page else None
        ok = tls.ok and bool(own) and status == 200
        evidence = {"certificate": tls.names[:3], "error": tls.error, "status": status}
        result.append(finding("probe.no_sni", node_target(item.node), ok, evidence))
    return result


@check("node.no_profile", "sni", "medium", "self_steal", "fix", panels=REMNAWAVE)
def no_profile(data: CheckInput) -> list[Finding]:
    """K24: a node whose profile was deleted runs nothing for clients; its own domain gives
    it a profile. Nodes with a profile get no finding: the score of a fleet stays."""
    return [
        finding("node.no_profile", node_target(item.node), False, {})
        for item in data.nodes
        if not item.node.is_disabled and data.snapshot.node_profile(item.node) is None
    ]


@check("hy2.foreign_masquerade", "sni", "medium", "self_steal", "fix", panels=REMNAWAVE)
def foreign_masquerade(data: CheckInput) -> list[Finding]:
    result = []
    for item in data.nodes:
        for inbound in hysteria_inbounds(data.snapshot, item.node):
            masquerade = (stream(inbound).get("hysteriaSettings") or {}).get("masquerade") or {}
            url = str(masquerade.get("url") or "")
            host = urlsplit(url).hostname or ""
            ok = bool(host) and data.resolves_to(host, data.node_ips(item))
            result.append(finding("hy2.foreign_masquerade", node_target(item.node), ok,
                                  {"inbound": inbound.get("tag"), "masquerade": url}))  # fmt: skip
    return result


def profile_differences(config: dict) -> list[str]:
    """Protected parts of a node profile that differ from templates/profile.json."""
    tpl = templates.load(templates.PROFILE)
    diffs = []
    if config.get("dns") != tpl["dns"]:
        diffs.append("dns")
    outbounds = {(o.get("tag"), o.get("protocol")) for o in config.get("outbounds") or []
                 if isinstance(o, dict)}  # fmt: skip
    if not {(o["tag"], o["protocol"]) for o in tpl["outbounds"]} <= outbounds:
        diffs.append("outbounds")
    rules = (config.get("routing") or {}).get("rules") or []
    if not all(rule in rules for rule in tpl["routing"]["rules"]):
        diffs.append("routing")
    inbounds = [i for i in config.get("inbounds") or [] if isinstance(i, dict)]
    reality = [i for i in inbounds if stream(i).get("security") == "reality"]
    tpl_reality = reality_settings(tpl["inbounds"][0])
    if not reality or any(
        reality_settings(i).get("dest") != tpl_reality["dest"]
        or "" not in (reality_settings(i).get("shortIds") or [])
        or i.get("sniffing") != tpl["inbounds"][0]["sniffing"]
        for i in reality
    ):
        diffs.append("reality")
    hysteria = [i for i in inbounds if i.get("protocol") == "hysteria"]
    good_hy2 = False
    for inbound in hysteria:
        certs = (stream(inbound).get("tlsSettings") or {}).get("certificates") or []
        url = ((stream(inbound).get("hysteriaSettings") or {}).get("masquerade") or {}).get("url")
        match = re.match(r"^/etc/letsencrypt/live/([^/]+)/", str((certs or [{}])[0].get(
            "certificateFile", "")))  # fmt: skip
        if match and url == f"https://{match.group(1)}":
            good_hy2 = True
    if not good_hy2:
        diffs.append("hysteria2")
    return diffs


@check("profile.template", "sni", "medium", "self_steal", "fix", panels=REMNAWAVE)
def profile_template(data: CheckInput) -> list[Finding]:
    result = []
    seen = set()
    for item in data.nodes:
        profile = data.snapshot.node_profile(item.node)
        if profile is None or profile.uuid in seen:
            continue
        seen.add(profile.uuid)
        diffs = profile_differences(profile.config)
        result.append(finding("profile.template", node_target(item.node), not diffs,
                              {"profile": profile.name, "differs": diffs}))  # fmt: skip
    return result


@check("site.same_template", "sni", "medium", "self_steal.site", "fix")
def same_template(data: CheckInput) -> list[Finding]:
    templates_by_node = {}
    for item in data.nodes:
        hashes = {s["template"] for s in item.sites.values() if s and s.get("template")}
        if hashes:
            templates_by_node[item.node.uuid] = hashes
    result = []
    for item in data.nodes:
        mine = templates_by_node.get(item.node.uuid)
        if not mine:
            continue
        same = [
            other.node.name for other in data.nodes
            if other is not item and mine & templates_by_node.get(other.node.uuid, set())
        ]  # fmt: skip
        result.append(finding("site.same_template", node_target(item.node), not same,
                              {"template": sorted(mine)[0], "with": same}))  # fmt: skip
    return result


# == Topic 3. Scanning ===========================================================
@check("ssh.password", "scanning", "high", "ssh.key_only", "fix")
def ssh_password(data: CheckInput) -> list[Finding]:
    result = []
    for item in with_facts(data):
        ssh = item.facts.get("ssh", {})
        bad = (
            ssh.get("passwordAuthentication")
            or ssh.get("kbdInteractive")
            or ssh.get("permitRootLogin") == "yes"
        )
        evidence = {
            "passwordAuthentication": ssh.get("passwordAuthentication"),
            "kbdInteractive": ssh.get("kbdInteractive"),
            "permitRootLogin": ssh.get("permitRootLogin"),
            "adminKeys": ssh.get("adminKeys"),
        }
        result.append(finding("ssh.password", node_target(item.node), not bad, evidence))
    return result


@check("ssh.port_default", "scanning", "medium", "ssh.port", "fix")
def ssh_port_default(data: CheckInput) -> list[Finding]:
    return [
        finding("ssh.port_default", node_target(item.node), 22 not in ssh_ports(item),
                {"ports": ssh_ports(item)})
        for item in with_facts(data)
    ]  # fmt: skip


@check("ssh.fail2ban", "scanning", "medium", "fail2ban.sshd", "fix")
def ssh_fail2ban(data: CheckInput) -> list[Finding]:
    result = []
    for item in with_facts(data):
        f2b = item.facts.get("fail2ban", {})
        uncovered = sorted(set(ssh_ports(item)) - set(f2b.get("jailPorts") or []))
        ok = bool(f2b.get("installed") and f2b.get("sshdJail")) and not uncovered
        evidence = {"installed": f2b.get("installed"), "sshdJail": f2b.get("sshdJail"),
                    "uncovered": uncovered}  # fmt: skip
        result.append(finding("ssh.fail2ban", node_target(item.node), ok, evidence))
    return result


@check("kernel.mptcp", "scanning", "high", "mptcp.guard", "fix")
def kernel_mptcp(data: CheckInput) -> list[Finding]:
    result = []
    for item in with_facts(data):
        mptcp = item.facts.get("mptcp", {})
        evidence = {"enabled": mptcp.get("enabled"), "sockets": mptcp.get("sockets", 0),
                    "xray": (item.facts.get("remnanode") or {}).get("xrayVersion")}  # fmt: skip
        result.append(finding("kernel.mptcp", node_target(item.node), not mptcp.get("enabled"),
                              evidence))  # fmt: skip
    return result


@check("node_api.public", "scanning", "medium", "node_api.panel_only", "fix")
def node_api_public(data: CheckInput) -> list[Finding]:
    result = []
    for item in with_facts(data):
        api = item.facts.get("nodeApi", {})
        if not api.get("port"):
            continue
        evidence = {"port": api.get("port"), "otherPeers": api.get("otherPeers", 0),
                    "network": (item.facts.get("remnanode") or {}).get("network")}  # fmt: skip
        result.append(finding("node_api.public", node_target(item.node), bool(api.get("panelOnly")),
                              evidence))  # fmt: skip
    return result


# Client sockets, not services: a DHCP client waits for the lease answers on 68/udp (546/udp
# for DHCPv6) and systemd-timesyncd keeps an unconnected UDP socket for NTP replies. A drop
# rule there gains nothing and cuts the renewal of the node's address (K19).
UDP_CLIENT_PORTS = {68, 546}
UDP_CLIENT_PROCESSES = {"systemd-timesyn"}  # ss shows the first 15 characters of the name


def client_socket(sock: dict) -> bool:
    return sock.get("proto") == "udp" and (
        sock.get("port") in UDP_CLIENT_PORTS or sock.get("process") in UDP_CLIENT_PROCESSES
    )


def public_ports(item: NodeData, data: CheckInput) -> list[str]:
    facts = item.facts or {}
    allowed = {(443, "tcp"), (443, "udp"), (80, "tcp")}
    allowed |= {(p, "tcp") for p in ssh_ports(item)}
    api = (facts.get("nodeApi") or {}).get("port")
    if api:
        allowed.add((api, "tcp"))
    # TLS ports of nginx sites stay: an origin behind a CDN is reached there.
    allowed |= {(p, "tcp") for p in tls_listen_ports(facts)}
    # 3x-ui: its inbounds, the web panel and the subscription are public on purpose.
    allowed |= {tuple(p) for p in data.snapshot.open_ports.get(item.node.uuid, [])}
    public_addresses = {"0.0.0.0", "::", "*"} | set(data.node_ips(item))
    ports = []
    for sock in facts.get("listening", []):
        key = (sock.get("port"), sock.get("proto"))
        if (sock.get("address") in public_addresses and key not in allowed
                and not sock.get("firewalled") and not sock.get("docker")
                and not client_socket(sock)):  # fmt: skip
            label = f"{sock['port']}/{sock['proto']}"
            if label not in ports:
                ports.append(label)
    return sorted(ports, key=lambda p: int(p.split("/")[0]))


@check("ports.public", "scanning", "medium", "ports.drop", "fix")
def ports_public(data: CheckInput) -> list[Finding]:
    return [
        finding("ports.public", node_target(item.node), not ports, {"ports": ports})
        for item in with_facts(data)
        for ports in [public_ports(item, data)]
    ]


def tls_listen_ports(facts: dict) -> list[int]:
    ports = []
    for site in (facts.get("nginx") or {}).get("sites", []):
        for listen in site.get("listen", []):
            if "ssl" not in listen.split():
                continue
            address = listen.split()[0]
            if address.startswith("127.0.0.1") or address.startswith("[::1]"):
                continue
            port = address.rsplit(":", 1)[-1]
            if port.isdigit() and int(port) not in ports:
                ports.append(int(port))
    return ports


def cdn_xhttp_hosts(data: CheckInput, item: NodeData) -> list[tuple[dict, Host]]:
    pairs = []
    inbounds = {i.get("tag"): i for i in xhttp_inbounds(data.snapshot, item.node)}
    by_uuid = {i.uuid: i.tag for i in data.snapshot.node_inbounds(item.node)}
    for host in node_hosts(data, item):
        tag = by_uuid.get(host.inbound_uuid or "")
        if tag in inbounds and not host.is_disabled and behind_cdn(data, item, host):
            pairs.append((inbounds[tag], host))
    return pairs


def xhttp_path(inbound: dict, host: Host) -> str:
    path = str(host.raw.get("path") or "") or str(
        (stream(inbound).get("xhttpSettings") or {}).get("path") or "/"
    )
    return path if path.startswith("/") else "/" + path


def kerberos_sites(facts: dict) -> list:
    from kerberos.agent import SITE_CONF

    return [s for s in (facts.get("nginx") or {}).get("sites", []) if s.get("file") == SITE_CONF]


# The listener of a renewal in progress is not who holds :80 against it.
RENEWERS = ("socat", "certbot")


@check("acme.port80", "sni", "medium", None, "manual")
def acme_port80(data: CheckInput) -> list[Finding]:
    """A certificate renewed by its own listener on :80, with no hook that stops anything
    first, while another program holds the port over IPv4: the renewal fails and the
    certificate expires (§10.4, K17). A finding only where that is so."""
    result = []
    for item in with_facts(data):
        # agents before 0.10 do not say whether a hook frees the port: no data, no finding
        stuck = [r for r in item.facts.get("acme") or [] if r.get("freesPort") is False]
        holders = sorted({str(s.get("process") or "?") for s in item.facts.get("listening", [])
                          if s.get("port") == 80 and s.get("proto") == "tcp"
                          and ":" not in str(s.get("address", ""))  # IPv6 only: IPv4 is free
                          and s.get("process") not in RENEWERS})  # fmt: skip
        if not stuck or not holders:
            continue
        names = [n for r in stuck for n in r.get("names", [])]
        result.append(finding("acme.port80", node_target(item.node), False,
                              {"names": names, "holders": holders}))  # fmt: skip
    return result


@check("acme.stop_hook", "sni", "medium", None, "manual")
def acme_stop_hook(data: CheckInput) -> list[Finding]:
    """A pre-hook certbot runs before every renewal stops nginx, and the self-steal site
    renews its certificate through nginx: that renewal never passes (§10.4, K17). A finding
    only where both are so."""
    result = []
    for item in with_facts(data):
        if not (item.facts.get("certbot") or {}).get("stopsNginx"):
            continue  # agents before 0.10 do not say: no data, no finding
        sites = kerberos_sites(item.facts)
        if not sites:
            continue
        names = sorted({n for s in sites for n in s.get("serverNames", [])})
        result.append(finding("acme.stop_hook", node_target(item.node), False,
                              {"names": names}))  # fmt: skip
    return result


@check("cdn.origin_direct", "scanning", "high", "cdn.edge_only", "fix", panels=REMNAWAVE)
def cdn_origin_direct(data: CheckInput) -> list[Finding]:
    result = []
    for item in with_facts(data):
        pairs = cdn_xhttp_hosts(data, item)
        if not pairs or not item.ipv4:
            continue
        answers = []
        for inbound, host in pairs:
            name = host.sni or host.address
            for port in tls_listen_ports(item.facts):
                tunnel = data.pages.get((item.ipv4, port, name, xhttp_path(inbound, host)))
                probe = data.pages.get((item.ipv4, port, name, "/cdn-check"))
                if tunnel and tunnel.status == 400:
                    answers.append(f"{port}{xhttp_path(inbound, host)}: 400")
                if probe and probe.status == 204:
                    answers.append(f"{port}/cdn-check: 204")
        result.append(finding("cdn.origin_direct", node_target(item.node), not answers,
                              {"answers": answers}))  # fmt: skip
    return result


@check("panel.public", "scanning", "medium", "panel.portal", "fix", panels=REMNAWAVE)
def panel_public(data: CheckInput) -> list[Finding]:
    """The Remnawave login page on the panel's domain; KERBEROS puts a portal in front of
    it only behind Caddy in Docker as the Remnawave docs set it up (§10.10)."""
    from kerberos.fixes.portal import page_shows_panel

    page = data.panel_page
    if not data.snapshot.panel_domain or page is None:
        return []
    proxy = (data.panel_proxy or {}).get("proxy", "none")
    return [finding("panel.public", "panel", not page_shows_panel(page),
                    {"status": page.status, "proxy": proxy},
                    fix_id="panel.portal" if proxy == "caddy" else None)]  # fmt: skip


def xui_public(info: dict) -> bool:
    return str(info.get("listen") or "") in ("", "0.0.0.0", "::", "[::]")


@check("xui.panel_exposed", "scanning", "medium", "xui.panel_hide", "fix", panels=("3x-ui",))
def xui_panel_exposed(data: CheckInput) -> list[Finding]:
    """The 3x-ui web panel on all addresses with the default port or no secret path.

    KERBEROS moves it (§10.10) unless only the port is weak and XUI_PORT pins it.
    """
    info = data.snapshot.panel_info
    if not info:
        return []
    weak = info.get("port") == 2053 or not info.get("secretPath")
    evidence = {"port": info.get("port"), "secretPath": bool(info.get("secretPath"))}
    movable = bool(info.get("db")) and (not info.get("envPort") or not info.get("secretPath"))
    return [finding("xui.panel_exposed", "panel", not (xui_public(info) and weak), evidence,
                    fix_id="xui.panel_hide" if movable else None)]  # fmt: skip


@check("xui.panel_tls", "scanning", "low", None, "manual", panels=("3x-ui",))
def xui_panel_tls(data: CheckInput) -> list[Finding]:
    """The panel on all addresses without TLS: its login and password go in clear."""
    info = data.snapshot.panel_info
    if not info:
        return []
    return [finding("xui.panel_tls", "panel", not (xui_public(info) and not info.get("tls")),
                    {"tls": bool(info.get("tls"))})]  # fmt: skip


@check("xui.panel_2fa", "scanning", "low", None, "manual", panels=("3x-ui",))
def xui_panel_2fa(data: CheckInput) -> list[Finding]:
    info = data.snapshot.panel_info
    if not info:
        return []
    return [finding("xui.panel_2fa", "panel", bool(info.get("twoFactor")),
                    {"twoFactor": bool(info.get("twoFactor"))})]  # fmt: skip


@check("panel_server.ssh", "scanning", "high", None, "manual", panels=REMNAWAVE)
def panel_server_ssh(data: CheckInput) -> list[Finding]:
    if data.panel_ssh is None:
        return []
    password = data.panel_ssh.get("passwordauthentication") == "yes"
    return [finding("panel_server.ssh", "panel", not password,
                    {"passwordAuthentication": password})]  # fmt: skip


@check("client.ping_type", "scanning", "medium", "sub.ping_type", "fix", panels=REMNAWAVE)
def client_ping_type(data: CheckInput) -> list[Finding]:
    settings = data.snapshot.sub_settings
    if settings is None:
        return []
    has = any(k.lower() == "ping-type" for k in settings.headers)
    return [finding("client.ping_type", "panel", has,
                    {"ping-type": next((v for k, v in settings.headers.items()
                                        if k.lower() == "ping-type"), None)})]  # fmt: skip


@check("node.icmp", "scanning", "info", None, "explain")
def node_icmp(data: CheckInput) -> list[Finding]:
    return [
        finding("node.icmp", node_target(item.node), not data.pings.get(item.ipv4 or ""))
        for item in data.nodes
        if item.ipv4 and item.ipv4 in data.pings
    ]


# == Topic 4. DPI ================================================================
def has_padding(extra: Optional[dict]) -> bool:
    return bool(extra) and "xPaddingBytes" in extra


@check("xhttp.padding", "dpi", "medium", "xhttp.padding", "fix", panels=REMNAWAVE)
def xhttp_padding(data: CheckInput) -> list[Finding]:
    result = []
    for item in data.nodes:
        by_uuid = {i.uuid: i.tag for i in data.snapshot.node_inbounds(item.node)}
        for inbound in xhttp_inbounds(data.snapshot, item.node):
            server_extra = inbound_extra(inbound)
            server = has_padding(server_extra)
            hosts = [h for h in node_hosts(data, item) if by_uuid.get(h.inbound_uuid or "")
                     == inbound.get("tag") and not h.is_disabled]  # fmt: skip
            # What each client gets: its host's extra, or the inbound's when it has none.
            clients = [has_padding(effective(h.xhttp_extra, server_extra)) for h in hosts]
            complete = server and all(clients)
            partial = not complete and (server or any(clients))
            evidence = {"inbound": inbound.get("tag"), "server": server,
                        "hosts": sum(clients), "of": len(clients)}  # fmt: skip
            result.append(finding("xhttp.padding", node_target(item.node), complete, evidence,
                                  fix_id=None if partial else "default"))  # fmt: skip
    return result


@check("xhttp.uplink_get", "dpi", "medium", "xhttp.uplink_get", "fix", panels=REMNAWAVE)
def xhttp_uplink_get(data: CheckInput) -> list[Finding]:
    result = []
    for item in data.nodes:
        for inbound, host in cdn_xhttp_hosts(data, item):
            extra = effective(host.xhttp_extra, inbound_extra(inbound)) or {}
            method = str(extra.get("uplinkHTTPMethod") or "POST").upper()
            result.append(finding("xhttp.uplink_get", host_target(host), method == "GET",
                                  {"host": host.remark, "method": method}))  # fmt: skip
    return result


def max_post_bytes(value) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    numbers = [int(n) for n in re.findall(r"\d+", str(value or ""))]
    return max(numbers) if numbers else None


@check("xhttp.post_size", "dpi", "info", None, "explain", panels=REMNAWAVE)
def xhttp_post_size(data: CheckInput) -> list[Finding]:
    result = []
    for item in data.nodes:
        for inbound, host in cdn_xhttp_hosts(data, item):
            extra = effective(host.xhttp_extra, inbound_extra(inbound)) or {}
            size = max_post_bytes(extra.get("scMaxEachPostBytes"))
            if size is not None:
                evidence = {"host": host.remark, "scMaxEachPostBytes": size}
                result.append(
                    finding("xhttp.post_size", host_target(host), size >= 10_000, evidence)
                )
    return result


@check("xhttp.extra_outer", "dpi", "low", None, "manual")
def xhttp_extra_outer(data: CheckInput) -> list[Finding]:
    result = []
    for item in data.nodes:
        for inbound in xhttp_inbounds(data.snapshot, item.node):
            settings = stream(inbound).get("xhttpSettings") or {}
            outer = sorted(k for k in settings if k.startswith("sc"))
            bad = bool(outer) and isinstance(settings.get("extra"), dict)
            result.append(finding("xhttp.extra_outer", node_target(item.node), not bad,
                                  {"inbound": inbound.get("tag"), "keys": outer}))  # fmt: skip
    return result


@check("host.fingerprint", "dpi", "low", "host.fingerprint", "fix", panels=REMNAWAVE)
def host_fingerprint(data: CheckInput) -> list[Finding]:
    result = []
    seen = set()
    for item in data.nodes:
        for host in node_hosts(data, item):
            if host.is_disabled or host.uuid in seen:
                continue
            seen.add(host.uuid)
            result.append(finding("host.fingerprint", host_target(host), bool(host.fingerprint),
                                  {"host": host.remark}))  # fmt: skip
    return result


@check("dpi.fragment", "dpi", "info", None, "explain")
def dpi_fragment(data: CheckInput) -> list[Finding]:
    return [finding("dpi.fragment", "fleet", False)] if data.nodes else []


@check("dpi.mtu", "dpi", "info", None, "explain")
def dpi_mtu(data: CheckInput) -> list[Finding]:
    return [finding("dpi.mtu", "fleet", False)] if data.nodes else []


# == Topic 5. Smart routing ======================================================
def host_template(snapshot: PanelSnapshot, host: Host) -> Optional[str]:
    """The XRAY_JSON template a host's subscription is built from.

    A host without one gets the panel's default template. Nothing in the API marks it:
    KERBEROS takes the XRAY_JSON template named «Default» (any case); without one the
    host is skipped, as before.
    """
    if host.template_uuid:
        return host.template_uuid
    default = next((t for t in snapshot.templates if t.type == "XRAY_JSON"
                    and t.name.strip().lower() == "default"), None)  # fmt: skip
    return default.uuid if default is not None else None


def used_templates(data: CheckInput) -> list:
    used = []
    for item in data.nodes:
        for host in node_hosts(data, item):
            uuid = host_template(data.snapshot, host)
            if host.is_disabled or not uuid:
                continue
            template = data.snapshot.template(uuid)
            if template is not None and template.json is not None and template not in used:
                used.append(template)
    return used


CATCH_ALL_KEYS = {"type", "network", "outboundTag", "balancerTag", "ruleTag"}


def is_catch_all(rule: dict) -> bool:
    """The final rule: everything left goes to a proxy or a balancer."""
    return (
        isinstance(rule, dict)
        and set(rule) <= CATCH_ALL_KEYS
        and (str(rule.get("outboundTag", "")).lower() != "direct")
    )


def ru_direct(template_json: dict) -> dict:
    rules = (template_json.get("routing") or {}).get("rules") or []
    # Rules before the final catch-all; a template without one (no reserve) has all.
    before_final = rules[:-1] if rules and is_catch_all(rules[-1]) else rules
    found = {"geoip:ru": False, "geosite:category-ru": False}
    for rule in before_final:
        if not isinstance(rule, dict) or str(rule.get("outboundTag", "")).lower() != "direct":
            continue
        if "geoip:ru" in (rule.get("ip") or []):
            found["geoip:ru"] = True
        if "geosite:category-ru" in (rule.get("domain") or []):
            found["geosite:category-ru"] = True
    return found


@check("sub.ru_direct", "routing", "medium", "sub.template", "fix", panels=REMNAWAVE)
def sub_ru_direct(data: CheckInput) -> list[Finding]:
    result = []
    for template in used_templates(data):
        found = ru_direct(template.json)
        result.append(finding("sub.ru_direct", f"template:{template.uuid}", all(found.values()),
                              {"template": template.name, **found}))  # fmt: skip
    return result


def probe_interval(template_json: dict) -> Optional[float]:
    values = []
    burst = (template_json.get("burstObservatory") or {}).get("pingConfig") or {}
    if "interval" in burst:
        values.append(seconds(burst["interval"]))
    observatory = template_json.get("observatory") or {}
    if "probeInterval" in observatory:
        values.append(seconds(observatory["probeInterval"]))
    values = [v for v in values if v is not None]
    return min(values) if values else None


@check("sub.probe_interval", "routing", "medium", "sub.template", "fix", panels=REMNAWAVE)
def sub_probe_interval(data: CheckInput) -> list[Finding]:
    result = []
    for template in used_templates(data):
        interval = probe_interval(template.json)
        if interval is None:
            continue
        result.append(finding("sub.probe_interval", f"template:{template.uuid}", interval >= 60,
                              {"template": template.name, "seconds": interval}))  # fmt: skip
    return result


@check("exit.ru_traffic", "routing", "medium", None, "plan", panels=REMNAWAVE)
def exit_ru_traffic(data: CheckInput) -> list[Finding]:
    result = []
    for item in data.nodes:
        share = ((item.watch or {}).get("xray") or {}).get("ruShare")
        if share is None:
            continue
        result.append(finding("exit.ru_traffic", node_target(item.node), share <= 0.01,
                              {"ruShare": share}))  # fmt: skip
    return result


# == Topic 6. Reserves ===========================================================
def reserves_of(data: CheckInput, item: NodeData) -> list:
    """Nodes holding enabled hidden hosts with a tag of this node's visible hosts."""
    visible = [h for h in node_hosts(data, item) if not h.is_hidden and not h.is_disabled]
    tags = {t for h in visible for t in h.tags}
    found = []
    for other in data.snapshot.nodes:
        if other.uuid == item.node.uuid:
            continue
        hidden = [h for h in data.snapshot.node_hosts(other) if h.is_hidden and not h.is_disabled]
        if any(set(h.tags) & tags for h in hidden) and other not in found:
            found.append(other)
    return found


@check("reserve.missing", "reserves", "medium", "reserve", "plan", panels=REMNAWAVE)
def reserve_missing(data: CheckInput) -> list[Finding]:
    result = []
    for item in data.nodes:
        visible = [h for h in node_hosts(data, item) if not h.is_hidden and not h.is_disabled]
        if not visible:
            continue
        reserves = reserves_of(data, item)
        result.append(finding("reserve.missing", node_target(item.node), bool(reserves),
                              {"reserves": [r.name for r in reserves]}))  # fmt: skip
    return result


@check("reserve.same_asn", "reserves", "medium", None, "manual", panels=REMNAWAVE)
def reserve_same_asn(data: CheckInput) -> list[Finding]:
    if data.asn is None:
        return []
    result = []
    by_uuid = {n.node.uuid: n for n in data.nodes}
    for item in data.nodes:
        mine = data.asn.get(item.ipv4 or "")
        if mine is None:
            continue
        for reserve in reserves_of(data, item):
            other = by_uuid.get(reserve.uuid)
            theirs = data.asn.get(other.ipv4 or "") if other else None
            if theirs is None:
                continue
            result.append(finding("reserve.same_asn", node_target(item.node),
                                  theirs.asn != mine.asn,
                                  {"asn": mine.asn, "reserve": reserve.name}))  # fmt: skip
    return result


# Below this many connections the share of cut ones says nothing: 1 of 1 is not 100 % (K18).
MIN_WATCH_CONNECTIONS = 20


def cut_share(watch: Optional[dict], key: str = "cut") -> Optional[float]:
    """The share of connections with a sign of the watch: `cut` (silent within 1.5 KB) or
    `stalled` (frozen after ~16 KB, K27; agents before 0.11 send none: 0)."""
    if not watch:
        return None
    total = sum((watch.get(f) or {}).get("connections", 0) for f in ("v4", "v6"))
    cut = sum((watch.get(f) or {}).get(key, 0) or 0 for f in ("v4", "v6"))
    return cut / total if total >= MIN_WATCH_CONNECTIONS else None


@check("node.blocked", "reserves", "high", None, "manual")
def node_blocked(data: CheckInput) -> list[Finding]:
    result = []
    for item in data.nodes:
        if item.node.is_disabled:
            continue
        reserves = reserves_of(data, item)
        reserve_users = sum(r.users_online for r in reserves)
        by_users = item.node.users_online == 0 and reserve_users > 0
        share = cut_share(item.watch)
        stall = cut_share(item.watch, "stalled")
        by_cut = share is not None and share > 0.05
        by_stall = stall is not None and stall > 0.05
        if not reserves and share is None:
            continue
        evidence = {"usersOnline": item.node.users_online, "reserveUsers": reserve_users,
                    "cutShare": round(share, 3) if share is not None else None,
                    "stallShare": round(stall, 3) if stall is not None else None}  # fmt: skip
        blocked = by_users or by_cut or by_stall
        result.append(finding("node.blocked", node_target(item.node), not blocked, evidence))
    return result


@check("watch.missing", "reserves", "info", "watch.install", "fix")
def watch_missing(data: CheckInput) -> list[Finding]:
    return [
        finding("watch.missing", node_target(item.node),
                bool((item.facts.get("watch") or {}).get("installed")))
        for item in with_facts(data)
    ]  # fmt: skip
