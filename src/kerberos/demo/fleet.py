"""The demo fleet: a panel and six nodes with typical problems (tech.md §2.8).

Only documentation addresses (RFC 5737) and example.com / example.net
domains. Reality keys and shortIds are visible placeholders.
"""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path
from typing import Optional

from kerberos.demo.nodes import auth_methods_of, build_prober, build_whois, give_agent
from kerberos.host import CommandResult, FakeHost
from kerberos.nodes.fake import FakeNode, FakeTransport
from kerberos.nodes.keys import PublicKey, demo_blob
from kerberos.panel.fake import (
    FakePanel,
    new_uuid,
    raw_host,
    raw_node,
    raw_profile,
    seed_uuids,
)
from kerberos.state import State

PANEL_VERSION = "2.8.1"
PANEL_DOMAIN = "panel.example.com"
FOREIGN_SNI = "www.example.net"
CDN_DOMAIN = "cdn.example.com"


def reality(tag: str, dest: str, names: list[str], key: str) -> dict:
    return {
        "tag": tag,
        "port": 443,
        "listen": "0.0.0.0",
        "protocol": "vless",
        "settings": {"clients": [], "decryption": "none"},
        "streamSettings": {
            "network": "raw",
            "security": "reality",
            "realitySettings": {
                "dest": dest,
                "show": False,
                "xver": 0,
                "shortIds": ["", "0123456789abcdef"],
                "privateKey": key,
                "serverNames": names,
            },
        },
    }


def hysteria(tag: str, masquerade: str) -> dict:
    return {
        "tag": tag,
        "port": 443,
        "listen": "0.0.0.0",
        "protocol": "hysteria",
        "settings": {"clients": [], "version": 2},
        "streamSettings": {
            "network": "hysteria",
            "security": "tls",
            "tlsSettings": {"alpn": ["h3"], "certificates": []},
            "hysteriaSettings": {
                "version": 2,
                "masquerade": {"url": masquerade, "type": "proxy", "rewriteHost": True},
            },
        },
    }


def xhttp(tag: str, path: str) -> dict:
    return {
        "tag": tag,
        "port": 2053,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "settings": {"clients": [], "decryption": "none"},
        "streamSettings": {
            "network": "xhttp",
            "security": "none",
            "xhttpSettings": {
                "path": path,
                "mode": "auto",
                "scMaxEachPostBytes": 1000000,
                "extra": {"noSSEHeader": True},
            },
        },
    }


def profile_config(*inbounds: dict) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": list(inbounds),
        "outbounds": [
            {"tag": "DIRECT", "protocol": "freedom"},
            {"tag": "BLOCK", "protocol": "blackhole"},
        ],
        "routing": {"rules": [{"ip": ["geoip:private"], "type": "field", "outboundTag": "BLOCK"}]},
    }


USER_TEMPLATE = {
    "dns": {"servers": ["https://one.one.one.one/dns-query"]},
    "routing": {
        "rules": [
            {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
            {"type": "field", "network": "tcp,udp", "balancerTag": "auto"},
        ],
        "balancers": [{"tag": "auto", "selector": ["proxy"], "strategy": {"type": "leastPing"}}],
    },
    "outbounds": [{"tag": "direct", "protocol": "freedom"}],
    "observatory": {"subjectSelector": ["proxy"], "probeInterval": "30s"},
}


def build_panel(shape: str = "tags") -> FakePanel:
    seed_uuids(20261116)
    panel = FakePanel(shape=shape, accept_any_token=True, accept_any_login=True)
    nl1 = raw_profile(
        "NL-1",
        profile_config(
            reality("VLESS-REALITY-NL1", f"{FOREIGN_SNI}:443", [FOREIGN_SNI], "DEMO_KEY_NL1")
        ),
    )
    nl2 = raw_profile(
        "NL-2",
        profile_config(
            reality("VLESS-REALITY-NL2", f"{FOREIGN_SNI}:443", [FOREIGN_SNI], "DEMO_KEY_NL2")
        ),
    )
    de1 = raw_profile(
        "DE-1",
        profile_config(
            reality("VLESS-REALITY-DE1", "127.0.0.1:8445", ["de-1.example.com"], "DEMO_KEY_DE1"),
            hysteria("HY2-DE1", f"https://{FOREIGN_SNI}"),
        ),
    )
    fi1 = raw_profile(
        "FI-1",
        profile_config(
            reality("VLESS-REALITY-FI1", "127.0.0.1:8445", ["fi-1.example.com"], "DEMO_KEY_FI1"),
            xhttp("XHTTP-FI1", "/api/stream"),
        ),
    )
    us1 = raw_profile(
        "US-1",
        profile_config(
            reality("VLESS-REALITY-US1", f"{FOREIGN_SNI}:443", [FOREIGN_SNI], "DEMO_KEY_US1")
        ),
    )
    kz1 = raw_profile(
        "KZ-1",
        profile_config(
            reality("VLESS-REALITY-KZ1", f"{FOREIGN_SNI}:443", [FOREIGN_SNI], "DEMO_KEY_KZ1")
        ),
    )
    panel.profiles = [nl1, nl2, de1, fi1, us1, kz1]
    panel.nodes = [
        raw_node("nl-1", "203.0.113.10", "NL", nl1, users=38),
        raw_node("nl-2", "203.0.113.11", "NL", nl2, users=0),
        raw_node("de-1", "198.51.100.20", "DE", de1, users=25),
        raw_node("fi-1", "198.51.100.77", "FI", fi1, users=14),
        raw_node("us-1", "192.0.2.50", "US", us1, connected=False, disabled=True),
        raw_node("kz-1", "192.0.2.60", "KZ", kz1, users=3),
    ]
    template = {
        "uuid": new_uuid(),
        "name": "Default",
        "templateType": "XRAY_JSON",
        "templateJson": copy.deepcopy(USER_TEMPLATE),
    }
    panel.templates = [template]
    tpl = template["uuid"]
    cdn_extra = {
        "xmux": {"maxConcurrency": "16-32", "hMaxReusableSecs": "1800-3000"},
        "scMaxEachPostBytes": 1200,
        "uplinkHTTPMethod": "POST",
    }
    panel.hosts = [
        raw_host(
            shape,
            nl1,
            "VLESS-REALITY-NL1",
            "NL Reality",
            "203.0.113.10",
            sni=FOREIGN_SNI,
            tags=["NL1"],
            template_uuid=tpl,
            position=1,
        ),
        raw_host(
            shape,
            nl2,
            "VLESS-REALITY-NL2",
            "NL-2 Reality",
            "203.0.113.11",
            sni=FOREIGN_SNI,
            fingerprint="chrome",
            tags=["NL2"],
            position=2,
        ),
        raw_host(
            shape,
            de1,
            "VLESS-REALITY-DE1",
            "DE Reality",
            "198.51.100.20",
            sni="de-1.example.com",
            fingerprint="chrome",
            tags=["DE1"],
            template_uuid=tpl,
            position=3,
        ),
        raw_host(
            shape,
            de1,
            "HY2-DE1",
            "DE Hysteria2",
            "198.51.100.20",
            sni="de-1.example.com",
            fingerprint="chrome",
            tags=["DE1"],
            position=4,
        ),
        raw_host(
            shape,
            de1,
            "VLESS-REALITY-DE1",
            "NL-2 reserve",
            "198.51.100.20",
            sni="de-1.example.com",
            fingerprint="chrome",
            tags=["NL2"],
            hidden=True,
            position=5,
        ),
        raw_host(
            shape,
            fi1,
            "VLESS-REALITY-FI1",
            "FI Reality",
            "198.51.100.77",
            sni="fi-1.example.com",
            fingerprint="chrome",
            tags=["FI1"],
            position=6,
        ),
        raw_host(
            shape,
            fi1,
            "XHTTP-FI1",
            "FI CDN",
            CDN_DOMAIN,
            sni=CDN_DOMAIN,
            fingerprint="chrome",
            tags=["FI1"],
            extra=cdn_extra,
            position=7,
        ),
        raw_host(
            shape,
            us1,
            "VLESS-REALITY-US1",
            "US Reality",
            "192.0.2.50",
            sni=FOREIGN_SNI,
            fingerprint="chrome",
            position=8,
        ),
        raw_host(
            shape,
            kz1,
            "VLESS-REALITY-KZ1",
            "KZ Reality",
            "kz-1.example.com",
            sni=FOREIGN_SNI,
            fingerprint="chrome",
            position=9,
        ),
        raw_host(
            shape,
            nl2,
            "VLESS-REALITY-NL2",
            "NL-1 reserve",
            "203.0.113.11",
            sni=FOREIGN_SNI,
            fingerprint="chrome",
            tags=["NL1"],
            hidden=True,
            position=10,
        ),
    ]
    reality_inbounds = [
        i
        for p in panel.profiles
        for i in p["inbounds"]
        if i["type"] == "vless" and i["security"] == "reality"
    ]
    panel.squads = [
        {"uuid": new_uuid(), "name": "Default-Squad", "inbounds": copy.deepcopy(reality_inbounds)}
    ]
    panel.sub_settings = {
        "uuid": new_uuid(),
        "customResponseHeaders": {"profile-update-interval": "12"},
    }
    return panel


def build_host() -> FakeHost:
    """The panel server of the demo: docker with Remnawave, its .env."""
    host = FakeHost(name="panel")
    ps = "\n".join(
        json.dumps(item)
        for item in (
            {
                "ID": "a1b2c3d4e5f6",
                "Image": f"remnawave/backend:{PANEL_VERSION}",
                "Names": "remnawave",
                "Ports": "127.0.0.1:3000->3000/tcp",
            },
            {"ID": "b2c3d4e5f6a1", "Image": "postgres:17", "Names": "remnawave-db"},
            {"ID": "c3d4e5f6a1b2", "Image": "valkey/valkey:8.1", "Names": "remnawave-redis"},
        )
    )
    host.on(["docker", "ps"], CommandResult(0, ps + "\n"))
    inspect = [
        {
            "Config": {"Labels": {"com.docker.compose.project.working_dir": "/opt/remnawave"}},
            "HostConfig": {"NetworkMode": "remnawave-network"},
            "NetworkSettings": {
                "Ports": {"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3000"}]},
                "Networks": {"remnawave-network": {"IPAddress": "172.30.0.4"}},
            },
        }
    ]
    host.on(["docker", "inspect", "remnawave"], CommandResult(0, json.dumps(inspect)))
    host.on(
        ["docker", "exec", "remnawave", "cat", "/opt/app/package.json"],
        CommandResult(0, json.dumps({"name": "@remnawave/backend", "version": PANEL_VERSION})),
    )
    host.on(["ssh-keygen"], _keygen)
    host.on(["sshd", "-T"], CommandResult(0, "port 22\npasswordauthentication yes\n"))
    admin = demo_blob("admin-laptop")
    host.files["/root/.ssh/authorized_keys"] = f"ssh-ed25519 {admin} admin@laptop\n"
    host.files["/opt/remnawave/.env"] = (
        f"APP_PORT=3000\nPANEL_DOMAIN={PANEL_DOMAIN}\nJWT_AUTH_SECRET=demo-value-never-read\n"
    )
    return host


PANEL_IP = "198.51.100.5"  # the panel server as the nodes see it


def build_nodes() -> list[FakeNode]:
    """Six nodes; nl-1 and nl-2 share a host key (an image of the hoster)."""
    shared = PublicKey("ssh-ed25519", demo_blob("hoster-image"))
    nodes = [
        FakeNode("nl-1", "203.0.113.10", shared, panel_ip=PANEL_IP),
        FakeNode("nl-2", "203.0.113.11", shared, panel_ip=PANEL_IP),
        FakeNode(
            "de-1",
            "198.51.100.20",
            PublicKey("ssh-ed25519", demo_blob("de-1")),
            python=False,
            panel_ip=PANEL_IP,
        ),
        FakeNode(
            "fi-1",
            "198.51.100.77",
            PublicKey("ssh-ed25519", demo_blob("fi-1")),
            root_keys=True,
            panel_ip=PANEL_IP,
        ),
        FakeNode(
            "us-1",
            "192.0.2.50",
            PublicKey("ssh-ed25519", demo_blob("us-1")),
            reachable=False,
            panel_ip=PANEL_IP,
        ),
        FakeNode(
            "kz-1",
            "192.0.2.60",
            PublicKey("ssh-ed25519", demo_blob("kz-1")),
            reachable=False,
            panel_ip=PANEL_IP,
        ),
    ]
    for node in nodes:
        give_agent(node)
    return nodes


def _keygen(argv, _input) -> CommandResult:
    """ssh-keygen of the demo: a fake key pair in the demo state directory."""
    path = Path(argv[argv.index("-f") + 1])
    comment = argv[argv.index("-C") + 1]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("demo private key: not a real key\n", encoding="utf-8")
    blob = demo_blob(str(path))
    path.with_suffix(".pub").write_text(f"ssh-ed25519 {blob} {comment}\n", encoding="utf-8")
    return CommandResult(0)


def attach(env, state_root: Optional[Path] = None) -> None:
    """Point the ports of `env` at the demo fleet; state goes to a temporary directory."""
    env.host = build_host()
    env.panel_transport = build_panel()
    root = state_root or Path(tempfile.mkdtemp(prefix="kerberos-demo-"))
    env.state = State(root)
    env.transport = FakeTransport(build_nodes(), env.state)
    env.prober = build_prober(env.panel_transport, list(env.transport.nodes.values()))
    env.prober.auth = auth_methods_of(list(env.transport.nodes.values()))
    env.whois = build_whois()
    from kerberos.demo.xui import attach_xui

    attach_xui(env)
