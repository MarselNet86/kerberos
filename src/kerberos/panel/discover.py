"""Finding Remnawave on this server (tech.md §7.1).

`docker ps` finds the container of the `remnawave/backend` image, `docker
inspect` gives its published API port and the compose directory, the
version comes from /opt/app/package.json inside the container (else from
the image tag). From the panel's .env only APP_PORT and PANEL_DOMAIN are
read: the other values of that file are secrets.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

from kerberos.fixes.xui_routing import routing_info
from kerberos.host import Host

IMAGE = "remnawave/backend"
DEFAULT_PORT = 3000


@dataclass
class PanelLocation:
    api: str
    version: str
    container: str = ""
    panel_domain: Optional[str] = None
    kind: str = "remnawave"  # remnawave | 3x-ui (§7.6)
    info: dict = field(default_factory=dict)  # 3x-ui: {port, secretPath, tls, listen, sub...}


def _image_tag(image: str) -> str:
    name, _, tag = image.rpartition(":")
    return tag if name and "/" not in tag else ""


def _bind_ip(ip: str) -> str:
    return "127.0.0.1" if ip in ("", "0.0.0.0", "::", "[::]") else ip


def discover(host: Host) -> Optional[PanelLocation]:
    ps = host.run(["docker", "ps", "--format", "{{json .}}"], timeout=20)
    if not ps.ok:
        return None
    container = image = ""
    for line in ps.stdout.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and IMAGE in str(item.get("Image", "")):
            container = str(item.get("Names") or item.get("ID") or "")
            image = str(item["Image"])
            break
    if not container:
        return None
    inspect = host.run(["docker", "inspect", container], timeout=20)
    try:
        data = json.loads(inspect.stdout)[0]
    except (ValueError, IndexError, KeyError, TypeError):
        return None
    labels = (data.get("Config") or {}).get("Labels") or {}
    workdir = labels.get("com.docker.compose.project.working_dir")
    env = (
        host.read_env_keys(workdir.rstrip("/") + "/.env", ["APP_PORT", "PANEL_DOMAIN"])
        if workdir
        else {}
    )
    try:
        app_port = int(env.get("APP_PORT") or DEFAULT_PORT)
    except ValueError:
        app_port = DEFAULT_PORT
    settings = data.get("NetworkSettings") or {}
    mode = (data.get("HostConfig") or {}).get("NetworkMode") or ""
    address: Optional[str] = None
    if mode == "host":
        address = f"127.0.0.1:{app_port}"
    else:
        for binding in (settings.get("Ports") or {}).get(f"{app_port}/tcp") or []:
            if binding.get("HostPort"):
                address = f"{_bind_ip(binding.get('HostIp', ''))}:{binding['HostPort']}"
                break
        if address is None:
            for network in (settings.get("Networks") or {}).values():
                if network.get("IPAddress"):
                    address = f"{network['IPAddress']}:{app_port}"
                    break
    if address is None:
        return None
    version = _image_tag(image)
    package = host.run(["docker", "exec", container, "cat", "/opt/app/package.json"], timeout=20)
    if package.ok:
        try:
            version = str(json.loads(package.stdout).get("version") or version)
        except ValueError:
            pass
    domain = env.get("PANEL_DOMAIN") or None
    return PanelLocation(
        api=f"http://{address}/api",
        version=version or "?",
        container=container,
        panel_domain=domain,
    )


# -- 3x-ui (tech.md §7.6) ---------------------------------------------------------
XUI_DB = "/etc/x-ui/x-ui.db"
XUI_ENV = "/etc/default/x-ui"  # EnvironmentFile of the x-ui unit
XUI_BIN = "/usr/local/x-ui/x-ui"
XUI_PORT = 2053
# Keys of the 3x-ui settings table KERBEROS reads; credentials, the session
# secret and the two-factor token are never among them.
XUI_KEYS = (
    "webListen",
    "webPort",
    "webBasePath",
    "webCertFile",
    "webDomain",
    "subEnable",
    "subListen",
    "subPort",
    "subPath",
    "twoFactorEnable",
    # K29: the routing the subscription hands out; no secrets among them.
    "subEnableRouting",
    "subRoutingRules",
    "subJsonEnable",
    "subJsonRules",
)


def base_path(value: str) -> str:
    """3x-ui stores the path with or without slashes; the API wants /path/."""
    path = "/" + (value or "").strip().strip("/")
    return path if path == "/" else path + "/"


def discover_xui(host: Host) -> Optional[PanelLocation]:
    """None: no SQLite settings here (not 3x-ui, PostgreSQL since v3.1, or no sqlite3)."""
    env = host.read_env_keys(XUI_ENV, ["XUI_DB_FOLDER", "XUI_PORT"])
    folder = (env.get("XUI_DB_FOLDER") or "").rstrip("/")
    settings = host.read_settings(f"{folder}/x-ui.db" if folder else XUI_DB, XUI_KEYS)
    if settings is None:
        return None
    try:
        # From v3.4 the XUI_PORT of the unit's environment wins over the setting.
        port = int(env.get("XUI_PORT") or settings.get("webPort") or XUI_PORT)
    except ValueError:
        port = XUI_PORT
    listen = (settings.get("webListen") or "").strip()
    tls = bool((settings.get("webCertFile") or "").strip())
    address = listen if listen not in ("", "0.0.0.0", "::", "[::]") else "127.0.0.1"
    if ":" in address and not address.startswith("["):
        address = f"[{address}]"
    path = base_path(settings.get("webBasePath", "/"))
    version = "?"
    result = host.run([XUI_BIN, "-v"], timeout=10)
    match = re.search(r"(\d+\.\d+\.\d+)", result.stdout or "")
    if result.ok and match:
        version = match.group(1)
    try:
        sub_port = int(settings.get("subPort") or 0)
    except ValueError:
        sub_port = 0
    info = {
        "port": port,
        "secretPath": path != "/",
        "tls": tls,
        "listen": listen,
        "subPort": sub_port if settings.get("subEnable", "").lower() == "true" else 0,
        "twoFactor": settings.get("twoFactorEnable", "").lower() == "true",
        # Where the CLI of §10.10 writes and KERBEROS reads back; XUI_PORT pins the port.
        "db": f"{folder}/x-ui.db" if folder else XUI_DB,
        "dbFolder": folder,
        "envPort": bool(env.get("XUI_PORT")),
        "routing": routing_info(version, settings),
    }
    return PanelLocation(
        api=f"{'https' if tls else 'http'}://{address}:{port}{path}",
        version=version,
        panel_domain=(settings.get("webDomain") or "").strip() or None,
        kind="3x-ui",
        info=info,
    )
