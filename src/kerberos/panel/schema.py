"""Validation of panel answers (tech.md §7.2, §7.4, §19).

Answers come wrapped in `{response: ...}`; extra fields are ignored. A field
KERBEROS needs that is missing or of the wrong type raises
PanelError("bad_response") and the run stops before any change.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from kerberos.panel.errors import PanelError
from kerberos.panel.model import (
    Host,
    Inbound,
    Node,
    Profile,
    Squad,
    SubSettings,
    Template,
)

# Host forms: field for tags, field for XHTTP extra parameters.
HOST_SHAPES = {
    "tags": ("tags", "xhttpExtraParams"),
    "tag": ("tag", "xHttpExtraParams"),
}


# An API token is a JWT: base64url parts and dots (§7.3).
TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]+")
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def bad(what: str) -> PanelError:
    return PanelError("bad_response", detail=what)


def unwrap(payload: Any) -> Any:
    if not isinstance(payload, dict) or "response" not in payload:
        raise bad("no response wrapper")
    return payload["response"]


def items(value: Any, key: str) -> list:
    """A list answer, either bare or inside `{key: [...]}`."""
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and isinstance(value.get(key), list):
        return value[key]
    raise bad(f"expected a list of {key}")


def _str(obj: dict, key: str, *, required: bool = True, default: str = "") -> str:
    value = obj.get(key)
    if value is None:
        if required:
            raise bad(f"missing {key}")
        return default
    if not isinstance(value, str):
        raise bad(f"{key} is not a string")
    return value


def _int(obj: dict, key: str, *, required: bool = True, default: int = 0) -> int:
    value = obj.get(key)
    if value is None:
        if required:
            raise bad(f"missing {key}")
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        if isinstance(value, str) and value.isdigit():
            return int(value)
        raise bad(f"{key} is not a number")
    return value


def _bool(obj: dict, key: str, *, default: bool = False) -> bool:
    value = obj.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise bad(f"{key} is not a boolean")
    return value


def _obj(value: Any, what: str) -> dict:
    if not isinstance(value, dict):
        raise bad(f"{what} is not an object")
    return value


def access_token(raw: Any) -> str:
    """`POST /auth/login`: the admin login token (§7.4, K30)."""
    token = _str(_obj(raw, "login"), "accessToken")
    if not TOKEN_RE.fullmatch(token):
        raise bad("accessToken is not a token")
    return token


def api_token(raw: Any) -> tuple[str, str]:
    """`POST /tokens`: (token, uuid) of the API token KERBEROS made (§7.4, K30)."""
    obj = _obj(raw, "api token")
    token, uuid = _str(obj, "token"), _str(obj, "uuid")
    if not TOKEN_RE.fullmatch(token):
        raise bad("token is not a token")
    if not UUID_RE.fullmatch(uuid):
        raise bad("uuid is not a uuid")
    return token, uuid


def node(raw: Any) -> Node:
    obj = _obj(raw, "node")
    profile = obj.get("configProfile") or {}
    if not isinstance(profile, dict):
        raise bad("configProfile is not an object")
    inbound_uuids = []
    for inbound in profile.get("activeInbounds") or []:
        if isinstance(inbound, dict) and isinstance(inbound.get("uuid"), str):
            inbound_uuids.append(inbound["uuid"])
    return Node(
        uuid=_str(obj, "uuid"),
        name=_str(obj, "name"),
        address=_str(obj, "address"),
        port=_int(obj, "port", required=False, default=2222),
        is_connected=_bool(obj, "isConnected"),
        is_disabled=_bool(obj, "isDisabled"),
        country=_str(obj, "countryCode", required=False, default="XX"),
        users_online=_int(obj, "usersOnline", required=False, default=0),
        profile_uuid=profile.get("activeConfigProfileUuid") or None,
        inbound_uuids=inbound_uuids,
    )


def inbound(raw: Any, profile_uuid: str) -> Inbound:
    obj = _obj(raw, "inbound")
    port = obj.get("port")
    return Inbound(
        uuid=_str(obj, "uuid"),
        tag=_str(obj, "tag"),
        type=_str(obj, "type", required=False, default=""),
        network=obj.get("network") if isinstance(obj.get("network"), str) else None,
        security=obj.get("security") if isinstance(obj.get("security"), str) else None,
        port=port if isinstance(port, int) and not isinstance(port, bool) else None,
        profile_uuid=obj.get("profileUuid") or profile_uuid,
    )


def profile(raw: Any) -> Profile:
    obj = _obj(raw, "config profile")
    uuid = _str(obj, "uuid")
    config = obj.get("config")
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except ValueError as exc:
            raise bad("config is not JSON") from exc
    config = _obj(config, "config")
    nodes = []
    for item in obj.get("nodes") or []:
        if isinstance(item, dict) and isinstance(item.get("uuid"), str):
            nodes.append(item["uuid"])
    return Profile(
        uuid=uuid,
        name=_str(obj, "name", required=False, default=uuid[:8]),
        config=config,
        inbounds=[inbound(i, uuid) for i in obj.get("inbounds") or []],
        node_uuids=nodes,
    )


def detect_shape(raw_hosts: list) -> str:
    for raw in raw_hosts:
        if isinstance(raw, dict):
            if "tags" in raw or "xhttpExtraParams" in raw:
                return "tags"
            if "tag" in raw or "xHttpExtraParams" in raw:
                return "tag"
    return "tags"


def _extra(value: Any) -> Optional[dict]:
    if value in (None, ""):
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError as exc:
            raise bad("xhttp extra is not JSON") from exc
    if not isinstance(value, dict):
        raise bad("xhttp extra is not an object")
    return value


def host(raw: Any, shape: str) -> Host:
    obj = _obj(raw, "host")
    tags_key, extra_key = HOST_SHAPES[shape]
    if shape == "tags":
        tags = obj.get(tags_key) or []
        if not isinstance(tags, list) or not all(isinstance(x, str) for x in tags):
            raise bad("tags is not a list of strings")
    else:
        tag = obj.get(tags_key)
        if tag is not None and not isinstance(tag, str):
            raise bad("tag is not a string")
        tags = [tag] if tag else []
    inbound_ref = obj.get("inbound") or {}
    if not isinstance(inbound_ref, dict):
        raise bad("inbound is not an object")
    template = obj.get("xrayJsonTemplateUuid")
    position = obj.get("viewPosition")
    return Host(
        uuid=_str(obj, "uuid"),
        remark=_str(obj, "remark", required=False),
        address=_str(obj, "address", required=False),
        port=_int(obj, "port", required=False, default=443),
        sni=_str(obj, "sni", required=False),
        fingerprint=_str(obj, "fingerprint", required=False),
        is_disabled=_bool(obj, "isDisabled"),
        is_hidden=_bool(obj, "isHidden"),
        tags=list(tags),
        xhttp_extra=_extra(obj.get(extra_key)),
        profile_uuid=inbound_ref.get("configProfileUuid") or None,
        inbound_uuid=inbound_ref.get("configProfileInboundUuid") or None,
        template_uuid=template if isinstance(template, str) and template else None,
        override_sni=_bool(obj, "overrideSniFromAddress"),
        view_position=position if isinstance(position, int) else None,
        raw=dict(obj),
    )


def host_write_fields(fields: dict, shape: str) -> dict:
    """Canonical fields (tags, xhttpExtraParams) in the panel's own form."""
    tags_key, extra_key = HOST_SHAPES[shape]
    out = {}
    for key, value in fields.items():
        if key == "tags":
            if shape == "tags":
                out[tags_key] = list(value or [])
            else:
                out[tags_key] = (value or [None])[0]
        elif key in ("xhttpExtraParams", "xHttpExtraParams"):
            out[extra_key] = value
        else:
            out[key] = value
    return out


def template(raw: Any) -> Template:
    obj = _obj(raw, "subscription template")
    body = obj.get("templateJson")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            body = None
    return Template(
        uuid=_str(obj, "uuid"),
        name=_str(obj, "name", required=False),
        type=_str(obj, "templateType", required=False),
        json=body if isinstance(body, dict) else None,
    )


def squad(raw: Any) -> Squad:
    obj = _obj(raw, "internal squad")
    inbounds = []
    for item in obj.get("inbounds") or []:
        if isinstance(item, dict) and isinstance(item.get("uuid"), str):
            inbounds.append(item["uuid"])
        elif isinstance(item, str):
            inbounds.append(item)
    info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
    members = info.get("membersCount")
    return Squad(
        uuid=_str(obj, "uuid"),
        name=_str(obj, "name", required=False),
        inbound_uuids=inbounds,
        members=members if isinstance(members, int) and not isinstance(members, bool) else None,
    )


def sub_settings(raw: Any) -> SubSettings:
    obj = _obj(raw, "subscription settings")
    headers = obj.get("customResponseHeaders") or {}
    if not isinstance(headers, dict):
        raise bad("customResponseHeaders is not an object")
    return SubSettings(uuid=_str(obj, "uuid"), headers=dict(headers))
