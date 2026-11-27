"""Copies of hosts for self-steal (tech.md §10.4 step 3). Pure functions.

A copy keeps every field of the source except: `sni` (the own domain),
`overrideSniFromAddress` and `keepSniBlank` (false: either would hide the
domain from clients), `fingerprint` (the source's, or firefox if empty), and,
when given, the subscription template, tags and visibility.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Optional

from kerberos.panel.model import Host

# Fields of the answer that a new host does not take.
NOT_COPIED = {"uuid", "viewPosition"}
KEEP = object()
FINGERPRINTS = ("chrome", "firefox")
REMARK_LIMIT = 40  # 2.8 takes remarks up to 40 UTF-16 code units, 3.x up to 100 (§7.4)
CHANGED = {
    "sni",
    "overrideSniFromAddress",
    "keepSniBlank",
    "fingerprint",
    "xrayJsonTemplateUuid",
    "tags",
    "tag",
    "isHidden",
    "isDisabled",
}


def _ids(value: Any) -> Any:
    """Lists of objects in an answer become lists of uuids in a request."""
    if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
        return [v.get("uuid") for v in value if v.get("uuid")]
    return value


def copy_fields(
    source: Host,
    domain: str,
    *,
    template_uuid: Any = KEEP,
    tags: Optional[list[str]] = None,
    hidden: Optional[bool] = None,
) -> dict:
    fields = {k: _ids(copy.deepcopy(v)) for k, v in source.raw.items() if k not in NOT_COPIED}
    fields.pop("tag", None)
    fields.pop("xHttpExtraParams", None)
    fields["tags"] = list(source.tags if tags is None else tags)
    fields["xhttpExtraParams"] = copy.deepcopy(source.xhttp_extra)
    fields["sni"] = domain
    fields["overrideSniFromAddress"] = False
    fields["keepSniBlank"] = False
    fields["fingerprint"] = source.fingerprint or fingerprint_of(source.uuid)
    fields["isDisabled"] = False
    if template_uuid is not KEEP:
        fields["xrayJsonTemplateUuid"] = template_uuid
    if hidden is not None:
        fields["isHidden"] = hidden
    return fields


def fingerprint_of(key: str) -> str:
    """The uTLS fingerprint a host gets when it has none (§10.5, K26): chrome or firefox,
    the same for a host every time, so the hosts of KERBEROS do not all show one. Safari
    and Edge are left out: a phone on Android with Safari's fingerprint stands out itself."""
    return FINGERPRINTS[hashlib.sha256(key.encode("utf-8")).digest()[0] % len(FINGERPRINTS)]


def _units(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def fit_remark(base: str, suffix: str, limit: int = REMARK_LIMIT) -> str:
    """`base` + `suffix` within the panel's remark limit; `base` is cut, never `suffix`."""
    base = base.strip()
    while base and _units(base + suffix) > limit:
        base = base[:-1].rstrip()
    return (base + suffix).strip() if base else suffix.strip()


def hysteria_host(
    reality_source: Host, domain: str, profile_uuid: str, inbound_uuid: str, remark: str
) -> dict:
    """A Hysteria2 host after the Reality one when the node has none (§10.4)."""
    fields = copy_fields(reality_source, domain)
    fields["inbound"] = {
        "configProfileUuid": profile_uuid,
        "configProfileInboundUuid": inbound_uuid,
    }
    fields["port"] = 443
    fields["remark"] = remark
    fields["xhttpExtraParams"] = None
    return fields


def fresh_host(remark: str, address: str, port: int, domain: str, profile_uuid: str,
               inbound_uuid: str) -> dict:  # fmt: skip
    """A host without a model (K24): the node had no Reality host to copy (§10.4)."""
    return {
        "inbound": {"configProfileUuid": profile_uuid, "configProfileInboundUuid": inbound_uuid},
        "remark": remark,
        "address": address,
        "port": port,
        "sni": domain,
        "fingerprint": fingerprint_of(f"{profile_uuid}:{inbound_uuid}:{remark}"),
        "isDisabled": False,
        "isHidden": False,
        "overrideSniFromAddress": False,
        "keepSniBlank": False,
        "tags": [],
        "xhttpExtraParams": None,
    }


def mismatches(sent: dict, got: Host) -> list[str]:
    """Fields the panel stored differently from what KERBEROS sent."""
    checks = {
        "sni": got.sni,
        "fingerprint": got.fingerprint,
        "overrideSniFromAddress": got.override_sni,
        "keepSniBlank": bool(got.raw.get("keepSniBlank", False)),
        "isHidden": got.is_hidden,
        "address": got.address,
        "port": got.port,
        "tags": got.tags,
    }
    if "xrayJsonTemplateUuid" in sent:
        checks["xrayJsonTemplateUuid"] = got.template_uuid
    bad = []
    for key, value in checks.items():
        if key in sent and sent[key] != value and not (key == "tags" and sent[key] == value):
            bad.append(key)
    return bad
