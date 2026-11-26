"""The node profile from templates/profile.json (tech.md §10.9). Pure functions.

Markers are replaced structurally, by walking the JSON: a string that is a
marker becomes the value, a list element that is a list marker expands into
the values, a marker inside a string (a path, a URL) is replaced there. Tags,
the Reality private key and shortIds of the node survive; other inbounds of
the person and the routing rules that use them stay, before the template's.
"""

from __future__ import annotations

import base64
import copy
import random
import re
from typing import Any, Optional

from kerberos import templates

SCALAR = ("__REALITY_TAG__", "__HY2_TAG__", "__REALITY_PRIVATE_KEY__", "__DOMAIN__")
LISTS = ("__SERVER_NAMES__", "__OWN_DOMAINS__", "__REALITY_SHORT_ID__")
MARKERS = SCALAR + LISTS

TRANSLIT = dict(
    zip(
        "абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
        [
            "a",
            "b",
            "v",
            "g",
            "d",
            "e",
            "e",
            "zh",
            "z",
            "i",
            "y",
            "k",
            "l",
            "m",
            "n",
            "o",
            "p",
            "r",
            "s",
            "t",
            "u",
            "f",
            "h",
            "ts",
            "ch",
            "sh",
            "sch",
            "",
            "y",
            "",
            "e",
            "yu",
            "ya",
        ],
    )
)


class ProfileError(Exception):
    """The template could not be filled: KERBEROS writes nothing (§10.9)."""


def latin_upper(name: str) -> str:
    """The node name in Latin upper case for new inbound tags."""
    text = "".join(TRANSLIT.get(ch, ch) for ch in name.lower())
    return re.sub(r"[^A-Z0-9]+", "-", text.upper()).strip("-") or "NODE"


def new_private_key(rng: random.Random) -> str:
    """An x25519 private key as Xray writes it: 32 clamped bytes, base64url, no padding."""
    key = bytearray(rng.getrandbits(8) for _ in range(32))
    key[0] &= 248
    key[31] &= 127
    key[31] |= 64
    return base64.urlsafe_b64encode(bytes(key)).decode().rstrip("=")


def new_short_id(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(16))


def substitute(value: Any, values: dict) -> Any:
    if isinstance(value, dict):
        return {k: substitute(v, values) for k, v in value.items()}
    if isinstance(value, list):
        result: list = []
        for item in value:
            if isinstance(item, str) and item in LISTS:
                result.extend(values.get(item, [item]))
            else:
                result.append(substitute(item, values))
        return result
    if isinstance(value, str):
        if value in values and not isinstance(values[value], list):
            return values[value]
        for marker in SCALAR:
            if marker in value and marker in values:
                value = value.replace(marker, values[marker])
        return value
    return value


def remaining(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [m for v in value.values() for m in remaining(v)]
    if isinstance(value, list):
        return [m for v in value for m in remaining(v)]
    if isinstance(value, str):
        return [m for m in MARKERS if m in value]
    return []


def is_reality(inbound: dict) -> bool:
    stream = inbound.get("streamSettings") or {}
    return inbound.get("protocol") == "vless" and stream.get("security") == "reality"


def is_hysteria(inbound: dict) -> bool:
    return inbound.get("protocol") in ("hysteria", "hysteria2")


def reality_settings(inbound: Optional[dict]) -> dict:
    if not inbound:
        return {}
    return (inbound.get("streamSettings") or {}).get("realitySettings") or {}


def unique_tag(base: str, taken: set) -> str:
    """`base`, else `base-2`, `base-3`: inbound tags are unique across the panel (§7.4)."""
    if base not in taken:
        return base
    number = 2
    while f"{base}-{number}" in taken:
        number += 1
    return f"{base}-{number}"


def build_profile(
    current: dict,
    node_name: str,
    domain: str,
    rng: random.Random,
    finalized: bool = False,
    *,
    taken: frozenset = frozenset(),
    fresh: bool = False,
) -> dict:
    """Profile of the node on its own domain; old server names stay until finalization.

    `taken`: inbound tags of the other profiles of the panel, which a new tag must not
    repeat. `fresh`: the node's own profile (K24): every tag is new, the Reality key,
    shortIds and names still come from `current`.
    """
    inbounds = [i for i in current.get("inbounds") or [] if isinstance(i, dict)]
    reality = next((i for i in inbounds if is_reality(i)), None)
    hysteria = next((i for i in inbounds if is_hysteria(i)), None)
    settings = reality_settings(reality)
    names = [n for n in settings.get("serverNames") or [] if isinstance(n, str) and n != domain]
    short_ids = [s for s in settings.get("shortIds") or [] if isinstance(s, str) and s]
    node = latin_upper(node_name)
    reality_tag = None if fresh else (reality or {}).get("tag")
    reality_tag = reality_tag or unique_tag(f"VLESS-REALITY-{node}", set(taken))
    hysteria_tag = None if fresh else (hysteria or {}).get("tag")
    hysteria_tag = hysteria_tag or unique_tag(f"HY2-{node}", set(taken) | {reality_tag})
    values = {
        "__REALITY_TAG__": reality_tag,
        "__HY2_TAG__": hysteria_tag,
        "__REALITY_PRIVATE_KEY__": settings.get("privateKey") or new_private_key(rng),
        # An existing Reality keeps exactly its shortIds; a new one gets a random one.
        "__REALITY_SHORT_ID__": short_ids if reality else [new_short_id(rng)],
        "__DOMAIN__": domain,
        "__SERVER_NAMES__": [domain] if finalized else [domain, *names],
    }
    profile = substitute(templates.load(templates.PROFILE), values)
    left = remaining(profile)
    if left:
        raise ProfileError(", ".join(sorted(set(left))))
    kept = [copy.deepcopy(i) for i in inbounds if i is not reality and i is not hysteria]
    profile["inbounds"] += kept
    kept_tags = {i.get("tag") for i in kept}
    rules = [
        copy.deepcopy(rule)
        for rule in (current.get("routing") or {}).get("rules") or []
        if isinstance(rule, dict) and set(_tags(rule.get("inboundTag"))) & kept_tags
    ]
    profile["routing"]["rules"] = rules + profile["routing"]["rules"]
    have = {o.get("tag") for o in profile["outbounds"]}
    wanted = {r.get("outboundTag") for r in rules} | {r.get("balancerTag") for r in rules}
    for outbound in current.get("outbounds") or []:
        if isinstance(outbound, dict) and outbound.get("tag") in wanted - have:
            profile["outbounds"].append(copy.deepcopy(outbound))
    for key in ("balancers",):
        if key in (current.get("routing") or {}) and any(r.get("balancerTag") for r in rules):
            profile["routing"][key] = copy.deepcopy(current["routing"][key])
    return profile


def template_tags(profile: dict) -> dict:
    """Tags of the Reality and Hysteria2 inbounds the template made in a built profile.

    `build_profile` puts the template's inbounds first; the person's own come after.
    """
    inbounds = [i for i in profile.get("inbounds") or [] if isinstance(i, dict)]
    return {
        "reality": next((i.get("tag") for i in inbounds if is_reality(i)), None),
        "hysteria": next((i.get("tag") for i in inbounds if is_hysteria(i)), None),
    }


def finalize_profile(current: dict, domain: str) -> dict:
    """§10.4 step 6: only the own domain stays in serverNames."""
    profile = copy.deepcopy(current)
    for inbound in profile.get("inbounds") or []:
        if isinstance(inbound, dict) and is_reality(inbound):
            settings = reality_settings(inbound)
            if domain in (settings.get("serverNames") or []):
                settings["serverNames"] = [domain]
    return profile


def server_names(config: dict) -> list[str]:
    for inbound in config.get("inbounds") or []:
        if isinstance(inbound, dict) and is_reality(inbound):
            return list(reality_settings(inbound).get("serverNames") or [])
    return []


def _tags(value: Any) -> list:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []
