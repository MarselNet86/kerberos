"""Subscription templates of KERBEROS (tech.md §10.9, §10.5). Pure functions.

Two XRAY_JSON templates are made from templates/: «KERBEROS» with a reserve
(balancer, injected hidden hosts, a probe every 60 s) and «KERBEROS single»
(the panel takes only Latin letters, digits, spaces, _ and - in template
names). The only marker is __OWN_DOMAINS__: `domain:<zone>` for every DNS
zone of the fleet's domains, so the clients resolve and reach the nodes
directly.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from kerberos import templates
from kerberos.fixes.profile import ProfileError, latin_upper, remaining, substitute

RESERVE_NAME = "KERBEROS"
SINGLE_NAME = "KERBEROS single"
NODE_IN_TAG = 22  # KRB_<NODE>_VLESS within 32 characters: 2.2–2.7 take tags up to 32, 2.8+ 36


def zone(domain: str) -> str:
    labels = domain.lower().rstrip(".").split(".")
    return ".".join(labels[-2:])


def own_domains(domains: Iterable[str]) -> list[str]:
    return [f"domain:{z}" for z in sorted({zone(d) for d in domains if d and "." in d})]


def _drop_empty(value):
    """A DNS server or a rule whose domain list became empty would match everything."""
    if isinstance(value, dict):
        return {k: _drop_empty(v) for k, v in value.items()}
    if isinstance(value, list):
        kept = []
        for item in value:
            if isinstance(item, dict) and "domains" in item and item["domains"] == []:
                continue
            if (
                isinstance(item, dict)
                and "domain" in item
                and item["domain"] == []
                and (set(item) <= {"type", "domain", "outboundTag", "balancerTag"})
            ):
                continue
            kept.append(_drop_empty(item))
        return kept
    return value


def build(kind: str, domains: Iterable[str]) -> dict:
    """`kind`: "reserve" or "single"."""
    name = templates.RESERVE if kind == "reserve" else templates.SINGLE
    filled = substitute(templates.load(name), {"__OWN_DOMAINS__": own_domains(domains)})
    filled = _drop_empty(filled)
    left = remaining(filled)
    if left:
        raise ProfileError(", ".join(sorted(set(left))))
    return filled


def _strings(value) -> list:
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return [value] if isinstance(value, str) else []


def own_write(kind: str, current) -> bool:
    """The template in the panel is one KERBEROS wrote, for other zones of the fleet: a new
    node domain changes only `domain:<zone>` (K24, found on the stand). Not a hand edit:
    it is brought up to date without asking."""
    if not isinstance(current, dict):
        return False
    base = set(_strings(build(kind, [])))
    zones = [s[len("domain:"):] for s in dict.fromkeys(_strings(current))
             if s.startswith("domain:") and s not in base]  # fmt: skip
    try:
        return build(kind, zones) == current
    except ProfileError:
        return False


def pair_tags(node_name: str) -> dict:
    """Tags of a main and its reserve, one per protocol; panel format ^[A-Z0-9_:]+$, ≤ 32.

    A long name keeps its first 17 characters and 4 of its hash: two long names
    with the same start still get different tags.
    """
    node = latin_upper(node_name).replace("-", "_")
    if len(node) > NODE_IN_TAG:
        mark = hashlib.sha256(node_name.encode("utf-8")).hexdigest()[:4].upper()
        node = f"{node[: NODE_IN_TAG - 5].rstrip('_')}_{mark}"
    return {"vless": f"KRB_{node}_VLESS", "hysteria": f"KRB_{node}_HY2"}
