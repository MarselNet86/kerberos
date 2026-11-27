"""Subscription templates of KERBEROS (tech.md §10.9, §10.5). Pure functions.

Two XRAY_JSON templates are made from templates/: «KERBEROS» with a reserve
(balancer, injected hidden hosts, a probe every minute or so) and «KERBEROS single»
(the panel takes only Latin letters, digits, spaces, _ and - in template
names). The only marker is __OWN_DOMAINS__: `domain:<zone>` for every DNS
zone of the fleet's domains, so the clients resolve and reach the nodes
directly.

The probe of the reserve is the panel's own (K26): an interval of 60–90 s and one of a
few connectivity checks, chosen once and then kept, so the clients of every KERBEROS do
not all ask the same address at the same beat.
"""

from __future__ import annotations

import hashlib
import random
import re
from collections.abc import Iterable
from typing import Any, Optional

from kerberos import templates
from kerberos.fixes.profile import ProfileError, latin_upper, remaining, substitute

RESERVE_NAME = "KERBEROS"
SINGLE_NAME = "KERBEROS single"
NODE_IN_TAG = 22  # KRB_<NODE>_VLESS within 32 characters: 2.2–2.7 take tags up to 32, 2.8+ 36
# Connectivity checks that answer 204 to HEAD; the first is the one of templates/.
PROBE_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://www.google.com/generate_204",
    "https://connectivitycheck.gstatic.com/generate_204",
    "https://clients3.google.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
)
PROBE_SECONDS = (60, 90)  # sub.probe_interval wants 60 s and more
# What every KERBEROS wrote before K26: a template with it gets a probe of its own.
OLD_PROBE = {"interval": "60s", "destination": PROBE_URLS[0]}
INTERVAL = re.compile(r"^(\d+)s$")


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


def probe_of(template: Any) -> Optional[dict]:
    """{interval, destination} of the reserve's probe, when it is one KERBEROS writes."""
    ping = ((template or {}).get("burstObservatory") or {}).get("pingConfig") \
        if isinstance(template, dict) else None  # fmt: skip
    if not isinstance(ping, dict):
        return None
    interval, destination = ping.get("interval"), ping.get("destination")
    match = INTERVAL.match(interval) if isinstance(interval, str) else None
    low, high = PROBE_SECONDS
    if not match or not low <= int(match.group(1)) <= high or destination not in PROBE_URLS:
        return None
    return {"interval": interval, "destination": destination}


def own_probe(template: Any) -> Optional[dict]:
    """The probe this panel chose before; None for none or for the one of before K26."""
    probe = probe_of(template)
    return None if probe is None or probe == OLD_PROBE else probe


def new_probe(rng: random.Random) -> dict:
    """A probe of this panel's own; never the one every KERBEROS had before K26."""
    while True:
        probe = {"interval": f"{rng.randint(*PROBE_SECONDS)}s",
                 "destination": rng.choice(PROBE_URLS)}  # fmt: skip
        if probe != OLD_PROBE:
            return probe


def build(kind: str, domains: Iterable[str], probe: Optional[dict] = None) -> dict:
    """`kind`: "reserve" or "single"; `probe`: the reserve's own (K26), else templates/."""
    name = templates.RESERVE if kind == "reserve" else templates.SINGLE
    filled = substitute(templates.load(name), {"__OWN_DOMAINS__": own_domains(domains)})
    filled = _drop_empty(filled)
    ping = (filled.get("burstObservatory") or {}).get("pingConfig")
    if probe and isinstance(ping, dict):
        ping.update(probe)
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
    node domain changes only `domain:<zone>` (K24, found on the stand), and the probe of
    the reserve is the panel's own or the one of before K26. Not a hand edit: it is
    brought up to date without asking."""
    if not isinstance(current, dict):
        return False
    base = set(_strings(build(kind, [])))
    zones = [s[len("domain:"):] for s in dict.fromkeys(_strings(current))
             if s.startswith("domain:") and s not in base]  # fmt: skip
    try:
        return build(kind, zones, probe_of(current)) == current
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
