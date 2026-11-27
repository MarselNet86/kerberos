"""Russian sites directly in the subscription of 3x-ui (tech.md §7.6, §10.2, K29). Pure.

From v3.0 3x-ui hands Happ a routing profile with every subscription: the settings
`subEnableRouting` and `subRoutingRules` become the headers `Routing-Enable` and `Routing`.
`subRoutingRules` is a Happ deeplink (`happ://routing/onadd/<base64 JSON>`), the JSON
itself or, from v3.10, a URL the panel fetches. Before v3.0 only the JSON subscription
takes rules: `subJsonRules`, an array of Xray rules put before the panel's own.

KERBEROS reads these settings and never writes them: the settings of 3x-ui are saved
only all at once, with its secrets, and differ from version to version. The person pastes
the profile KERBEROS gives into the panel.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Optional, Union

PREFIXES = ("happ://routing/onadd/", "happ://routing/add/")
REMOTE = "remote"
RU_SITES = ("geosite:category-ru", "geosite:ru")
RU_IP = "geoip:ru"
VERSION = re.compile(r"^(\d+)\.")

# The routing of the KERBEROS templates (§10.9) in the words of Happ: Russian sites and
# addresses directly, the rest through the proxy, MAX blocked. The field names are the ones
# 3x-ui itself reads from such a profile (internal/sub/json_routing.go).
PROFILE = {
    "Name": "KERBEROS",
    "GlobalProxy": "true",
    "DomainStrategy": "IPIfNonMatch",
    "DirectSites": ["geosite:category-ru", "geosite:private"],
    "DirectIp": ["geoip:ru", "geoip:private"],
    "ProxySites": [],
    "ProxyIp": [],
    "BlockSites": ["domain:max.ru", "domain:oneme.ru"],
    "BlockIp": [],
}


def routing_link() -> str:
    """The Happ deeplink of PROFILE, one line, to paste into the panel."""
    compact = json.dumps(PROFILE, separators=(",", ":"), ensure_ascii=False)
    return PREFIXES[0] + base64.b64encode(compact.encode("utf-8")).decode("ascii")


def parse_routing(value: str) -> Union[dict, str, None]:
    """The profile of `subRoutingRules`: a dict, REMOTE for a URL KERBEROS cannot see, None
    for nothing readable (empty, `happ://routing/off`, broken)."""
    text = (value or "").strip()
    if not text or text == "happ://routing/off":
        return None
    if text.startswith(("http://", "https://")):
        return REMOTE
    payload: Optional[bytes] = None
    if text.startswith("{"):
        payload = text.encode("utf-8")
    for prefix in PREFIXES:
        if text.startswith(prefix):
            raw = text[len(prefix) :]
            try:
                payload = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False)
            except (binascii.Error, ValueError):
                return None
    if payload is None:
        return None
    try:
        profile = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return profile if isinstance(profile, dict) else None


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def profile_ru_direct(profile: dict) -> bool:
    """Russian sites and addresses go directly in a Happ profile."""
    sites, ips = _strings(profile.get("DirectSites")), _strings(profile.get("DirectIp"))
    return any(s in sites for s in RU_SITES) and RU_IP in ips


def json_rules_ru_direct(text: str) -> bool:
    """`subJsonRules` of v2 sends Russian sites and addresses to the direct outbound."""
    try:
        rules = json.loads(text or "[]")
    except ValueError:
        return False
    if not isinstance(rules, list):
        return False
    sites = ips = False
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("outboundTag") != "direct":
            continue
        sites = sites or any(s in _strings(rule.get("domain")) for s in RU_SITES)
        ips = ips or RU_IP in _strings(rule.get("ip"))
    return sites and ips


def routing_supported(version: str, settings: dict) -> bool:
    """Happ routing in the subscription: 3x-ui v3.0 and later. An unknown version counts
    by the keys the panel has saved."""
    match = VERSION.match(version or "")
    if match:
        return int(match.group(1)) >= 3
    return "subEnableRouting" in settings or "subRoutingRules" in settings


def routing_info(version: str, settings: dict) -> dict:
    """What `panel_info` keeps of the routing of the subscription (no secrets in it)."""
    return {
        "happ": routing_supported(version, settings),
        "enabled": settings.get("subEnableRouting", "").lower() == "true",
        "rules": settings.get("subRoutingRules", ""),
        "json": settings.get("subJsonEnable", "").lower() == "true",
        "jsonRules": settings.get("subJsonRules", ""),
    }
