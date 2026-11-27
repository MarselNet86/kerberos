"""XHTTP padding and the uplink method (tech.md §10.6). Pure functions.

Padding fields must match on the server (the inbound's `extra` in the
profile) and on every client, or the tunnel breaks. A client gets the host's
`extra` when it is not empty, else the inbound's whole (the panel does not
merge them): a host without its own `extra` follows the inbound. The key
and the header are random per inbound, and so is the range of the padding
(K26): neither the fleet nor KERBEROS as a whole shares one signature.
Rollback removes only the keys KERBEROS added.
"""

from __future__ import annotations

import copy
import random
import string
from collections.abc import Iterable
from typing import Any, Optional

PADDING_KEYS = (
    "xPaddingBytes",
    "xPaddingObfsMode",
    "xPaddingKey",
    "xPaddingHeader",
    "xPaddingPlacement",
    "xPaddingMethod",
)
# The range of `xPaddingBytes`, random per inbound (K26): before it was 100-1000 everywhere.
PADDING_LOW = (64, 256)
PADDING_HIGH = (768, 1536)
# Header names that look like what browsers and frameworks send.
HEADER_WORDS = ("Request", "Trace", "Session", "Client", "Cache", "Edge", "Origin", "Span")


def padding_fields(rng: random.Random) -> dict:
    letters = string.ascii_lowercase
    key = "".join(rng.choice(letters) for _ in range(rng.randint(6, 10)))
    suffix = "".join(rng.choice(letters) for _ in range(4))
    return {
        "xPaddingBytes": f"{rng.randint(*PADDING_LOW)}-{rng.randint(*PADDING_HIGH)}",
        "xPaddingObfsMode": True,
        "xPaddingKey": key,
        "xPaddingHeader": f"X-{rng.choice(HEADER_WORDS)}-{suffix.capitalize()}",
        "xPaddingPlacement": "queryInHeader",
        "xPaddingMethod": "tokenish",
    }


def own_extra(extra: Any) -> Optional[dict]:
    """The host's own extra, or None when the panel would hand out the inbound's."""
    return extra if isinstance(extra, dict) and extra else None


def effective(host_extra: Any, inbound_extra: Any) -> Optional[dict]:
    """The extra a client of this host gets (§10.6)."""
    own = own_extra(host_extra)
    if own is not None:
        return own
    return inbound_extra if isinstance(inbound_extra, dict) else None


def inbound_extra(inbound: Optional[dict]) -> Optional[dict]:
    extra = (((inbound or {}).get("streamSettings") or {}).get("xhttpSettings") or {}).get("extra")
    return extra if isinstance(extra, dict) else None


def has_padding(extra: Optional[dict]) -> bool:
    return bool(extra) and "xPaddingBytes" in extra


def padding_of(extra: Optional[dict]) -> dict:
    return {k: (extra or {})[k] for k in PADDING_KEYS if k in (extra or {})}


def with_padding(extra: Optional[dict], fields: dict) -> dict:
    result = copy.deepcopy(extra) if isinstance(extra, dict) else {}
    result.update(copy.deepcopy(fields))
    return result


def without_padding(extra: Optional[dict]) -> dict:
    return {k: copy.deepcopy(v) for k, v in (extra or {}).items() if k not in PADDING_KEYS}


def xhttp_settings(inbound: dict) -> dict:
    stream = inbound.setdefault("streamSettings", {})
    return stream.setdefault("xhttpSettings", {})


def add_padding(config: dict, tags: list[str], rng: random.Random) -> tuple[dict, dict]:
    """A copy of the profile with padding on the inbounds that have none; {tag: fields}."""
    config = copy.deepcopy(config)
    written: dict = {}
    for inbound in config.get("inbounds") or []:
        if not isinstance(inbound, dict) or inbound.get("tag") not in tags:
            continue
        settings = xhttp_settings(inbound)
        extra = settings.get("extra") if isinstance(settings.get("extra"), dict) else None
        if has_padding(extra):
            continue  # someone did it meanwhile, e.g. a profile shared with another node
        fields = padding_fields(rng)
        settings["extra"] = with_padding(extra, fields)
        written[inbound["tag"]] = fields
    return config, written


def remove_padding(
    config: dict, written: dict, force: Iterable[str] = ()
) -> tuple[dict, list[str]]:
    """Padding KERBEROS wrote taken out again; tags whose padding was changed since.

    Changed padding stays, unless its tag is in `force` (the person agreed to remove it).
    """
    config = copy.deepcopy(config)
    changed = []
    forced = set(force)
    for inbound in config.get("inbounds") or []:
        if not isinstance(inbound, dict) or inbound.get("tag") not in written:
            continue
        settings = xhttp_settings(inbound)
        extra = settings.get("extra") if isinstance(settings.get("extra"), dict) else None
        current = padding_of(extra)
        if not current:
            continue
        if current != written[inbound["tag"]] and inbound["tag"] not in forced:
            changed.append(inbound["tag"])
            continue
        rest = without_padding(extra)
        if rest:
            settings["extra"] = rest
        else:
            settings.pop("extra", None)  # an empty extra means no extra
    return config, changed


def uplink_get(extra: Optional[dict]) -> dict:
    result = copy.deepcopy(extra) if isinstance(extra, dict) else {}
    result["uplinkHTTPMethod"] = "GET"
    return result


def uplink_back(extra: Optional[dict], previous: Any, was_none: bool) -> Optional[dict]:
    result = copy.deepcopy(extra) if isinstance(extra, dict) else {}
    if previous is None:
        result.pop("uplinkHTTPMethod", None)
    else:
        result["uplinkHTTPMethod"] = previous
    return None if was_none and not result else result
