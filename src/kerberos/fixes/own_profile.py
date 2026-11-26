"""A node's own profile (tech.md §10.4, K24). Pure functions.

Remnawave 2.8.1 and 3.4.11 keep inbound tags unique across the panel, not per profile:
a node that leaves a shared profile gets new tags, and with them new hosts and a place
in the squads. The Reality key, shortIds and old names come along, so a client with the
old subscription still gets in through the new inbound until finalization.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from kerberos.fixes.hosts import fit_remark
from kerberos.fixes.profile import is_hysteria, is_reality, latin_upper

PREFIX = "KERBEROS "
NAME_LIMIT = 30  # POST /api/config-profiles: 2 to 30 of [A-Za-z0-9_ -] (§7.4)
NAME_RE = re.compile(r"[A-Za-z0-9_\s-]{2,30}")


def needs_own(snapshot: Any, node: Any) -> bool:
    """A node without a profile, or on one other nodes run too."""
    profile = snapshot.node_profile(node)
    return profile is None or len(profile.node_uuids) > 1


def running_configs(snapshot: Any, node: Any, config: Optional[dict] = None) -> list[dict]:
    """The inbounds of its profile the node runs, as configs; `config` read afresh."""
    profile = snapshot.node_profile(node)
    if profile is None:
        return []
    tags = {i.tag for i in snapshot.node_inbounds(node)}
    source = profile.config if config is None else config
    return [i for i in source.get("inbounds") or [] if isinstance(i, dict) and i.get("tag") in tags]


def template_pair(configs: list[dict]) -> tuple[Optional[dict], Optional[dict]]:
    """The Reality and Hysteria2 the template replaces: the first of each kind."""
    reality = next((i for i in configs if is_reality(i)), None)
    hysteria = next((i for i in configs if is_hysteria(i)), None)
    return reality, hysteria


def other_inbounds(snapshot: Any, node: Any) -> list[str]:
    """Tags a node on a shared profile runs besides the template's Reality and Hysteria2:
    KERBEROS does not carry them to the node's own profile (`plan.blocked.shared_other`)."""
    if not needs_own(snapshot, node):
        return []
    configs = running_configs(snapshot, node)
    pair = template_pair(configs)
    return [str(i.get("tag")) for i in configs if i is not pair[0] and i is not pair[1]]


def profile_name(node_name: str, taken: set) -> str:
    """«KERBEROS NL-1»: unique among the panel's profile names, at most 30 characters."""
    base = (PREFIX + latin_upper(node_name))[:NAME_LIMIT].rstrip(" -")
    if base not in taken:
        return base
    number = 2
    while True:
        suffix = f" {number}"
        name = base[: NAME_LIMIT - len(suffix)].rstrip(" -") + suffix
        if name not in taken:
            return name
        number += 1


def flag(country: str) -> str:
    """The flag emoji of a two-letter country code; nothing for an unknown country."""
    code = (country or "").upper()
    if len(code) != 2 or not code.isalpha() or not code.isascii() or code == "XX":
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def fresh_remark(country: str, node_name: str) -> str:
    """The remark of a host KERBEROS makes without a model: «🇳🇱 nl-1»."""
    return fit_remark(f"{flag(country)} {node_name}".strip(), "")


def squads_holding(squads: list, inbound_uuids: list[str]) -> list:
    return [s for s in squads if set(s.inbound_uuids) & set(inbound_uuids)]


def squad_params(snapshot: Any, node: Any) -> dict:
    """Where the node's new inbounds go (§10.4): the squads that hold its inbounds now
    ({}); with none, the only squad of the panel; with several, the person picks (u)."""
    squads = list(snapshot.squads)
    held = [i.uuid for i in snapshot.node_inbounds(node)]
    if not squads or squads_holding(squads, held):
        return {}
    if len(squads) == 1:
        return {"squads": [squads[0].uuid]}
    return {"squads": None, "pickSquads": True}


def suggested_squads(snapshot: Any, node: Any) -> list[str]:
    """The squads that hold inbounds of the other nodes: marked first in the list of u."""
    others = [i.uuid for n in snapshot.nodes if n.uuid != node.uuid
              for i in snapshot.node_inbounds(n)]  # fmt: skip
    return [s.uuid for s in squads_holding(list(snapshot.squads), others)]
