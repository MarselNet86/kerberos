"""Areas: the same groups of measures on S6, the plan, consent and S9 (tech.md §6, K23).

The model keeps its topics of §10.2; areas only group what the screens show, in the
words of a person who is not an administrator. The plan (S7) splits two areas
further: the new SSH port and the way into the panel are the person's own choice and
get rows of their own, unmarked by default.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Optional

from kerberos.copy import TEXT, t

AREAS = ("domain", "access", "scanners", "cdn", "subscription", "watch")

FIX_AREA = {
    # Own domain: every step of self-steal, the 3x-ui variant and the reserve pair.
    "self_steal": "domain",
    "self_steal.site": "domain",
    "node.letsencrypt_mount": "domain",
    "self_steal.own_profile": "domain",
    "self_steal.profile": "domain",
    "self_steal.node": "domain",
    "self_steal.squads": "domain",
    "self_steal.hosts": "domain",
    "xui.reality": "domain",
    "reserve": "domain",
    "access.admin_keys": "access",
    "ssh.key_only": "access",
    "fail2ban.sshd": "access",
    "hostkeys.regenerate": "access",
    "ssh.port": "access",
    "ssh.panel_only": "access",
    "mptcp.guard": "scanners",
    "node_api.panel_only": "scanners",
    "ports.drop": "scanners",
    "panel.portal": "scanners",
    "xui.panel_hide": "scanners",
    "cdn.edge_only": "cdn",
    "xhttp.padding": "cdn",
    "xhttp.uplink_get": "cdn",
    "sub.template": "subscription",
    "sub.templates": "subscription",
    "sub.ping_type": "subscription",
    "host.fingerprint": "subscription",
    "watch.install": "watch",
}

# Rows of the block «KERBEROS сделает сам» in S7, in this order. Own domain is not
# among them: it has a block of its own, a row a node, where the domain is typed.
PLAN_GROUPS = ("access", "ssh_port", "ssh_panel", "scanners", "panel_login", "cdn",
               "subscription", "watch")  # fmt: skip
OWN_GROUP = {"ssh.port": "ssh_port", "ssh.panel_only": "ssh_panel", "panel.portal": "panel_login",
             "xui.panel_hide": "panel_login"}  # fmt: skip


def area_of(fix_id: Optional[str]) -> str:
    return FIX_AREA.get(fix_id or "", "other")


def plan_group(fix_id: str) -> str:
    return OWN_GROUP.get(fix_id) or area_of(fix_id)


def area_order(area: str) -> int:
    return AREAS.index(area) if area in AREAS else len(AREAS)


def area_title(area: str) -> str:
    return t(f"area.{area}") if f"area.{area}" in TEXT else t("area.other")


def fix_short(fix_id: str) -> str:
    """A measure in a few words, for a line that lists several (fix.<id>.short)."""
    key = f"fix.{fix_id}.short"
    return TEXT[key] if key in TEXT else fix_id


def check_short(check_id: str, title: str = "") -> str:
    """What is wrong in a few words (check.<id>.short); the title as the fallback."""
    key = f"check.{check_id}.short"
    if key in TEXT:
        return TEXT[key]
    return title[:1].lower() + title[1:] if title else check_id


def joined(parts: Iterable[str], most: int = 0) -> str:
    """Distinct parts in their first order, comma separated; with `most`, the first
    `most` of them and how many more."""
    distinct = list(dict.fromkeys(p for p in parts if p))
    if most and len(distinct) > most:
        return ", ".join(distinct[:most]) + " " + t("where.more", n=len(distinct) - most)
    return ", ".join(distinct)


def where(names: Iterable[str], others: Iterable[str] = (), most: int = 3) -> str:
    """Who a line is about: up to `most` node names, else their number; then the rest
    (the panel, hosts, templates) by name."""
    nodes = list(dict.fromkeys(n for n in names if n))
    rest = list(dict.fromkeys(o for o in others if o))
    parts = [", ".join(nodes) if len(nodes) <= most else t("where.nodes", n=len(nodes))]
    parts = [p for p in parts if p] + rest[:most]
    more = f" {t('where.more', n=len(rest) - most)}" if len(rest) > most else ""
    return ", ".join(parts) + more
