"""Normalised panel objects (tech.md §7.4).

The panel answers in two host forms (`tags` + `xhttpExtraParams` on the live
backend 2.8.1, `tag` + `xHttpExtraParams` in the npm contract). Inside
KERBEROS a host always has `tags: list[str]` and `xhttp_extra`; `raw` keeps
the object exactly as the panel sent it, for copies and snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Inbound:
    uuid: str
    tag: str
    type: str
    network: Optional[str] = None
    security: Optional[str] = None
    port: Optional[int] = None
    profile_uuid: str = ""


@dataclass
class Profile:
    uuid: str
    name: str
    config: dict
    inbounds: list[Inbound] = field(default_factory=list)
    node_uuids: list[str] = field(default_factory=list)

    def inbound_config(self, tag: str) -> Optional[dict]:
        for inbound in self.config.get("inbounds") or []:
            if isinstance(inbound, dict) and inbound.get("tag") == tag:
                return inbound
        return None


@dataclass
class Node:
    uuid: str
    name: str
    address: str
    port: int
    is_connected: bool
    is_disabled: bool
    country: str
    users_online: int
    profile_uuid: Optional[str] = None
    inbound_uuids: list[str] = field(default_factory=list)


@dataclass
class Host:
    uuid: str
    remark: str
    address: str
    port: int
    sni: str
    fingerprint: str
    is_disabled: bool
    is_hidden: bool
    tags: list[str]
    xhttp_extra: Optional[dict]
    profile_uuid: Optional[str]
    inbound_uuid: Optional[str]
    template_uuid: Optional[str]
    override_sni: bool
    view_position: Optional[int]
    raw: dict = field(default_factory=dict, repr=False)


@dataclass
class Template:
    uuid: str
    name: str
    type: str
    json: Optional[dict] = None


@dataclass
class Squad:
    uuid: str
    name: str
    inbound_uuids: list[str] = field(default_factory=list)
    members: Optional[int] = None  # info.membersCount: how many users the squad has


@dataclass
class SubSettings:
    uuid: str
    headers: dict = field(default_factory=dict)


@dataclass
class PanelSnapshot:
    """Everything KERBEROS reads from the panel for one run."""

    version: str
    nodes: list[Node]
    hosts: list[Host]
    profiles: list[Profile] = field(default_factory=list)
    templates: list[Template] = field(default_factory=list)
    squads: list[Squad] = field(default_factory=list)
    sub_settings: Optional[SubSettings] = None
    host_shape: str = "tags"
    panel_domain: Optional[str] = None
    # 3x-ui (tech.md §7.6): one server is panel and node at once; its inbounds,
    # the web panel and the subscription listen on ports meant to be public.
    kind: str = "remnawave"
    open_ports: dict = field(default_factory=dict)  # node uuid -> [(port, proto)]
    panel_info: dict = field(default_factory=dict)  # {port, secretPath, tls, listen}

    def node(self, uuid: str) -> Optional[Node]:
        return next((n for n in self.nodes if n.uuid == uuid), None)

    def profile(self, uuid: Optional[str]) -> Optional[Profile]:
        return next((p for p in self.profiles if p.uuid == uuid), None)

    def node_profile(self, node: Node) -> Optional[Profile]:
        return self.profile(node.profile_uuid)

    def node_inbounds(self, node: Node) -> list[Inbound]:
        profile = self.node_profile(node)
        if not profile:
            return []
        if node.inbound_uuids:
            return [i for i in profile.inbounds if i.uuid in node.inbound_uuids]
        return list(profile.inbounds)

    def node_hosts(self, node: Node) -> list[Host]:
        inbounds = {i.uuid for i in self.node_inbounds(node)}
        hosts = [h for h in self.hosts if h.inbound_uuid in inbounds]
        profile = self.node_profile(node)
        if profile and len(profile.node_uuids) > 1:
            # A shared profile: the host belongs to this node when the panel
            # binds it to the node, or else when it points at its address.
            def mine(host: Host) -> bool:
                bound = host.raw.get("nodes")
                if isinstance(bound, list) and bound:
                    ids = {b.get("uuid") if isinstance(b, dict) else b for b in bound}
                    return node.uuid in ids
                return host.address == node.address

            hosts = [h for h in hosts if mine(h)]
        return hosts

    def template(self, uuid: Optional[str]) -> Optional[Template]:
        return next((t for t in self.templates if t.uuid == uuid), None)
