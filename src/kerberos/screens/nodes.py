"""S3. Nodes (tech.md §6): which nodes to protect.

Space marks, `a` marks all, Enter goes on. Nodes disabled in the panel are
muted and cannot be marked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from rich.console import Group, RenderableType
from rich.text import Text

from kerberos.copy import t
from kerberos.flow import BACK, NEXT
from kerberos.panel.model import Inbound, Node, PanelSnapshot
from kerberos.screens.panel import panel_line
from kerberos.ui.widgets import Checklist, Notice

if TYPE_CHECKING:
    from kerberos.app import App, Session


def protocol_label(inbound: Inbound) -> str:
    kind = (inbound.type or "").lower()
    if kind == "vless" and inbound.security == "reality":
        return "Reality"
    if kind == "vless" and inbound.network == "xhttp":
        return "XHTTP"
    if kind in ("hysteria", "hysteria2"):
        return "Hysteria2"
    if kind == "vless":
        return "VLESS"
    return kind.capitalize() or "?"


def protocols(snapshot: PanelSnapshot, node: Node) -> str:
    labels: list[str] = []
    for inbound in snapshot.node_inbounds(node):
        label = protocol_label(inbound)
        if label not in labels:
            labels.append(label)
    return ", ".join(labels) or "—"


def role(snapshot: PanelSnapshot, node: Node) -> str:
    hosts = [h for h in snapshot.node_hosts(node) if not h.is_disabled]
    if not hosts:
        return "—"
    if any(not h.is_hidden for h in hosts):
        return t("nodes.role.main")
    return t("nodes.role.reserve")


def status(node: Node) -> Text:
    if node.is_disabled:
        return Text(t("nodes.status.disabled"))
    if node.is_connected:
        return Text(f"✓ {t('nodes.status.connected')}", style="ok")
    return Text(f"✗ {t('nodes.status.offline')}", style="risk.high")


def keys() -> tuple:
    return (
        ("↑↓", t("keys.select")),
        (t("keys.space"), t("keys.toggle")),
        ("a", t("keys.all")),
        ("Enter", t("keys.next")),
        ("Esc", t("keys.back")),
        ("q", t("keys.quit")),
    )


def step(app: App, session: Session) -> Any:
    snapshot = session.snapshot
    assert snapshot is not None
    if snapshot.kind == "3x-ui":
        # One server, the one KERBEROS runs on: nothing to choose (§7.6). Esc on S4
        # passes through to S2 instead of opening S4 again.
        session.selected = [n.uuid for n in snapshot.nodes]
        return BACK if session.data.pop("back_from_access", False) else NEXT
    session.data.pop("back_from_access", None)
    nodes = snapshot.nodes
    disabled = {i for i, n in enumerate(nodes) if n.is_disabled}
    if session.selected:
        selected = {i for i, n in enumerate(nodes) if n.uuid in session.selected}
    else:
        selected = {i for i in range(len(nodes)) if i not in disabled}
    columns = [
        t("nodes.col.country"),
        t("nodes.col.name"),
        t("nodes.col.address"),
        t("nodes.col.status"),
        t("nodes.col.online"),
        t("nodes.col.protocols"),
        t("nodes.col.role"),
    ]
    checklist = Checklist([], columns, selected=selected, disabled=disabled)
    state: dict[str, Optional[str]] = {"error": None}

    def rows() -> list[list[Any]]:
        return [
            [
                node.country,
                app.mask(node.name),
                app.mask(node.address),
                status(node),
                str(node.users_online),
                protocols(snapshot, node),
                role(snapshot, node),
            ]
            for node in nodes
        ]

    def body(_w: int, height: int) -> RenderableType:
        checklist.rows = rows()
        head = [*panel_line(app, session), Text(t("nodes.title"), style="bold")]
        tail: list[RenderableType] = [
            Text(t("nodes.selected", n=len(checklist.selected), total=len(nodes)), style="muted")
        ]
        if disabled:
            tail.append(Text(t("nodes.disabled_hint"), style="muted"))
        if state["error"]:
            tail.append(Notice("warning", state["error"]))
        checklist.viewport = max(4, height - len(head) - len(tail) - (3 if state["error"] else 0))
        return Group(*head, checklist, *tail)

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return BACK
        state["error"] = None
        if checklist.handle(key) == "done":
            if not checklist.selected:
                state["error"] = t("nodes.need_one")
                return None
            return NEXT
        return None

    result = app.interact(t("s3.title"), body, keys(), handle)
    session.selected = [nodes[i].uuid for i in sorted(checklist.selected)]
    return result
