"""S7 plan and consent, S8 applying, S9 green report (tech.md §6, §11, §12)."""

from __future__ import annotations

import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from rich import box
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from kerberos.checks import run_checks
from kerberos.checks.score import score
from kerberos.copy import TEXT, t
from kerberos.fixes.engine import Engine
from kerberos.fixes.journal import RunStore, iso
from kerberos.fixes.model import is_applied
from kerberos.fixes.plan import (
    NEEDS_INPUT,
    PERSON_MARKS,
    PlanItem,
    build_plan,
    follow_admin_key,
)
from kerberos.flow import BACK, EXIT_OK, NEXT
from kerberos.report.areas import (
    PLAN_GROUPS,
    area_of,
    area_order,
    area_title,
    fix_short,
    joined,
    plan_group,
    where,
)
from kerberos.report.view import change_target, counts
from kerberos.screens.check import (
    COMPACT_BELOW,
    show_full_report,
    show_pager,
    without_access,
    write_report,
)
from kerberos.ui.keys import hotkey
from kerberos.ui.palette import SYMBOL_FAIL, SYMBOL_OK, SYMBOL_ROLLED_BACK
from kerberos.ui.widgets import (
    Block,
    BlockList,
    BlockRow,
    Checklist,
    Clamp,
    Column,
    Consent,
    Hanging,
    Notice,
    ProgressBoard,
    ScoreBadge,
    Stack,
    TextInput,
    bold,
)

if TYPE_CHECKING:
    from kerberos.app import App, Session

STEP_KEYS = ("backup", "apply", "check", "confirm")


def warning_of(item: PlanItem, kind: str = "remnawave") -> Optional[str]:
    """Warnings of §15 shown before consent, word for word."""
    if item.fix_id == "ssh.key_only":
        return t("fix.key_only.warning")
    if item.fix_id == "ssh.port":
        return t("fix.ssh_port.warning", port=item.params.get("port"))
    if item.fix_id == "self_steal":
        # 3x-ui changes only target and serverNames of its Reality inbounds (§7.6).
        return t("fix.xui_steal.warning") if kind == "3x-ui" else t("fix.self_steal.warning")
    if item.fix_id == "cdn.edge_only":
        return t("fix.edge_only.warning")
    if item.fix_id == "xhttp.padding":
        return t("fix.padding.warning")
    if item.fix_id == "panel.portal":
        return t("fix.portal.warning")
    if item.fix_id == "xui.panel_hide":
        port = item.params.get("port")
        return t("fix.xui_hide.warning", port=port) if port else t("fix.xui_hide.warning.path")
    return None


def extra_warnings(app: App, session: Session, item: PlanItem) -> list[str]:
    """Self-steal also replaces the profile and may restart the node container.

    On 3x-ui there is neither: the inbounds keep their config, the server its Xray.
    """
    if item.fix_id != "self_steal" or session.snapshot.kind == "3x-ui":
        return []
    texts = [t("fix.profile.warning")]
    node = session.data["input"].node_data(item.node_uuid or "")
    own = item.params.get("ownProfile")
    if own:
        name = app.mask(app.session_name(item.node_uuid))
        shared = item.params.get("sharedProfile")
        texts.append(
            t("fix.own_profile.warning", node=name, shared=shared, profile=own)
            if shared
            else t("fix.own_profile.warning.none", node=name, profile=own)
        )
    facts = node.facts if node else {}
    if not (facts.get("remnanode") or {}).get("letsencryptMounted", True):
        texts.append(t("fix.mount.warning", node=app.mask(node.node.name)))
    return texts


def consent_warnings(app: App, session: Session, chosen: list[PlanItem]) -> list[str]:
    """The warnings of the chosen fixes, each once; one text for several new SSH ports."""
    kind = session.snapshot.kind
    ports = [i for i in chosen if i.fix_id == "ssh.port"]
    warnings: list[str] = []
    for item in chosen:
        if item.fix_id == "ssh.port" and len(ports) > 1:
            texts = [t("fix.ssh_port.warning.many", ports=", ".join(
                f"{app.mask(app.session_name(p.node_uuid))}: {p.params.get('port')}"
                for p in ports))]  # fmt: skip
        else:
            texts = [warning_of(item, kind), *extra_warnings(app, session, item)]
        for text in texts:
            if text and text not in warnings:
                warnings.append(text)
    return warnings


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$"
)


def dns_state(app: App, session: Session, item: PlanItem) -> None:
    """§10.4: A must point to the node's IPv4, AAAA (if any) to its IPv6."""
    domain = item.params.get("domain")
    if not domain:
        item.params["dns"] = "none"
        return
    node = session.data["input"].node_data(item.node_uuid or "")
    addresses = app.env.prober.resolve(domain)
    v4 = [a for a in addresses if ":" not in a]
    v6 = [a for a in addresses if ":" in a]
    want4 = node.ipv4
    want6 = (node.facts or {}).get("ipv6", []) if node else []
    ok = bool(want4) and v4 == [want4] and (not v6 or bool(set(v6) & set(want6)))
    item.params["dns"] = "ok" if ok else "wait"
    item.params["record"] = f"A {domain} → {want4}"
    if ok and item.blocked is None and not waits_for_squads(item):
        item.selected = True


def last_domains(app: App) -> dict[str, str]:
    """node uuid -> the domain typed for it in the newest earlier run (K25): its own
    domain did not go through, or went back, so the node is in the plan again."""
    if app.env.state is None:
        return {}
    found: dict[str, str] = {}
    for run in RunStore(app.env.state, app.env.clock).runs():
        for change in run.get("changes") or []:
            params = change.get("params") or {}
            fix_id = str(change.get("fixId", ""))
            node, domain = params.get("node"), params.get("domain")
            if (fix_id.startswith("self_steal") or fix_id == "xui.reality") and node and domain:
                found.setdefault(str(node), str(domain))
    return found


def domain_candidates(session: Session, item: PlanItem, last: dict) -> list[tuple[str, str]]:
    """(name, where from) in the order of §6 S7: the last run, the node's address in the
    panel, the addresses of its visible enabled hosts. Names only, never IP addresses."""
    from kerberos.checks import is_ip

    node = session.snapshot.node(item.node_uuid or "")
    if node is None:
        return []
    found = []
    if last.get(node.uuid):
        found.append((last[node.uuid], t("plan.domain.from.last")))
    found.append((node.address, t("plan.domain.from.node")))
    for host in session.snapshot.node_hosts(node):
        if not host.is_disabled and not host.is_hidden:
            found.append((host.address, t("plan.domain.from.host", host=host.remark)))
    return [(name.strip().lower().rstrip("."), where) for name, where in found
            if name and not is_ip(name.strip())]  # fmt: skip


def prefill_domains(app: App, session: Session, items: list[PlanItem]) -> None:
    """K25: the domain of «Свой домен» the person need not type: one that already
    resolves to the node (§6 S7). The panel's own domain never is one."""
    location = session.location
    panel_domain = ((location.panel_domain if location else "") or "").lower()
    taken = {i.params.get("domain") for i in items if i.fix_id == "self_steal"}
    sources: dict = session.data.setdefault("domain_from", {})
    last = last_domains(app)
    for item in items:
        if item.fix_id != "self_steal" or item.blocked or item.params.get("domain"):
            continue
        before = dict(item.params)
        for name, source in domain_candidates(session, item, last):
            if name == panel_domain or name in taken or not DOMAIN_RE.match(name):
                continue
            item.params["domain"] = name
            dns_state(app, session, item)
            if item.params.get("dns") == "ok":
                app.env.masker.register(name)
                sources[item.node_uuid] = source
                taken.add(name)
                break
            item.params.clear()
            item.params.update(before)
            item.selected = False


def pair_ready(items: list[PlanItem], pair: PlanItem) -> bool:
    """A reserve pair runs only when both nodes move to their domains in this run."""
    wanted = {pair.node_uuid, pair.params["reserve"]}
    ready = {i.node_uuid for i in items if i.fix_id == "self_steal" and i.selected
             and i.params.get("dns") == "ok"}  # fmt: skip
    return wanted <= ready


def choose_reserve(app: App, session: Session, items: list[PlanItem], main: PlanItem) -> None:
    """§6 S7: «Резервная нода» of a main node: another node of this run, or none."""
    from kerberos.fixes.plan import reserve_item
    from kerberos.ui.widgets import Menu

    name = app.session_name(main.node_uuid)
    if main.params.get("reserveOf"):
        # A reserve with its own reserve would be hidden and visible at once (§10.9).
        app.notice("warning", t("plan.reserve.is_reserve", node=app.mask(name),
                                main=app.mask(app.session_name(main.params["reserveOf"]))),
                   t("plan.title"))  # fmt: skip
        return
    others = [i for i in items if i.fix_id == "self_steal" and i is not main
              and not i.params.get("reserve")
              and i.params.get("reserveOf") in (None, main.node_uuid)]  # fmt: skip
    options = [("none", t("plan.reserve.none"), "")]
    options += [(i.node_uuid, app.mask(app.session_name(i.node_uuid)), "") for i in others]
    menu = Menu(options)

    def handle(key: str) -> Optional[str]:
        return "" if key == "esc" else menu.handle(key)

    body = Group(Text(t("plan.reserve", node=app.mask(name)), style="bold"),
                 Text(t("plan.reserve.hint", node=app.mask(name)), style="muted"), Text(""),
                 menu)  # fmt: skip
    keys = (("↑↓", t("keys.select")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
    choice = app.interact(t("plan.title"), body, keys, handle)
    if choice == "":
        return
    for item in items:
        if item.params.get("reserveOf") == main.node_uuid:
            item.params.pop("reserveOf", None)
    main.params.pop("reserve", None)
    items[:] = [i for i in items if not (i.fix_id == "reserve" and i.node_uuid == main.node_uuid)]
    if choice == "none":
        return
    spare = next(i for i in items if i.node_uuid == choice and i.fix_id == "self_steal")
    main.params["reserve"] = spare.node_uuid
    spare.params["reserveOf"] = main.node_uuid
    items.append(reserve_item(main, spare))


def confirm_edges(app: App, session: Session, item: PlanItem) -> None:
    """§10.6: the /24 nets the tunnel path was reached from; the person confirms the list."""
    from kerberos.nodes.transport import NodeAgentError, Target, TransportError

    node = session.snapshot.node(item.node_uuid or "")
    record = app.env.state.node(node.uuid)
    target = record.target(node.address) if record else Target(node.uuid, node.name,
                                                                   node.address, 22)  # fmt: skip
    counts: dict = {}
    for path in item.params["paths"]:
        try:
            answer = app.env.transport.agent(target, "edge-sources", {"path": path})
        except (NodeAgentError, TransportError) as exc:
            code = getattr(exc, "code", None) or getattr(exc, "kind", "")
            app.notice("error", t("plan.edges.failed", reason=error_text(code)), t("plan.title"))
            return
        for row in answer.get("nets") or []:
            if isinstance(row, dict) and isinstance(row.get("net"), str):
                counts[row["net"]] = counts.get(row["net"], 0) + int(row.get("count") or 0)
    if not counts:
        app.notice("warning", t("plan.edges.empty"), t("plan.title"))
        return
    nets = sorted(counts, key=lambda net: (-counts[net], net))
    chosen = set(item.params.get("nets") or nets)
    table = Checklist([[app.mask(net), str(counts[net])] for net in nets],
                      [t("plan.edges.col.net"), t("plan.edges.col.count")],
                      selected={i for i, net in enumerate(nets) if net in chosen})  # fmt: skip

    def body(_w: int, height: int) -> RenderableType:
        table.viewport = max(4, height - 5)
        return Group(Text(t("plan.edges.title", node=app.mask(node.name)), style="bold"),
                     Text(t("plan.edges.hint"), style="muted"), table)  # fmt: skip

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        result = table.handle(key)
        return "done" if result == "done" and table.selected else None

    keys = ((t("keys.space"), t("keys.toggle")), ("Enter", t("plan.edges.confirm")),
            ("Esc", t("keys.back")))  # fmt: skip
    if app.interact(t("plan.title"), body, keys, handle) == "done":
        item.params["nets"] = [net for i, net in enumerate(nets) if i in table.selected]
        if item.blocked is None:
            item.selected = True


def choose_squads(app: App, session: Session, item: PlanItem) -> None:
    """§10.4 (K24): the squads whose users get the node, when none holds its inbounds."""
    from kerberos.fixes.own_profile import suggested_squads

    node = session.snapshot.node(item.node_uuid or "")
    squads = list(session.snapshot.squads)
    chosen = set(item.params.get("squads") or suggested_squads(session.snapshot, node))
    rows = [[s.name, "" if s.members is None else str(s.members)] for s in squads]
    table = Checklist(rows, [t("plan.squads.col.name"), t("plan.squads.col.members")],
                      selected={i for i, s in enumerate(squads) if s.uuid in chosen})  # fmt: skip

    def body(_w: int, height: int) -> RenderableType:
        table.viewport = max(4, height - 6)
        return Group(Text(t("plan.squads.title", node=app.mask(node.name)), style="bold"),
                     Text(t("plan.squads.hint"), style="muted"), table)  # fmt: skip

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        result = table.handle(key)
        return "done" if result == "done" and table.selected else None

    keys = ((t("keys.space"), t("keys.toggle")), ("Enter", t("plan.squads.confirm")),
            ("Esc", t("keys.back")))  # fmt: skip
    if app.interact(t("plan.title"), body, keys, handle) == "done":
        item.params["squads"] = [s.uuid for i, s in enumerate(squads) if i in table.selected]
        if item.blocked is None and item.params.get("dns") == "ok":
            item.selected = True


def ask_domain(app: App, session: Session, item: PlanItem) -> None:
    node = session.snapshot.node(item.node_uuid or "")
    data = session.data["input"].node_data(item.node_uuid or "")
    ipv4 = data.ipv4 if data else None
    field = TextInput(
        t("plan.domain.label", node=app.mask(node.name if node else "")),
        hint=t("plan.domain.hint", ip=app.mask(ipv4)) if ipv4 else t("plan.domain.hint.no_ip"),
        validate=lambda v: None if DOMAIN_RE.match(v.strip().lower()) else t("plan.domain.invalid"),
        value=item.params.get("domain") or "",
    )

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return ""
        return field.handle(key)

    keys = (("Enter", t("keys.next")), ("Esc", t("keys.back")))
    value = app.interact(t("plan.title"), field, keys, handle, typing=True).strip().lower()
    if value:
        app.env.masker.register(value)
        if value != item.params.get("domain"):
            session.data.get("domain_from", {}).pop(item.node_uuid, None)
        item.params["domain"] = value
        dns_state(app, session, item)


def launcher() -> str:
    return str(Path(__file__).resolve().parent.parent.parent.parent / "kerberos")


def rollback_command(run_id: str) -> str:
    return f"sudo {launcher()} rollback {run_id}"


def fix_label(app: App, item: Any) -> str:
    fix_id = item.fix_id if isinstance(item, PlanItem) else item["fixId"]
    params = item.params if isinstance(item, PlanItem) else item["params"]
    ports = ", ".join(params.get("ports", []))
    spare = params.get("reserve")
    label = t(f"fix.{fix_id}.label", ports=ports, port=params.get("port", ""),
              domain=params.get("domain") or "…", nets=len(params.get("nets") or []),
              reserve=app.session_name(spare) if spare else "",
              profile=params.get("profile", ""))  # fmt: skip
    return app.mask(label)


def node_name(session: Session, target: str, params: Optional[dict] = None) -> str:
    """Who a change belongs to: a node, a host, a template or the panel."""
    names = {n.uuid: n.name for n in session.snapshot.nodes}
    return change_target(target, params or {}, names)


def node_renewals(session: Session, target: str) -> list:
    """Certificates of the node that renew on :80 themselves: self-steal moves them
    to the webroot of its nginx (§10.4, K16)."""
    uuid = target.partition(":")[2]
    for data in session.data["input"].nodes:
        if data.node.uuid == uuid:
            return [r for r in (data.facts or {}).get("acme") or [] if not r.get("blocked")]
    return []


def renewals_text(app: App, renewals: list) -> str:
    return ", ".join(f"{app.mask(str(r.get('name', '')))} ({r.get('tool', '')})"
                     for r in renewals)  # fmt: skip


def error_text(code: Optional[str]) -> str:
    if not code:
        return ""
    return TEXT.get(f"error.{code}", code)


def site_preview(app: App, session: Session, item: PlanItem) -> Text:
    """§10.4: what the stub site of the node will be, with its colours (g draws another).

    Without colour the samples would be three equal blocks: they are left out.
    """
    from kerberos.agent import site_spec

    spec = site_spec(item.params.get("siteSeed", 0))
    theme = spec["theme"]
    line = Text(t("plan.site", node=app.mask(app.session_name(item.node_uuid)),
                  title=spec["title"], kind=t(f"site.kind.{spec['kind']}")))  # fmt: skip
    if app.term.color:
        for key in ("background", "text", "accent"):
            line.append(" ")
            line.append("██", style=theme[key])
    line.append("  " + t("plan.site.again"), style="muted")
    return line


def new_site(session: Session, item: PlanItem) -> None:
    """Another random stub site for the node, still unlike the other nodes' sites."""
    from kerberos.agent import site_html, template_hash
    from kerberos.fixes.plan import free_site_seed, site_layouts_in_use

    data = session.data["input"]
    used = site_layouts_in_use(data)
    for other in session.data["plan"]:
        if other.fix_id == "self_steal":
            used.add(template_hash(site_html(other.params.get("siteSeed", 0), "example.com")))
    rng = session.data.setdefault("rng", random.SystemRandom())
    item.params["siteSeed"] = free_site_seed(used, rng)


def waits_for_squads(item: PlanItem) -> bool:
    """K24: no squad holds the node's inbounds and the panel has several: the person picks."""
    return bool(item.params.get("pickSquads")) and not item.params.get("squads")


def waits_for_input(item: PlanItem) -> bool:
    if item.fix_id == "self_steal":
        return item.params.get("dns") != "ok" or waits_for_squads(item)
    if item.fix_id == "cdn.edge_only":
        return not item.params.get("nets")
    if item.fix_id == "panel.portal":
        return not item.params.get("login")
    return False


def ask_portal_login(app: App, session: Session, item: PlanItem) -> None:
    """§10.10: the login and password of the portal, typed twice; they stay in memory
    (the password never reaches the plan or the journal) until the env file is written."""
    from kerberos.fixes.portal import LOGIN_RE, PASSWORD_RE

    fields = [TextInput(t("plan.portal.login"), value=item.params.get("login") or ""),
              TextInput(t("plan.portal.password"), secret=True),
              TextInput(t("plan.portal.repeat"), secret=True)]  # fmt: skip
    state: dict[str, Any] = {"focus": 0, "error": None}

    def body(_w: int, _h: int) -> RenderableType:
        for i, field in enumerate(fields):
            field.focused = i == state["focus"]
        parts: list[RenderableType] = [
            Text(t("plan.portal.title"), style="bold"),
            Text(t("plan.portal.hint"), style="muted"),
            Text(""),
        ]
        for field in fields:
            parts += [field, Text("")]
        if state["error"]:
            parts.append(Notice("error", state["error"]))
        return Group(*parts)

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        if key in ("tab", "down"):
            state["focus"] = (state["focus"] + 1) % len(fields)
            return None
        if key == "up":
            state["focus"] = (state["focus"] - 1) % len(fields)
            return None
        if key == "enter":
            if state["focus"] < len(fields) - 1:
                state["focus"] += 1
                return None
            return "submit"
        fields[state["focus"]].handle(key)
        state["error"] = None
        return None

    keys = (("Tab", t("keys.field")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
    try:
        while app.interact(t("plan.title"), body, keys, handle, typing=True) == "submit":
            login = fields[0].value.strip()
            password = fields[1].value
            if not LOGIN_RE.fullmatch(login):
                state["error"], state["focus"] = t("plan.portal.bad_login"), 0
            elif not PASSWORD_RE.fullmatch(password):
                state["error"], state["focus"] = t("plan.portal.bad_password"), 1
            elif password != fields[2].value:
                state["error"], state["focus"] = t("plan.portal.mismatch"), 2
            else:
                session.data["portal"] = {"login": login, "password": password}
                item.params["login"] = login
                item.selected = True
                return
            fields[1].clear()
            fields[2].clear()
    finally:
        for field in fields[1:]:
            field.clear()


# -- S7 -------------------------------------------------------------------------
DETAILS_LINES = 3
PLAN_COLUMNS = [Column(most=3), Column(most=22), Column(flex=1, least=16),
                Column(most=18, least=6)]  # fmt: skip
DOMAIN_COLUMNS = [Column(most=3), Column(most=14), Column(flex=1, least=12), Column(most=14),
                  Column(flex=1, least=10)]  # fmt: skip
# What a group row asks before its items can be marked (e, p work on the group row too).
NEEDS = {"self_steal": "plan.need_domain", "cdn.edge_only": "plan.need_edges",
         "panel.portal": "plan.need_portal"}  # fmt: skip


def need_of(item: PlanItem) -> str:
    """What a marked row still waits for: the domain, then the squads (K24)."""
    if item.fix_id == "self_steal" and item.params.get("dns") == "ok" and waits_for_squads(item):
        return t("plan.need_squads")
    return t(NEEDS[item.fix_id])


def blocked_text(item: PlanItem) -> str:
    if item.blocked == "shared_other":
        return t("plan.blocked.shared_other", tags=", ".join(item.params.get("otherInbounds", [])))
    return t(f"plan.blocked.{item.blocked}")


def note_of(app: App, item: PlanItem) -> str:
    """The «Заметка» of a row: why it is off, what it waits for, its reserve."""
    if item.blocked:
        return blocked_text(item)
    note = ""
    if item.fix_id == "self_steal":
        state = item.params.get("dns")
        if state == "ok":
            note = t("plan.domain.ok")
        elif state == "wait":
            note = t("plan.domain.waiting")
        else:
            note = t("plan.domain.none")
        if item.params.get("reserve"):
            note += " · " + t("plan.reserve.with", node=app.session_name(item.params["reserve"]))
        if item.params.get("reserveOf"):
            note += " · " + t("plan.reserve.of", node=app.session_name(item.params["reserveOf"]))
    elif item.fix_id == "cdn.edge_only":
        nets = item.params.get("nets")
        note = t("plan.edges.ok", n=len(nets)) if nets else t("plan.edges.none")
    elif item.fix_id == "panel.portal":
        login = item.params.get("login")
        note = t("plan.portal.ok", login=login) if login else t("plan.portal.none")
    elif warning_of(item):
        note = t("plan.has_warning")
    return app.mask(note)


def plan_details(app: App, session: Session, item: PlanItem) -> RenderableType:
    """Under the table: the current row in full, why it is off and its warning."""
    name = app.mask(node_name(session, item.target, item.params))
    head = Text(f"{name}: {fix_label(app, item)}", style="bold")
    note = note_of(app, item)
    if note and item.fix_id in NEEDS_INPUT and not item.blocked:
        head.append(" · " + note, style="")  # the domain, its DNS, the reserve, the nets
    lines: list[RenderableType] = [head]
    if item.blocked:
        lines.append(Text(t("plan.details.blocked", reason=note), style="risk.medium"))
    else:
        source = session.data.get("domain_from", {}).get(item.node_uuid)
        if item.fix_id == "self_steal" and source and item.params.get("domain"):
            lines.append(Text(t("plan.domain.found", domain=app.mask(item.params["domain"]),
                                where=app.mask(source)), style="muted"))  # fmt: skip
        if item.fix_id == "self_steal" and item.params.get("dns") == "wait":
            # The record to make, in full: the table column is too narrow for it.
            lines.append(Text(t("plan.domain.wait", record=app.mask(item.params["record"])),
                              style="risk.medium"))  # fmt: skip
        if item.fix_id == "self_steal" and item.params.get("ownProfile"):
            lines.append(Text(own_profile_line(app, session, item), style="muted"))
        if item.fix_id == "self_steal" and item.params.get("squads") and item.params.get(
                "pickSquads"):  # fmt: skip
            names = [s.name for s in session.snapshot.squads if s.uuid in item.params["squads"]]
            lines.append(Text(t("plan.squads.chosen", names=", ".join(names)), style="muted"))
        if item.fix_id == "self_steal":
            lines.append(site_preview(app, session, item))
            renewals = node_renewals(session, item.target)
            if renewals:
                lines.append(Text(t("plan.renewals", names=renewals_text(app, renewals)),
                                  style="muted"))  # fmt: skip
        warning = warning_of(item, session.snapshot.kind)
        if warning:
            lines.append(Text(t("plan.details.warning", text=warning), style="muted"))
    return Clamp(Group(*lines), DETAILS_LINES, pad=True)


def own_profile_line(app: App, session: Session, item: PlanItem) -> str:
    """«Свой профиль «KERBEROS NL-1» вместо общего «Default» (с de-1, nl-2)» (K24)."""
    own = item.params["ownProfile"]
    shared = item.params.get("sharedProfile")
    if not shared:
        return t("plan.own_profile.none", profile=own)
    node = session.snapshot.node(item.node_uuid or "")
    profile = session.snapshot.node_profile(node) if node else None
    others = [
        n.name
        for n in session.snapshot.nodes
        if profile and n.uuid in profile.node_uuids and n.uuid != item.node_uuid
    ]
    return t("plan.own_profile", profile=own, shared=shared,
             nodes=app.mask(where(others)))  # fmt: skip


@dataclass
class PlanRow:
    """A row of S7 (K23): a group of measures, one item of an open group, or the own
    domain of a node."""

    kind: str  # "group", "item" or "domain"
    group: str
    indexes: list


def plan_rows(items: list[PlanItem], expanded: set) -> tuple[list[PlanRow], list[PlanRow]]:
    """The rows of the two blocks of S7: a row a group of measures, its items under it
    when open; a row a node for its own domain. A reserve pair shows in the row of its
    main node: it is chosen there (r)."""
    groups: dict[str, list[int]] = {}
    domains = []
    for i, item in enumerate(items):
        if item.fix_id == "self_steal":
            domains.append(PlanRow("domain", "domain", [i]))
        elif item.fix_id != "reserve":
            groups.setdefault(plan_group(item.fix_id), []).append(i)
    upper: list[PlanRow] = []
    order = [g for g in PLAN_GROUPS if g in groups] + [g for g in groups if g not in PLAN_GROUPS]
    for group in order:
        upper.append(PlanRow("group", group, groups[group]))
        if group in expanded:
            upper += [PlanRow("item", group, [i]) for i in groups[group]]
    return upper, domains


def free_items(items: list[PlanItem], row: PlanRow) -> list[PlanItem]:
    return [items[i] for i in row.indexes if not items[i].blocked]


def mark_of(items: list[PlanItem], row: PlanRow) -> str:
    """[✓] all, [ ] none, [~] a part of a group; « - » when nothing in it can run."""
    free = free_items(items, row)
    if not free:
        return " - "
    marked = sum(1 for item in free if item.selected)
    if marked == len(free):
        return "[✓]"
    return "[~]" if marked else "[ ]"


def targets_where(app: App, session: Session, chosen: list[PlanItem]) -> str:
    nodes, others = [], []
    for item in chosen:
        name = app.mask(node_name(session, item.target, item.params))
        (nodes if item.node_uuid or item.params.get("node") else others).append(name)
    return where(nodes, others)


def group_row(app: App, session: Session, items: list[PlanItem], row: PlanRow) -> BlockRow:
    free = free_items(items, row)
    marked = sum(1 for item in free if item.selected)
    chosen = [items[i] for i in row.indexes]
    if 0 < marked < len(free):
        right = Text(t("plan.partial", n=marked, total=len(free)), style="risk.medium")
    else:
        right = Text(targets_where(app, session, chosen), style="muted")
    key = f"plan.group.{row.group}.desc"  # a group of one measure says what it does
    measures = t(key) if key in TEXT else joined(fix_short(item.fix_id) for item in chosen)
    return BlockRow([Text(mark_of(items, row)), Text(area_title(row.group), style="bold"),
                     Text(measures), right], muted=not free)  # fmt: skip


def item_row(app: App, session: Session, items: list[PlanItem], row: PlanRow) -> BlockRow:
    item = items[row.indexes[0]]
    name = app.mask(node_name(session, item.target, item.params))
    return BlockRow([Text(mark_of(items, row)), Text("  " + name), Text(fix_label(app, item)),
                     Text(note_of(app, item), style="muted")], muted=bool(item.blocked),
                    main=2)  # fmt: skip


def domain_row(app: App, session: Session, items: list[PlanItem], row: PlanRow) -> BlockRow:
    """Node, domain, DNS and what the row waits for: the record to make, else the reserve."""
    item = items[row.indexes[0]]
    domain = item.params.get("domain")
    cell = Text(app.mask(domain)) if domain else Text(t("plan.domain.enter"), style="muted")
    dns = item.params.get("dns")
    if item.blocked:
        state = Text(t("plan.domain.blocked"), style="muted")
        note = Text(blocked_text(item))
    else:
        state = {"ok": Text(t("plan.domain.ok"), style="ok"),
                 "wait": Text("… " + t("plan.domain.waiting"), style="risk.medium")}.get(
            dns, Text(t("plan.domain.none"), style="risk.medium"))  # fmt: skip
        if dns == "wait":
            note = Text(t("plan.domain.record", record=app.mask(item.params.get("record", ""))))
        elif dns == "ok" and waits_for_squads(item):
            note = Text(t("plan.domain.squads"), style="risk.medium")
        elif not domain:
            note = Text("")  # the reserve matters once the node has its domain
        elif item.params.get("reserve"):
            note = Text(app.mask(t("plan.reserve.with",
                                   node=app.session_name(item.params["reserve"]))))  # fmt: skip
        elif item.params.get("reserveOf"):
            note = Text(app.mask(t("plan.reserve.of",
                                   node=app.session_name(item.params["reserveOf"]))))  # fmt: skip
        elif session.snapshot.kind == "3x-ui":
            note = Text("")  # no reserves on 3x-ui (§7.6)
        else:
            note = Text(t("plan.domain.no_reserve"), style="muted")
    name = app.mask(app.session_name(item.node_uuid))
    return BlockRow([Text(mark_of(items, row)), Text(name, style="bold"), cell, state, note],
                    muted=bool(item.blocked))  # fmt: skip


def plan_blocks(app: App, session: Session, items: list[PlanItem], upper: list[PlanRow],
                domains: list[PlanRow]) -> list[Block]:  # fmt: skip
    blocks = []
    if upper:
        rows = [group_row(app, session, items, row) if row.kind == "group"
                else item_row(app, session, items, row) for row in upper]  # fmt: skip
        free = [item for row in upper if row.kind == "group" for item in free_items(items, row)]
        note = t("plan.block.auto.note", n=sum(1 for i in free if i.selected), total=len(free))
        blocks.append(Block(t("plan.block.auto"), rows, PLAN_COLUMNS, "ok", note))
    if domains:
        free = [item for row in domains for item in free_items(items, row)]
        ready = [item for item in free if item.params.get("dns") == "ok"]
        waiting = len(ready) < len(free)
        title = t("plan.block.domain.need") if waiting else t("plan.block.domain")
        rows = [domain_row(app, session, items, row) for row in domains]
        note = t("plan.block.domain.note", n=len(ready), total=len(free))
        blocks.append(Block(title, rows, DOMAIN_COLUMNS, "accent" if waiting else "ok", note))
    return blocks


def group_details(app: App, session: Session, items: list[PlanItem],
                  row: PlanRow) -> RenderableType:  # fmt: skip
    """Under the blocks for a group row: where it runs, how much is marked, its warning."""
    free = free_items(items, row)
    chosen = [items[i] for i in row.indexes]
    head = Text(t("plan.group.details", group=area_title(row.group),
                  where=targets_where(app, session, chosen),
                  n=sum(1 for i in free if i.selected), total=len(free)), style="bold")  # fmt: skip
    lines: list[RenderableType] = [head]
    warnings = consent_warnings(app, session, free)
    if warnings:
        lines.append(Text(t("plan.details.warning", text=warnings[0]), style="muted"))
    return Clamp(Group(*lines), DETAILS_LINES, pad=True)


def step_plan(app: App, session: Session) -> Any:
    data = session.data["input"]
    if "plan" not in session.data:
        records = app.env.state.nodes()
        panel_ips = {uuid: r.panel_ip for uuid, r in records.items()}
        # The demo draws the same ports and stub sites every time: snapshots stay stable.
        session.data["rng"] = random.Random(20261116) if app.env.demo else random.SystemRandom()
        session.data["plan"] = build_plan(
            session.data["findings"], data, session.data.get("admin"), panel_ips,
            session.data["rng"],
        )  # fmt: skip
        prefill_domains(app, session, session.data["plan"])
        # Old names leave by the timer unless the person turns it off (K25); 3x-ui
        # gives KERBEROS no token for a timer (§7.6).
        session.data.setdefault("auto_finalize", session.snapshot.kind != "3x-ui")
    items: list[PlanItem] = session.data["plan"]
    if not items:
        app.notice("info", t("plan.empty"), t("plan.title"))
        return NEXT
    xui = session.snapshot.kind == "3x-ui"
    expanded: set = session.data.setdefault("plan_open", set())
    listing = BlockList()
    state: dict = {"error": None, "next_dns": app.env.clock.monotonic() + 10, "rows": []}

    def layout() -> list[PlanRow]:
        upper, domains = plan_rows(items, expanded)
        listing.blocks = plan_blocks(app, session, items, upper, domains)
        state["rows"] = upper + domains
        return state["rows"]

    def current() -> Optional[PlanRow]:
        rows = state["rows"] or layout()
        listing.current()  # keeps the cursor on a row
        return rows[listing.cursor] if rows else None

    def body(_w: int, _height: int) -> RenderableType:
        follow_admin_key(items)
        layout()
        tail: list[RenderableType] = []
        row = current()
        if row is not None and row.kind == "group" and len(row.indexes) > 1:
            tail.append(group_details(app, session, items, row))
        elif row is not None:
            # One row at a time: records of several waiting domains would push the
            # blocks off a low screen; the rows say which of them wait.
            tail.append(plan_details(app, session, items[row.indexes[0]]))
        if any(i.fix_id == "self_steal" and i.selected for i in items):
            auto = session.data.get("auto_finalize", False)
            key = "plan.finalize.auto" if auto else "plan.finalize.manual"
            if xui:
                key = "plan.finalize.xui"  # no timer: 3x-ui gives KERBEROS no token for it
            tail.append(Text(t(key), style="muted"))
        if state["error"]:
            tail.append(Notice("warning", state["error"]))
        return Stack(listing, *tail, flex=0)

    def tick() -> Optional[str]:
        # Waiting domains are resolved again every 10 seconds (§10.4).
        if app.env.clock.monotonic() >= state["next_dns"]:
            state["next_dns"] = app.env.clock.monotonic() + 10
            for item in items:
                if item.fix_id == "self_steal" and item.params.get("dns") == "wait":
                    dns_state(app, session, item)
        return None

    def mark_all() -> None:
        """`a`: everything that can run now, except the SSH port and the way into the
        panel (§6: the person marks them) and the reserve pairs (chosen with r);
        pressed again, it takes back what it marked."""
        marked = [i for i in items if not (i.blocked or waits_for_input(i) or i.fix_id
                                           in PERSON_MARKS or i.fix_id == "reserve")]  # fmt: skip
        on = not all(i.selected for i in marked)
        for item in marked:
            item.selected = on
        for item in items:
            if waits_for_input(item):
                item.selected = False

    def toggle(row: PlanRow) -> None:
        """Space: the item of the row, or every item of a group that can run now."""
        if row.kind != "group":
            item = items[row.indexes[0]]
            if not item.blocked:
                item.selected = not item.selected
            return
        free = free_items(items, row)
        waiting = [i for i in free if waits_for_input(i)]
        # Rows that wait for input are left out of «all marked»: the group could never
        # be unmarked otherwise. Marked, the group says what they wait for.
        markable = [i for i in free if i not in waiting]
        on = not markable or not all(i.selected for i in markable)
        for item in free:
            item.selected = on and item not in waiting
        if on and waiting:
            state["error"] = need_of(waiting[0])

    def input_item(row: Optional[PlanRow], fix_id: str) -> Optional[PlanItem]:
        """The item a key of input works on: the row's own, or the first of its group."""
        if row is None or row.kind == "domain":
            return None
        return next((items[i] for i in row.indexes
                     if items[i].fix_id == fix_id and not items[i].blocked), None)  # fmt: skip

    def handle(key: str) -> Optional[str]:
        state["error"] = None
        if key == "esc":
            return BACK
        row = current()
        item = items[row.indexes[0]] if row is not None and row.kind == "domain" else None
        free = item is not None and not item.blocked
        if key == "right" and row is not None and row.kind == "group":
            expanded.add(row.group)
            return None
        if key == "left" and row is not None and row.group in expanded:
            expanded.discard(row.group)
            rows = layout()
            listing.cursor = next(i for i, r in enumerate(rows)
                                  if r.kind == "group" and r.group == row.group)  # fmt: skip
            return None
        if key == "space" and row is not None:
            toggle(row)
            follow_admin_key(items)
            return None
        if hotkey(key) == "d" and free:
            ask_domain(app, session, item)
            return None
        if hotkey(key) == "g" and free:
            new_site(session, item)
            return None
        if hotkey(key) == "r" and free and not xui:
            choose_reserve(app, session, items, item)
            return None
        if hotkey(key) == "u" and free and item.params.get("pickSquads"):
            choose_squads(app, session, item)
            return None
        edges = input_item(row, "cdn.edge_only")
        if hotkey(key) == "e" and edges is not None:
            confirm_edges(app, session, edges)
            return None
        portal = input_item(row, "panel.portal")
        if hotkey(key) == "p" and portal is not None:
            ask_portal_login(app, session, portal)
            return None
        if hotkey(key) == "f" and not xui:
            session.data["auto_finalize"] = not session.data.get("auto_finalize", False)
            return None
        if hotkey(key) == "a":
            mark_all()
            follow_admin_key(items)
            return None
        if key == "enter":
            for chosen in items:
                if chosen.selected and not chosen.blocked and waits_for_input(chosen):
                    state["error"] = need_of(chosen)
                    return None
            for chosen in items:
                if chosen.fix_id == "reserve" and chosen.selected and not pair_ready(items, chosen):
                    state["error"] = t("plan.need_reserve")
                    return None
            return "consent" if any(i.selected and not i.blocked for i in items) else None
        listing.handle(key)
        return None

    def keys() -> list[tuple[str, str]]:
        """The footer follows the current row: its own keys first, the rest in `?`."""
        row = current()
        hints: list[tuple[str, str]] = []
        if row is not None and row.kind == "domain":
            if not items[row.indexes[0]].blocked:
                hints.append(("d", t("keys.domain")))
                if not xui:
                    hints.append(("r", t("keys.reserve")))
                if items[row.indexes[0]].params.get("pickSquads"):
                    hints.append(("u", t("keys.squads")))
                hints.append(("g", t("keys.site")))
            hints.append((t("keys.space"), t("keys.toggle")))
        elif row is not None:
            if input_item(row, "cdn.edge_only") is not None:
                hints.append(("e", t("keys.edges")))
            if input_item(row, "panel.portal") is not None:
                hints.append(("p", t("keys.portal")))
            if row.kind == "group":
                hints.append((t("keys.space"), t("keys.toggle_group")))
                opened = row.group in expanded
                hints.append(
                    (
                        "←" if opened else "→",
                        t("keys.close_group") if opened else t("keys.open_group"),
                    )
                )
            else:
                hints += [(t("keys.space"), t("keys.toggle")), ("←", t("keys.close_group"))]
        if len(hints) <= 2:
            hints.append(("a", t("keys.all_but_port")))
        return hints + [("Enter", t("keys.next")), ("Esc", t("keys.back")),
                        ("?", t("keys.help"))]  # fmt: skip

    app.screen_help = t("help.s7.xui" if xui else "help.s7")
    try:
        while True:
            if app.interact(t("plan.title"), body, keys, handle, timeout=1, tick=tick) == BACK:
                return BACK
            follow_admin_key(items)
            if consent(app, session, items):
                return NEXT
    finally:
        app.screen_help = ""


def agree(app: App, title: str, widget: Consent) -> bool:
    """A consent screen (S7, rollback, finalization): Enter agrees, ↑ ↓ PgUp PgDn Home
    End scroll, any other key goes back."""
    return bool(app.interact(title, widget, (), widget.handle, typing=True))


def area_changes(app: App, session: Session, chosen: list[PlanItem]) -> list[tuple[str, str]]:
    """What changes in each area, in words: the measures with their nodes (K23)."""
    xui = session.snapshot.kind == "3x-ui"
    by_area: dict[str, list[PlanItem]] = {}
    for item in chosen:
        by_area.setdefault(area_of(item.fix_id), []).append(item)
    result = []
    for area in sorted(by_area, key=area_order):
        found = by_area[area]
        parts = []
        if area == "domain":
            steals = [i for i in found if i.fix_id == "self_steal"]
            if steals:
                domains = ", ".join(f"{app.mask(i.params.get('domain') or '…')} "
                                    f"({app.mask(app.session_name(i.node_uuid))})"
                                    for i in steals)  # fmt: skip
                parts.append(t("consent.domain.xui" if xui else "consent.domain", domains=domains))
            owns = [f"{app.mask(app.session_name(i.node_uuid))} → {i.params['ownProfile']}"
                    for i in steals if i.params.get("ownProfile")]  # fmt: skip
            if owns:
                parts.append(t("consent.own_profile", profiles=", ".join(owns)))
            for pair in (i for i in found if i.fix_id == "reserve"):
                parts.append(
                    app.mask(
                        t(
                            "consent.reserve",
                            main=app.session_name(pair.node_uuid),
                            spare=app.session_name(pair.params["reserve"]),
                        )
                    )
                )
        else:
            for fix_id in dict.fromkeys(i.fix_id for i in found):
                same = [i for i in found if i.fix_id == fix_id]
                if fix_id == "ssh.port":
                    ports = ", ".join(f"{app.mask(app.session_name(i.node_uuid))} → "
                                      f"{i.params.get('port')}" for i in same)  # fmt: skip
                    parts.append(f"{fix_short(fix_id)}: {ports}")
                elif fix_id == "ports.drop":
                    ports = ", ".join(f"{app.mask(app.session_name(i.node_uuid))} "
                                      f"({', '.join(i.params.get('ports', []))})"
                                      for i in same)  # fmt: skip
                    parts.append(f"{fix_short(fix_id)}: {ports}")
                else:
                    parts.append(f"{fix_short(fix_id)} ({targets_where(app, session, same)})")
        result.append((area_title(area), "; ".join(parts)))
    for item in chosen:
        renewals = node_renewals(session, item.target) if item.fix_id == "self_steal" else []
        if renewals:
            name = app.mask(node_name(session, item.target, item.params))
            result.append(("", t("consent.renewals", node=name,
                                 names=renewals_text(app, renewals))))  # fmt: skip
    return result


def consent(app: App, session: Session, items: list[PlanItem]) -> bool:
    """§6 S7: what changes in every area, then the warnings of §15 word for word (K23)."""
    chosen = [i for i in items if i.selected and not i.blocked]
    table = Table.grid(padding=(0, 2))
    table.add_column(no_wrap=True, style="bold")
    table.add_column(ratio=1)
    for area, words in area_changes(app, session, chosen):
        table.add_row(area, words)
    parts: list[RenderableType] = [
        Panel(
            table,
            title=Text(f" {t('consent.block.what')} ", style="bold"),
            title_align="left",
            subtitle=Text(f" {t('consent.block.what.note', n=len(chosen))} ", style="muted"),
            subtitle_align="right",
            box=box.ROUNDED,
            border_style="muted",
        )  # fmt: skip
    ]
    warnings = consent_warnings(app, session, chosen)
    if warnings:
        bullets = [Hanging(f"• {text}", indent=2) for text in warnings]
        title = bold(f" {t('consent.block.warnings')} ", "risk.medium")
        parts.append(Panel(Group(*bullets), title=title, title_align="left", box=box.ROUNDED,
                           border_style="risk.medium"))  # fmt: skip
    parts.append(Text(t("consent.backup"), style="muted"))
    return agree(app, t("consent.title"), Consent(Group(*parts), t("consent.accept")))


# -- S8 -------------------------------------------------------------------------
def step_apply(app: App, session: Session) -> Any:
    items: list[PlanItem] = session.data["plan"]
    chosen = [i for i in items if i.selected and not i.blocked]
    names = []
    for item in chosen:
        name = node_name(session, item.target, item.params)
        if name not in names:
            names.append(name)
    board = ProgressBoard([app.mask(n) for n in names], [t(f"step.{s}") for s in STEP_KEYS])
    board.node_title, board.fix_title = t("board.node"), t("board.fix")
    board.legend = t("board.legend")

    def on_event(step: str, item: PlanItem, state: str, note: str) -> None:
        name = app.mask(node_name(session, item.target, item.params))
        if step == "backup" and state == "running":
            board.start(name, fix_label(app, item))
        board.set(name, t(f"step.{step}"), state)
        if state in ("failed", "rolled_back"):
            # A change that could not be undone either says so, never «откатил».
            text = (error_text(note) if note == "rollback_failed"
                    else t("apply.rolled_back", reason=error_text(note) or note))  # fmt: skip
            board.finish(name, Text(text, style="risk.high"))

    engine = Engine(app, session, chosen, on_event)
    engine.ask_diff = lambda diff: ask_overwrite(app, diff)
    engine.ask_outside = lambda port, command: ask_outside(app, port, command)
    from kerberos.screens.rollback import ask_old_port

    engine.ask_old_port = lambda port, command: ask_old_port(app, port, command)
    engine.ask_portal = lambda link, login, where: ask_portal(
        app, link, login, where, cancel=engine.cancel
    )
    session.data["engine"] = engine
    app.busy = True

    def tick() -> Optional[str]:
        if engine.done:
            return NEXT
        engine.step()
        return None

    def interrupt() -> Optional[str]:
        body = Group(Notice("warning", t("apply.interrupt")),
                     Text(t("apply.interrupt.keys"), style="muted"))  # fmt: skip
        app.draw(t("s8.title"), body)
        if app.term.read_key() == "enter":
            engine.cancel()
        return None

    keys = (("Ctrl+C", t("keys.interrupt")),)
    try:
        app.interact(t("s8.title"), board, keys, lambda _key: None, timeout=0, tick=tick,
                     interrupt=interrupt, typing=True)  # fmt: skip
    finally:
        app.busy = False
    finish_run(app, session, engine)
    from kerberos.screens.panel import settle_token

    settle_token(app, session.panel)
    if session.data.get("auto_finalize") and session.data["run"]["pending"]:
        from kerberos.fixes.finalize import schedule

        schedule(app, session.data["run"], launcher())
    return NEXT


def ask_outside(app: App, port: int, command: str) -> bool:
    """§7.6: the new SSH port of this server, tried by the person from their computer."""
    body = Group(Notice("warning", t("apply.outside", port=port, command=app.mask(command))),
                 Text(t("apply.outside.keys"), style="muted"))  # fmt: skip
    app.draw(t("s8.title"), body)
    return app.term.read_key() == "enter"


def masked_link(app: App, link: str) -> str:
    """The secret path of a panel link is hidden with the addresses when masking."""
    if not app.env.masker.enabled:
        return link
    head, _, _secret = link.partition("://")[2].partition("/")
    return app.mask(f"{link.partition('://')[0]}://{head}/") + "…"


def ask_portal(app: App, link: str, login: Optional[str], where: str = "",
               cancel: Optional[Any] = None) -> bool:  # fmt: skip
    """§10.10: the person logs in at the new link from their browser; Enter: in, Esc: no.

    Three minutes without an answer count as no: everything goes back. Ctrl+C means no
    too and stops the run after it; `q` is no way out here, it would leave the change
    half confirmed. With masking on, the full link is in the 0600 file `where`.
    """
    from kerberos.fixes.portal import LOGIN_WAIT

    def body(_w: int, _h: int) -> RenderableType:
        text = (t("apply.portal", link=masked_link(app, link), login=login) if login
                else t("apply.xui_panel", link=masked_link(app, link)))  # fmt: skip
        parts: list[RenderableType] = [Notice("warning", text)]
        if app.env.masker.enabled and where:
            parts.append(Text(t("apply.portal.masked", path=where), style="muted"))
        parts.append(Text(t("apply.portal.keys"), style="muted"))
        return Group(*parts)

    deadline = app.env.clock.monotonic() + LOGIN_WAIT

    def handle(key: str) -> Optional[str]:
        return {"enter": "yes", "esc": "no"}.get(key)

    def tick() -> Optional[str]:
        return "no" if app.env.clock.monotonic() >= deadline else None

    def interrupt() -> Optional[str]:
        if cancel is not None:
            cancel()
        return "no"

    keys = (("Enter", t("keys.logged_in")), ("Esc", t("keys.not_logged_in")),
            ("Ctrl+C", t("keys.interrupt")))  # fmt: skip
    return app.interact(t("s8.title"), body, keys, handle, typing=True, timeout=1,
                        tick=tick, interrupt=interrupt) == "yes"  # fmt: skip


def ask_overwrite(app: App, diff: str) -> bool:
    """§10.9: a KERBEROS template was edited in the panel: show how, ask before writing."""
    show_pager(app, t("tpl.diff.intro") + "\n\n" + app.mask(diff), t("s8.title"))
    body = Group(Notice("warning", t("tpl.diff.question")),
                 Text(f"{t('tpl.diff.yes')}    {t('tpl.diff.no')}", style="muted"))  # fmt: skip
    app.draw(t("s8.title"), body)
    return app.term.read_key() == "enter"


def refresh_snapshot(app: App, session: Session) -> None:
    """Panel changes land in the score after: read the panel again."""
    if session.panel is None or session.location is None or session.snapshot is None:
        return
    try:
        if session.snapshot.kind == "3x-ui":
            node = session.snapshot.nodes[0]  # §7.6: the one node is this server
            snapshot = session.panel.snapshot(session.location, node.address, node.name)
        else:
            snapshot = session.panel.snapshot(session.location.version,
                                              session.location.panel_domain)  # fmt: skip
    except Exception:  # noqa: BLE001 - the score after then uses what KERBEROS knows
        return
    session.snapshot = snapshot
    session.data["input"].snapshot = snapshot


def finish_run(app: App, session: Session, engine: Engine) -> None:
    run = session.data["run"]
    refresh_snapshot(app, session)
    data = session.data["input"]
    after = run_checks(data)
    session.data["findings_after"] = after
    run["scoreAfter"] = score(after)
    run["findingsAfter"] = after
    run["interrupted"] = engine.cancelled
    run["finishedAt"] = iso(app.env.clock)
    store = RunStore(app.env.state, app.env.clock)
    store.save(run)
    applied = sum(1 for c in run["changes"] if is_applied(c))
    store.log(run, f"fix: {applied} applied, {engine.failed} failed, {engine.rollback_failed} "
                   f"not rolled back, score {run['scoreAfter']}")  # fmt: skip
    session.data["exit"] = engine.exit_code  # kept if the person quits on S9
    write_report(app, run)


# -- S9 -------------------------------------------------------------------------
def rollback_failed(change: dict) -> bool:
    """The change did not apply and its undo failed too: it may still be on the node."""
    return change.get("error") == "rollback_failed"


def applied(change: dict) -> bool:
    return change["state"] in ("applied", "confirmed") and not rollback_failed(change)


def change_texts(app: App, session: Session, changes: list[dict]) -> list[Text]:
    """The changes of an area, a line each, with what a person needs from them: the
    stub site, the renewals moved to nginx, the host copies, the new host keys."""
    lines: list[Text] = []
    for change in changes:
        name = app.mask(node_name(session, change["target"], change["params"]))
        lines.append(Text(f"✓ {name}: {fix_label(app, change)}", style="ok"))
        details = change["details"]
        site = details.get("site")
        if change["fixId"] == "self_steal.site" and site:
            lines.append(Text("  " + t("s9.site", title=site["title"],
                                       kind=t(f"site.kind.{site['kind']}"),
                                       background=site["background"], accent=site["accent"]),
                              style="muted"))  # fmt: skip
        renewals = details.get("renewals")
        if change["fixId"] == "self_steal.site" and renewals:
            lines.append(Text("  " + t("s9.renewals", names=renewals_text(app, renewals)),
                              style="muted"))  # fmt: skip
        if change["fixId"] == "self_steal.hosts":
            hosts = t("s9.hosts", created=len(details["created"]),
                      disabled=len(details["disabled"]))  # fmt: skip
            lines.append(Text("  " + hosts, style="muted"))
        for key in details.get("hostKeys", []):
            if key.get("type") == "ED25519":
                node = session.snapshot.node(change["target"].partition(":")[2])
                lines.append(Text("  " + t("s9.hostkey", fingerprint=key["fingerprint"],
                                           address=app.mask(node.address if node else "")),
                                  style="muted"))  # fmt: skip
    return lines


def apply_summary(run: dict, findings: list) -> list[RenderableType]:
    """How the run went, then what is left: «Исправит KERBEROS» would read as a promise."""
    changes = run["changes"]
    ok = sum(1 for c in changes if applied(c))
    stuck = sum(1 for c in changes if rollback_failed(c))
    failed = len(changes) - ok - stuck
    line = Text(t("s9.applied", ok=ok, total=len(changes)), style="ok" if ok == len(changes)
                else "bold")  # fmt: skip
    if failed:
        line.append(" " + t("s9.failed", n=failed), style="risk.high")
    if stuck:
        line.append(" " + t("s9.rollback_failed", n=stuck), style="risk.high")
    numbers = counts(findings, {n["uuid"]: n["name"] for n in run["nodes"]})
    if numbers["problems"]:
        left = Text(t("s9.left.line", **numbers), style="bold")
    else:
        left = Text(f"✓ {t('s6.none')}", style="ok")
    return [line, left]


def save_lines(app: App, session: Session, run: dict) -> list[Text]:
    """§10.3, §10.10: the new ways in stand out, a line a node with the command to log
    in now; the new link to the panel; the nodes whose host keys changed."""
    lines: list[Text] = []
    for change in run["changes"]:
        if change["fixId"] != "ssh.port" or change["state"] != "confirmed":
            continue
        node = session.snapshot.node(change["target"].partition(":")[2])
        if node is None or rollback_failed(change):
            continue
        command = f"ssh -p {change['details'].get('newPort')} root@{app.mask(node.address)}"
        lines.append(Text(t("s9.save.ssh", node=app.mask(node.name), command=command),
                          style="bold"))  # fmt: skip
    lines += panel_links(app, run)
    renewed = [app.mask(node_name(session, c["target"], c["params"])) for c in run["changes"]
               if c["fixId"] == "hostkeys.regenerate" and applied(c)]  # fmt: skip
    if renewed:
        lines.append(Text(t("s9.save.hostkeys", nodes=", ".join(renewed)), style="muted"))
    return lines


def panel_links(app: App, run: dict) -> list[Text]:
    """§10.10: the new way into the panel stands out like a new SSH port."""
    from kerberos.fixes.panel_changes import load_snapshot

    lines: list[Text] = []
    for change in run["changes"]:
        if change["fixId"] not in ("panel.portal", "xui.panel_hide"):
            continue
        if change["state"] != "confirmed" or rollback_failed(change):
            continue
        saved = load_snapshot(change["details"].get("linkPath")) or {}
        if not saved.get("link"):
            continue
        link = masked_link(app, saved["link"])
        if change["fixId"] == "panel.portal":
            lines.append(Text(t("s9.portal", link=link), style="accent"))
            lines.append(Text(t("s9.portal.login", login=saved.get("login", "")), style="bold"))
        else:
            lines.append(Text(t("s9.xui_panel", link=link), style="accent"))
    return lines


def framed(title: str, lines: list[RenderableType], style: str, note: str = "",
           compact: bool = False) -> RenderableType:  # fmt: skip
    """A pinned block of S9; in a low terminal its title line without the frame."""
    if compact:
        tail = [Text(note, style="muted")] if note else []
        return Group(bold(title, style), *lines, *tail)
    return Panel(Group(*lines), title=bold(f" {title} ", style), title_align="left",
                 subtitle=Text(f" {note} ", style="muted") if note else None,
                 subtitle_align="right", box=box.ROUNDED, border_style=style)  # fmt: skip


DONE_COLUMNS = [Column(most=1), Column(most=20), Column(flex=1, least=16),
                Column(most=18, least=6)]  # fmt: skip
FAILED_COLUMNS = [Column(most=1), Column(flex=1, least=16)]


def done_blocks(app: App, session: Session, run: dict, findings: list) -> list[Block]:
    """What did not apply, what KERBEROS did a row an area, what is left to the person."""
    from kerberos.report.view import report_blocks

    blocks = []
    failed = []
    for change in run["changes"]:
        if applied(change):
            continue
        name = app.mask(node_name(session, change["target"], change["params"]))
        if rollback_failed(change):
            reason = t("apply.rollback_failed", reason=error_text(change["details"].get("failure")))
            symbol = SYMBOL_FAIL
        else:
            reason = t("apply.rolled_back", reason=error_text(change.get("error")))
            symbol = SYMBOL_ROLLED_BACK
        # The reason under the name, not beside it: a sentence needs the whole width.
        what = Text(f"{name}: {fix_label(app, change)}\n")
        what.append(reason, style="risk.high")
        failed.append(BlockRow([Text(symbol, style="risk.high"), what]))
    if failed:
        blocks.append(Block(t("s9.block.failed"), failed, FAILED_COLUMNS, "risk.high",
                            str(len(failed))))  # fmt: skip
    by_area: dict[str, list[dict]] = {}
    for change in run["changes"]:
        if applied(change):
            by_area.setdefault(area_of(change["fixId"]), []).append(change)
    rows = []
    for area in sorted(by_area, key=area_order):
        changes = by_area[area]
        nodes, others = [], []
        for change in changes:
            name = app.mask(node_name(session, change["target"], change["params"]))
            kind = change["target"].partition(":")[0]
            (nodes if kind == "node" or change["params"].get("node") else others).append(name)
        domains = [
            app.mask(c["params"]["domain"])
            for c in changes
            if c["fixId"] in ("self_steal.site", "xui.reality") and c["params"].get("domain")
        ]
        if area == "domain" and domains:
            measures = joined(domains, 3)  # which names the nodes answer to now
        else:
            measures = joined([fix_short(c["fixId"]) for c in changes], 4)
        rows.append(BlockRow([Text(SYMBOL_OK, style="ok"), Text(area_title(area), style="bold"),
                              Text(measures), Text(where(nodes, others), style="muted")],
                             change_texts(app, session, changes), key=("done", area)))  # fmt: skip
    if rows:
        blocks.append(Block(t("s9.block.done"), rows, DONE_COLUMNS, "ok", t("s9.block.done.note")))
    names = {n["uuid"]: n["name"] for n in run["nodes"]}
    for block in report_blocks(findings, names, app.mask, parts=("manual",)):
        block.title = t("s9.block.left")
        blocks.append(block)
    return blocks


def next_lines(app: App, run: dict, path: str) -> list[RenderableType]:
    """Finalization, rollback and the report: a command on a line of its own, so the
    label never pushes it to a break (it folds only when longer than the screen)."""
    lines: list[RenderableType] = []
    if run.get("pending"):
        # «Automatically» only when the timer is really set (§10.4 step 6).
        if run.get("finalizeTimer"):
            lines.append(Text(t("s9.finalize.auto"), style="accent"))
        else:
            lines += [
                Text(t("s9.finalize"), style="bold"),
                Text(f"sudo {launcher()} finalize {run['runId']}", overflow="fold"),
            ]
    if run["changes"]:
        lines += [
            Text(t("done.rollback"), style="bold"),
            Text(rollback_command(run["runId"]), overflow="fold"),
        ]
    lines.append(Text(t("report.saved", path=app.mask(path)), style="muted", overflow="fold"))
    return lines


# S9 pins more than S6 (the score, the new ways in, the commands): its blocks lose their
# frames sooner, so the list of changes keeps room on a 30-line terminal too.
S9_COMPACT_BELOW = COMPACT_BELOW + 8


def step_done(app: App, session: Session) -> Any:
    run = session.data["run"]
    engine: Engine = session.data.get("engine")
    path = str(RunStore(app.env.state, app.env.clock).path(run["runId"]) / "report.md")
    without = without_access(run)
    after = session.data.get("findings_after", session.data["findings"])
    cancelled = engine is not None and engine.cancelled
    title = t("apply.interrupted.title") if cancelled else t("done.title")
    listing = BlockList()

    def body(_w: int, height: int) -> RenderableType:
        compact = height < S9_COMPACT_BELOW
        summary = apply_summary(run, after)
        if without:
            summary.append(Text(t("s6.no_access", nodes=app.mask("; ".join(without))),
                                style="muted"))  # fmt: skip
        value = run.get("scoreAfter") or run["scoreBefore"]
        if compact:
            top: list[RenderableType] = [ScoreBadge(value, run["scoreBefore"], compact=True),
                                         *summary]  # fmt: skip
        else:
            grid = Table.grid(padding=(0, 2))
            grid.add_column(no_wrap=True)
            grid.add_column(ratio=1)
            grid.add_row(ScoreBadge(value, run["scoreBefore"]), Group(*summary))
            top = [grid]
        if cancelled:
            top.append(Notice("warning", t("apply.interrupted")))
        saves = save_lines(app, session, run)
        if saves:
            admin = app.env.state is not None and app.env.state.admin_key.exists()
            # `kerberos ssh` works only with the administrator key on this server (§8.5).
            note = t("s9.save.kerberos_ssh") if admin and any(
                c["fixId"] == "ssh.port" for c in run["changes"]) else ""  # fmt: skip
            top.append(framed(t("s9.block.save"), saves, "accent", note, compact))
        listing.blocks = done_blocks(app, session, run, after)
        bottom = [framed(t("s9.block.next"), next_lines(app, run, path), "muted",
                         compact=compact)]  # fmt: skip
        if not listing.blocks:
            listing.blocks = [Block(t("s9.block.done"), [BlockRow([Text(""), Text(t("s9.none"))])],
                                    [Column(most=1), Column(flex=1)], "muted")]  # fmt: skip
        return Stack(*top, listing, *bottom, flex=len(top))

    def handle(key: str) -> Optional[str]:
        if key in ("enter", "esc"):
            return "done"
        if hotkey(key) == "s":
            show_full_report(app, run["runId"], title)
            return None
        listing.handle(key)
        return None

    keys = (("↑↓ PgDn", t("keys.scroll")), (t("keys.space"), t("keys.details")),
            ("s", t("keys.full_report")), ("Enter", t("keys.menu")),
            ("?", t("keys.help")))  # fmt: skip
    app.screen_help = t("help.s9")
    try:
        app.interact(title, body, keys, handle)
    finally:
        app.screen_help = ""
    return engine.exit_code if engine is not None else EXIT_OK
