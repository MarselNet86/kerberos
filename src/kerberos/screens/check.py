"""S5 collection and S6 red report (tech.md §6, §10, §12).

S5 reads the fleet without changing anything: agent facts, observation,
sites, outside probes, whois only after consent. S6 shows the score and the
findings in blocks (K23) and saves the report; in «Проверка» this is the end.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from rich import box
from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from kerberos.checks import run_checks
from kerberos.checks.collect import STEPS, collect_in_background
from kerberos.checks.score import score
from kerberos.copy import t
from kerberos.fixes.journal import RunStore
from kerberos.fixes.model import Run
from kerberos.flow import BACK, NEXT
from kerberos.report import markdown
from kerberos.report.view import counts, projected, report_blocks
from kerberos.ui.keys import hotkey
from kerberos.ui.widgets import STEP_VIEW, BlockList, Menu, Notice, Pager, ScoreBadge, Stack

if TYPE_CHECKING:
    from kerberos.app import App, Session


def node_entries(session: Session) -> list[dict]:
    records = session.data.get("records", {})
    access = session.data.get("access", {})
    reasons = session.data.get("access_reason", {})
    entries = []
    for node in session.snapshot.nodes:
        if node.uuid not in session.selected:
            continue
        record = records.get(node.uuid)
        entry = {
            "uuid": node.uuid,
            "name": node.name,
            "address": node.address,
            "sshPort": record.ssh_port if record else 22,
            "access": access.get(node.uuid, "none"),
        }
        if entry["access"] != "ok" and reasons.get(node.uuid):
            entry["accessReason"] = reasons[node.uuid]
        entries.append(entry)
    return entries


def without_access(run: Run) -> list[str]:
    """Nodes without access, grouped by why (§6): «nl-1, nl-2 (пускает только по ключу)»."""
    groups: dict[str, list[str]] = {}
    for node in run["nodes"]:
        if node["access"] != "ok":
            groups.setdefault(node.get("accessReason") or "", []).append(node["name"])
    return [", ".join(names) + (f" ({why})" if why else "") for why, names in groups.items()]


def ask_whois(app: App, session: Session) -> Optional[bool]:
    menu = Menu([("yes", t("s5.whois.yes"), ""), ("no", t("s5.whois.no"), "")])

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        return menu.handle(key)

    body = Group(Text(t("s5.whois.question")), Text(""), menu)
    keys = (("↑↓", t("keys.select")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
    answer = app.interact(t("s5.title"), body, keys, handle)
    return None if answer == "back" else answer == "yes"


def progress_table(app: App, session: Session, progress: Any) -> Table:
    table = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False, pad_edge=False)
    table.add_column(t("s5.col.node"), no_wrap=True, header_style="muted")
    for step in STEPS:
        table.add_column(t(f"s5.step.{step}"), justify="center", header_style="muted")
    for node in session.snapshot.nodes:
        if node.uuid not in session.selected:
            continue
        cells = []
        for step in STEPS:
            symbol, style = STEP_VIEW[progress.cells.get((node.uuid, step), "pending")]
            cells.append(Text(symbol, style=style))
        table.add_row(app.mask(node.name), *cells)
    return table


def step_collect(app: App, session: Session) -> Any:
    if session.data.pop("back_from_report", False):
        # Esc on S6 goes back past the collection: nothing is asked or read again.
        return BACK
    whois = False
    candidates = [n for n in session.snapshot.nodes if n.uuid in session.selected]
    if len(candidates) >= 2:
        # Asked once (K25): the answer is kept, `w` on the summary of S4 changes it.
        state = app.env.state
        remembered = state.answers().get("whois") if state is not None else None
        if remembered is None:
            answer = ask_whois(app, session)
            if answer is None:
                return BACK
            if state is not None:
                state.remember(whois=answer)
            remembered = answer
        whois = remembered
    session.data["records"] = app.env.state.nodes() if app.env.state else {}
    progress, box_ = collect_in_background(
        app.env, session.snapshot, session.selected, session.data.get("access", {}), whois
    )

    def body(_w: int, _h: int) -> RenderableType:
        return Group(Text(t("s5.collecting"), style="bold"), Text(""),
                     progress_table(app, session, progress))  # fmt: skip

    def tick() -> Optional[str]:
        box_["thread"].join(0.2)  # wait for the collection, keys stay in the queue
        return NEXT if progress.done else None

    keys = (("q", t("keys.quit")),)
    app.interact(t("s5.title"), body, keys, lambda _key: None, timeout=0, tick=tick)
    box_["thread"].join()
    if progress.error is not None:
        app.notice("error", t("s5.failed", error=type(progress.error).__name__), t("s5.title"))
        return BACK
    data = box_["input"]
    for item in data.nodes:
        if item.access != session.data.get("access", {}).get(item.node.uuid):
            session.data.setdefault("access", {})[item.node.uuid] = item.access
    findings = run_checks(data)
    session.data["input"] = data
    session.data["findings"] = findings
    session.data["score"] = score(findings)
    save_check_run(app, session)
    return NEXT


def save_check_run(app: App, session: Session) -> Run:
    store = RunStore(app.env.state, app.env.clock)
    snapshot = session.snapshot
    run = session.data.get("run")
    if run is None:
        xui = snapshot.kind == "3x-ui"
        # The address of a 3x-ui panel holds its secret path: it stays out of the run.
        api = session.location.api if session.location and not xui else ""
        panel = {"version": snapshot.version, "nodes": len(snapshot.nodes),
                 "hosts": len(snapshot.hosts), "api": api, "kind": snapshot.kind}  # fmt: skip
        run = store.new_run(session.mode, panel, node_entries(session))
        session.data["run"] = run
    run["nodes"] = node_entries(session)
    run["findings"] = session.data["findings"]
    run["scoreBefore"] = session.data["score"]
    if session.mode == "check":
        from kerberos.fixes.journal import iso

        run["finishedAt"] = iso(app.env.clock)
    store.save(run)
    store.log(run, f"{session.mode}: {len(run['findings'])} findings, score {run['scoreBefore']}")
    for node in run["nodes"]:
        if node["access"] != "ok":
            why = f" ({node['accessReason']})" if node.get("accessReason") else ""
            store.log(run, f"access {node['name']}: {node['access']}{why}")
    write_report(app, run)
    return run


def write_report(app: App, run: Run) -> str:
    store = RunStore(app.env.state, app.env.clock)
    masker = app.env.masker
    text = markdown.render(run, masker.text if masker.enabled else None)
    masked = masker.data(run) if masker.enabled else None
    path = store.write_report(run, text, masked)
    return str(path)


def show_pager(app: App, text: str, title: str) -> None:
    pager = Pager(text)

    def body(_w: int, height: int) -> RenderableType:
        pager.viewport = height
        return pager

    def handle(key: str) -> Optional[str]:
        if key in ("esc", "enter") or hotkey(key) in ("s", "q"):
            return "close"
        pager.handle(key)
        return None

    keys = (("↑↓ PgDn", t("keys.scroll")), ("Esc", t("keys.back")))
    app.interact(title, body, keys, handle, typing=True)


def show_report_text(app: App, text: str, title: str) -> None:
    """The report on the screen: without the Markdown signs, masked as the screen is."""
    show_pager(app, app.mask(markdown.plain(text)), title)


def show_full_report(app: App, run_id: str, title: str) -> None:
    """`s` on S6 and S9: report.md of the run, with scrolling."""
    show_report_text(app, RunStore(app.env.state, app.env.clock).report_text(run_id) or "", title)


# Below this body height (a terminal under 30 lines) the score is one line: the large
# digits would leave too little room for what was found.
COMPACT_BELOW = 26


def check_summary(findings: list, names: Optional[dict] = None, *,
                  hint: bool = False) -> list[RenderableType]:  # fmt: skip
    """What was found, what KERBEROS fixes itself with the score after it, what is
    left to the person (K22, K23): the rows of the blocks below, counted."""
    numbers = counts(findings, names)
    if not numbers["problems"]:
        return [Text(f"✓ {t('s6.none')}", style="ok")]
    lines: list[RenderableType] = [Text(t("s6.found", **numbers), style="bold")]
    if numbers["auto"]:
        line = Text(t("s6.auto", **numbers), style="ok")
        line.append(t("s6.after", score=projected(findings)), style="bold")
        lines.append(line)
    if numbers["manual"]:
        lines.append(Text(t("s6.manual", **numbers), style="risk.medium"))
    if hint and numbers["auto"]:
        lines.append(Text(t("s6.fix_hint"), style="accent"))
    return lines


def report_header(app: App, findings: list, value: int, before: Optional[int],
                  without: list, path: str, *, summary: Optional[list] = None,
                  compact: bool = False) -> RenderableType:  # fmt: skip
    """Score with what was found and the nodes without access; the file on its own line,
    so the path is never cut (§12.1)."""
    lines: list[RenderableType] = list(summary if summary is not None else check_summary(findings))
    if without:
        lines.append(Text(t("s6.no_access", nodes=app.mask("; ".join(without))), style="muted"))
    saved = Text(t("report.saved", path=app.mask(path)), style="muted")
    if compact:
        return Group(ScoreBadge(value, before, compact=True), *lines, saved)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True)
    grid.add_column(ratio=1)
    grid.add_row(ScoreBadge(value, before), Group(*lines))
    return Group(grid, saved)


def to_fix(app: App, session: Session) -> Any:
    """S6 `f` in «Проверка»: «Исправление» on the same data. The administrator key is
    asked as S4 asks it in «Исправление»; a new run of mode fix gets the findings."""
    from kerberos.screens.access import AccessScreen
    from kerberos.screens.panel import ensure_write_token

    if not ensure_write_token(app, session):
        return None  # Esc: S6 stays
    if session.snapshot.kind == "3x-ui":
        session.data.setdefault("admin", {"mode": "local", "keys": []})
    elif "admin" not in session.data:
        session.data["admin"] = AccessScreen(app, session).admin_answer()
    session.mode = "fix"
    session.data.pop("run", None)
    save_check_run(app, session)
    return NEXT


def step_report(app: App, session: Session) -> Any:
    findings = session.data["findings"]
    run = session.data["run"]
    names = {n["uuid"]: n["name"] for n in run["nodes"]}
    listing = BlockList(report_blocks(findings, names, app.mask))
    path = str(RunStore(app.env.state, app.env.clock).path(run["runId"]) / "report.md")
    without = without_access(run)
    checking = session.mode == "check"

    def body(_w: int, height: int) -> RenderableType:
        listing.blocks = report_blocks(findings, names, app.mask)  # `m` masks it again
        head = report_header(app, findings, session.data["score"], None, without, path,
                             summary=check_summary(findings, names, hint=checking),
                             compact=height < COMPACT_BELOW)  # fmt: skip
        return Stack(head, Text(""), listing, flex=2)

    def handle(key: str) -> Optional[str]:
        if key == "enter":
            return NEXT
        if key == "esc":
            session.data["back_from_report"] = True
            return BACK
        if hotkey(key) == "s":
            show_full_report(app, run["runId"], t("s6.title"))
            return None
        if hotkey(key) == "f" and checking:
            return to_fix(app, session)
        listing.handle(key)
        return None

    keys: list[tuple[str, str]] = [(t("keys.space"), t("keys.details")),
                                   ("s", t("keys.full_report"))]  # fmt: skip
    if checking:
        keys += [("f", t("keys.fix")), ("Enter", t("keys.menu"))]
    else:
        keys += [("Enter", t("keys.next")), ("Esc", t("keys.back"))]
    keys.append(("?", t("keys.help")))
    app.screen_help = t("help.s6.check" if checking else "help.s6")
    try:
        return app.interact(t("s6.title"), body, keys, handle)
    finally:
        app.screen_help = ""


def reports_menu(app: App) -> None:
    """S1 «Отчёты»: past runs, newest first; Enter opens report.md."""
    store = RunStore(app.env.state, app.env.clock)
    runs = store.runs()
    if not runs:
        app.notice("info", t("report.empty"), t("reports.title"))
        return
    from kerberos.screens.rollback import run_label

    items = [(run["runId"], run_label(app, run), "") for run in runs]
    menu = Menu(items)
    while True:

        def handle(key: str) -> Optional[str]:
            if key == "esc":
                return "back"
            return menu.handle(key)

        keys = (("↑↓", t("keys.select")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
        choice = app.interact(t("reports.title"), menu, keys, handle)
        if choice == "back":
            return
        show_report_text(app, store.report_text(choice) or "", t("reports.title"))


def no_report_notice() -> Notice:
    return Notice("info", t("report.empty"))
