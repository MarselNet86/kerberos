"""Rollback of a past run, whole or change by change (tech.md §11.4, §5.3).

Changes go back in reverse order. A change on a node is rolled back by its
agent; the agent refuses when a file was changed after KERBEROS (a later
change touches it): then that later change has to go back first.
"""

from __future__ import annotations

import copy
from datetime import datetime
from typing import TYPE_CHECKING, Optional

from rich.console import Group
from rich.text import Text

from kerberos.copy import t
from kerberos.fixes.engine import ROLLBACKABLE
from kerberos.fixes.journal import RunStore, iso
from kerberos.fixes.panel_changes import PANEL_FIXES, undo
from kerberos.flow import EXIT_OK, EXIT_PANEL, EXIT_ROLLBACK_FAILED
from kerberos.nodes.transport import NodeAgentError, Target, TransportError
from kerberos.report.view import change_target
from kerberos.screens.check import write_report
from kerberos.screens.fix import agree, error_text
from kerberos.ui.widgets import Checklist, Consent, Menu, Notice

if TYPE_CHECKING:
    from kerberos.app import App


def node_of(run: dict, target: str) -> Optional[dict]:
    ref = target.partition(":")[2]
    return next((n for n in run["nodes"] if n["uuid"] == ref), None)


def label(app: App, run: dict, change: dict) -> str:
    # Named the way S9 and report.md name it: two host changes are «хост NL Reality» and
    # «хост DE Reality», not two lines «панель: …» (K19).
    names = {n["uuid"]: n["name"] for n in run["nodes"]}
    name = change_target(change["target"], change["params"], names)
    ports = ", ".join(change["params"].get("ports", []))
    text = t(
        "fix." + change["fixId"] + ".label",
        ports=ports,
        port=change["params"].get("port", ""),
        domain=change["params"].get("domain", ""),
        reserve=(node_of(run, f"node:{change['params'].get('reserve')}") or {}).get("name", ""),
        profile=change["params"].get("profile", ""),
    )
    return f"{app.mask(name)}: {app.mask(text)}"


def run_when(run: dict) -> str:
    """«16.11.2026 12:00 UTC»: when the run started; its id if the time is unreadable."""
    try:
        moment = datetime.strptime(run.get("startedAt") or "", "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return run.get("runId", "")
    return t("run.when", date=moment.strftime("%d.%m.%Y"), time=moment.strftime("%H:%M"))


def run_nodes(app: App, run: dict, limit: int = 3) -> str:
    names = [app.mask(n["name"]) for n in run.get("nodes", [])]
    return ", ".join(names[:limit]) + (", …" if len(names) > limit else "")


def run_label(app: App, run: dict, changes: Optional[int] = None) -> str:
    """How a person knows a run in a list: time, mode, changes (or the score), nodes."""
    parts = {"when": run_when(run), "mode": t(f"report.mode.{run['mode']}"),
             "nodes": run_nodes(app, run)}  # fmt: skip
    if changes is not None:
        return t("rb.item", n=changes, **parts)
    if run.get("changes"):
        return t("reports.item.changes", n=len(run["changes"]), **parts)
    after = run.get("scoreAfter")
    return t("reports.item", score=after if after is not None else run.get("scoreBefore", 0),
             **parts)  # fmt: skip


def choose_run(app: App, runs: list) -> Optional[dict]:
    items = [
        (run["runId"],
         run_label(app, run, sum(1 for c in run["changes"] if c["state"] in ROLLBACKABLE)), "")
        for run in runs
    ]  # fmt: skip
    menu = Menu(items)

    def handle(key: str) -> Optional[str]:
        return "" if key == "esc" else menu.handle(key)

    keys = (("↑↓", t("keys.select")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
    body = Group(Text(t("rb.choose"), style="bold"), Text(""), menu)
    choice = app.interact(t("rb.title"), body, keys, handle)
    return next((r for r in runs if r["runId"] == choice), None)


def current_nodes(app: App, nodes: list) -> list:
    """The nodes of a run with the SSH port they answer on now (nodes.json): a rolled back
    ssh.port is on the old port again, and report.md says how to log in (K19)."""
    result = []
    for node in nodes:
        record = app.env.state.node(node.get("uuid", ""))
        result.append(dict(node, sshPort=record.ssh_port) if record is not None else dict(node))
    return result


def target_of(app: App, run: dict, change: dict) -> Target:
    target = (
        f"node:{change['params']['node']}" if change["params"].get("node") else change["target"]
    )
    node = node_of(run, target) or {}
    record = app.env.state.node(node.get("uuid", ""))
    if record is not None:
        return record.target(record.address)
    return Target(node.get("uuid", ""), node.get("name", ""), node.get("address", ""),
                  node.get("sshPort", 22))  # fmt: skip


def ask_diff(app: App, diff: str) -> bool:
    """§11.4: the panel object changed after KERBEROS: show how, ask before undoing."""
    from kerberos.screens.check import show_pager

    show_pager(app, t("rb.diff.intro") + "\n\n" + app.mask(diff), t("rb.title"))
    body = Group(Notice("warning", t("rb.diff.question")),
                 Text(f"{t('quit.yes')}    {t('quit.no')}", style="muted"))  # fmt: skip
    app.draw(t("rb.title"), body)
    return app.term.read_key() == "enter"


def nodes_of(change: dict) -> set:
    """The nodes a change belongs to: its target node and the nodes in its parameters."""
    kind, _, ref = change["target"].partition(":")
    refs = {ref} if kind == "node" else set()
    return refs | {change["params"][k] for k in ("node", "reserve") if change["params"].get(k)}


def agent_rollback(app: App, target: Target, change: dict) -> tuple:
    """(error, back): back when the node's files are as before the change."""
    try:
        app.env.transport.agent(target, f"rollback {change['changeId']}")
    except TransportError as exc:
        return exc.kind, False
    except NodeAgentError as exc:
        # command_failed: the files are back, an undo command failed: a look by hand.
        return exc.code, exc.code == "command_failed"
    return None, True


def port_rollback(app: App, run: dict, target: Target, change: dict) -> tuple:
    """§9.3 (K13): a confirmed SSH port goes back the way it came (nodes/ssh_port.py)."""
    from kerberos.nodes.ssh_port import roll_back_port

    address = (node_of(run, f"node:{target.uuid}") or {}).get("address", "")

    def ask(port: int) -> bool:
        return ask_old_port(app, port, f"ssh -p {port} root@{address}")

    return roll_back_port(app.env, target, change, ask)


def ask_old_port(app: App, port: int, command: str) -> bool:
    """3x-ui (§7.6): the old SSH port is tried by the person from their computer."""
    body = Group(Notice("warning", t("rb.outside", port=port, command=app.mask(command))),
                 Text(t("rb.outside.keys"), style="muted"))  # fmt: skip
    app.draw(t("rb.title"), body)
    return app.term.read_key() == "enter"


def note_failure(change: dict, error: str) -> None:
    """This rollback did not take the change back. A change whose automatic rollback
    already failed keeps that mark (it may still be in place); the new reason goes to
    its details."""
    if change.get("error") == "rollback_failed":
        change["details"] = {**(change.get("details") or {}), "rollbackError": error}
    else:
        change["error"] = error


def note_back(change: dict) -> None:
    """The change went back now: a failed automatic rollback of it is settled, and the
    reason it failed at apply stays."""
    if change.get("error") == "rollback_failed":
        details = dict(change.get("details") or {})
        details.pop("rollbackError", None)
        change["details"] = details
        change["error"] = details.get("failure")


def failure_text(change: dict) -> str:
    """Why this rollback did not take the change back, in the words of a rollback."""
    code = change.get("error")
    if code == "rollback_failed":
        code = (change.get("details") or {}).get("rollbackError") or code
    return t("rb.port_closed") if code == "port_closed" else error_text(code)


def roll_back(app: App, run: dict, changes: list, client=None) -> list:
    """Reverse order; returns the changes that did not go back.

    A change that does not go back stops its node: the node's earlier changes stay, as
    a later change may need them (ssh.key_only needs the administrator key)."""
    failed = []
    blocked: set = set()
    store = RunStore(app.env.state, app.env.clock)
    # Reverse journal order: changes of one second share a timestamp.
    position = {id(c): i for i, c in enumerate(run["changes"])}
    from kerberos.fixes.portal import PORTAL_FIXES

    ordered = sorted(changes, key=lambda c: position.get(id(c), -1), reverse=True)
    # The way into the panel goes back last: the client of this rollback signed in where
    # the panel is now, and the panel's other changes still need it there (§10.10).
    ordered = ([c for c in ordered if c["fixId"] not in PORTAL_FIXES]
               + [c for c in ordered if c["fixId"] in PORTAL_FIXES])  # fmt: skip
    for change in ordered:
        nodes = nodes_of(change)
        if nodes & blocked:
            note_failure(change, "rollback_skipped")
            failed.append(change)
            store.save(run)
            continue
        from kerberos.fixes.portal import PORTAL_FIXES, undo_change

        if change["fixId"] in PORTAL_FIXES:
            # Files and commands of this server (§10.10): no panel sign-in needed.
            reason = undo_change(app.env.host, change, ask=lambda diff: ask_diff(app, diff))
            if reason:
                note_failure(change, reason)
                failed.append(change)
            else:
                note_back(change)
                change["state"] = "rolled_back"
                change["finishedAt"] = iso(app.env.clock)
            store.save(run)
            continue
        if change["fixId"] in PANEL_FIXES:
            reason = (
                undo(client, change, ask=lambda diff: ask_diff(app, diff))
                if client
                else ("no_panel")
            )
            if reason:
                note_failure(change, reason)
                failed.append(change)
                blocked |= nodes
                store.save(run)
                continue
            run["pending"] = [p for p in run.get("pending", [])
                              if p.get("changeId") != change["changeId"]]  # fmt: skip
            note_back(change)
            change["state"] = "rolled_back"
            change["finishedAt"] = iso(app.env.clock)
            store.save(run)
            continue
        target = target_of(app, run, change)
        if change["fixId"] == "ssh.port" and change["state"] == "confirmed":
            error, back = port_rollback(app, run, target, change)
        else:
            error, back = agent_rollback(app, target, change)
            if error == "no_backup" and change["state"] == "applying":
                error, back = None, True  # cut short before the agent changed anything
        if back:
            note_back(change)
            previous = change["details"].get("previousKey")
            if change["fixId"] == "hostkeys.regenerate" and previous:
                app.env.state.pin(target.address, target.port, "ssh-ed25519", previous)
            if change["fixId"] == "ssh.port" and change["details"].get("oldPorts"):
                record = app.env.state.node(target.uuid)
                if record is not None:
                    record.ssh_port = change["details"]["oldPorts"][0]
                    app.env.state.save_node(record)
            change["state"] = "rolled_back"
            change["finishedAt"] = iso(app.env.clock)
        if error:
            note_failure(change, error)
            failed.append(change)
            blocked |= nodes
        store.save(run)
    return failed


def rollback_flow(app: App, run_id: Optional[str] = None) -> int:
    store = RunStore(app.env.state, app.env.clock)
    runs = [r for r in store.runs() if any(c["state"] in ROLLBACKABLE for c in r["changes"])]
    if run_id is not None:
        runs = [r for r in runs if r["runId"] == run_id]
    if not runs:
        app.notice("info", t("rb.empty"), t("rb.title"))
        return EXIT_OK
    run = runs[0] if run_id is not None else choose_run(app, runs)
    if run is None:
        return EXIT_OK
    changes = [c for c in run["changes"] if c["state"] in ROLLBACKABLE]
    rows = [[label(app, run, c), t(f"state.{c['state']}")] for c in changes]
    checklist = Checklist(rows, [t("rb.col.change"), t("rb.col.state")],
                          selected=set(range(len(changes))))  # fmt: skip

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        result = checklist.handle(key)
        return "done" if result == "done" and checklist.selected else None

    keys = ((t("keys.space"), t("keys.toggle")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
    while True:
        body = Group(Text(t("rb.changes"), style="bold"), checklist)
        if app.interact(t("rb.title"), body, keys, handle) == "back":
            return EXIT_OK
        chosen = [changes[i] for i in sorted(checklist.selected)]
        summary = Group(Text(t("rb.consent", n=len(chosen))),
                        *[Text("  " + label(app, run, c)) for c in chosen])  # fmt: skip
        if agree(app, t("rb.title"), Consent(summary, t("rb.accept"), t("rb.keys"))):
            break
    client = None
    if any(c["fixId"] in PANEL_FIXES for c in chosen):
        from kerberos.screens.panel import open_panel

        opened = open_panel(app, kind=run["panel"].get("kind", "remnawave"))
        if not isinstance(opened, tuple):
            return EXIT_PANEL if opened == EXIT_PANEL else EXIT_OK
        client = opened[1]
    failed = roll_back(app, run, chosen, client)
    if client is not None:
        from kerberos.screens.panel import settle_token

        settle_token(app, client)
    record = store.new_run("rollback", run["panel"], current_nodes(app, run["nodes"]))
    record["changes"] = copy.deepcopy(chosen)
    record["findings"] = run.get("findings", [])
    # The rollback goes from the protection after the fix back to the one before it;
    # a partial rollback is counted the same way, as the lower bound.
    after = run.get("scoreAfter")
    record["scoreBefore"] = after if after is not None else run.get("scoreBefore", 0)
    record["scoreAfter"] = run.get("scoreBefore", 0)
    record["rolledBackRun"] = run["runId"]
    record["finishedAt"] = iso(app.env.clock)
    store.save(record)
    path = write_report(app, record)
    lines = [t("rb.done", ok=len(chosen) - len(failed), total=len(chosen))]
    for change in failed:
        lines.append(f"✗ {label(app, run, change)}: {failure_text(change)}")
    if failed:
        lines.append(t("rb.failed"))
    lines += ["", t("report.saved", path=app.mask(path))]
    app.notice("info" if not failed else "error", "\n".join(lines), t("rb.title"))
    return EXIT_ROLLBACK_FAILED if failed else EXIT_OK
