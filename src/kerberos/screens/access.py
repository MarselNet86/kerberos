"""S4. Access to the nodes (tech.md §6, §8).

For every chosen node without KERBEROS access: show the host key fingerprint
and pin it after the person confirms; log in with the panel server's root
keys or a key forwarded with `ssh -A`, else hand the terminal to `ssh` for the
node password, unless the node takes only keys; install the agent
and the restricted KERBEROS key; prove the access with a new connection.
Nodes that already have access get their agent version checked (§8.3).
The host keys of all new nodes are scanned together and confirmed in one
table (K25); in «Проверка» that table also says what S4 installs and that
settings stay as they are, and Esc there goes back before anything is
installed. A changed key is still asked node by node. In «Исправление» the
person chooses the administrator key (§8.5) once: the answer is kept in
answers.json, and `k` on the summary asks again; the keys reach the nodes
only after consent, as a planned change.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any, Callable, Optional

from rich import box
from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
from rich.table import Table
from rich.text import Text

from kerberos.copy import t
from kerberos.flow import BACK, NEXT
from kerberos.nodes import bootstrap
from kerberos.nodes.keys import fingerprint, parse_authorized_keys, parse_key
from kerberos.nodes.transport import NodeAgentError, Target, TransportError, ssh_host
from kerberos.panel.model import Node
from kerberos.screens.panel import panel_line
from kerberos.state import NodeRecord
from kerberos.ui.keys import hotkey
from kerberos.ui.widgets import Checklist, Menu, Notice, TextInput

if TYPE_CHECKING:
    from kerberos.app import App, Session

OK, NONE, DENIED = "ok", "none", "denied"
LOCAL_ADDRESS = "127.0.0.1"
LOCAL_HOST_KEY = "/etc/ssh/ssh_host_ed25519_key.pub"
ROOT_KEYS = "/root/.ssh/authorized_keys"
PASSWORD_METHODS = {"password", "keyboard-interactive"}
SCAN_WORKERS = 4  # host keys scanned at once, as S5 collects (§6)


def local_ssh_port(host: Any) -> int:
    """The first port SSH of this server listens on, found as the agent finds it: the
    ports of ssh.socket when it is active (a drop-in such as KERBEROS's own
    zz-kerberos.conf sets them), else sshd's own (`sshd -T`, else `ss`), else 22."""
    from kerberos.agent import parse_sshd_t, ssh_ports

    def out(argv: list) -> str:
        result = host.run(argv, timeout=20)
        return result.stdout if result.ok else ""

    active = out(["systemctl", "is-active", "ssh.socket"]).strip() == "active"
    listen = out(["systemctl", "show", "ssh.socket", "-p", "Listen"]) if active else ""
    sshd = parse_sshd_t(out(["sshd", "-T"]))["port"]
    ports, _by_socket = ssh_ports(sshd, active, listen, "" if sshd else out(["ss", "-Hlntup"]))
    return int(ports[0])


class AccessFailed(Exception):
    def __init__(self, status: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def target_of(node: Node, record: Optional[NodeRecord], resolve: Any = None) -> Target:
    """Where SSH goes: a node given by name on the IPv4 of the name (§8.2), resolved
    again on every run, so a changed A record is followed."""
    if record is not None:
        target = record.target(node.address)
        if resolve is None or record.ssh_address == LOCAL_ADDRESS:
            return target
        return Target(target.uuid, target.name, ssh_host(node.address, resolve), target.port)
    return Target(node.uuid, node.name, ssh_host(node.address, resolve), 22)


def ensure_key(app: App) -> str:
    """The KERBEROS key pair on the panel server, created on first use."""
    state = app.env.state
    public = state.public_key()
    if public:
        return public
    state.ensure()
    host = app.env.host
    result = host.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            f"kerberos@{host.hostname()}",
            "-f",
            str(state.key),
        ]  # fmt: skip
    )
    if not result.ok or state.public_key() is None:
        raise AccessFailed(NONE, t("access.reason.keygen"))
    os.chmod(state.key, 0o600)
    return state.public_key() or ""


class Fitted:
    """The node table over the question: with many nodes its rows give way (§14.2),
    so the question and its answers always fit the screen."""

    def __init__(
        self,
        table: Callable[[Optional[int]], Table],
        tail: list[RenderableType],
        height: int,
        head: Optional[list[RenderableType]] = None,
    ) -> None:
        self.table = table
        self.tail = tail
        self.height = height
        self.head = head or []

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        tail = Group(*self.head, *self.tail)
        used = len(console.render_lines(tail, options.update(height=None), pad=False))
        yield from self.head
        yield self.table(max(1, self.height - used - 3))  # header, rule and caption
        yield Group(*self.tail)


class AccessScreen:
    def __init__(self, app: App, session: Session) -> None:
        self.app = app
        self.session = session
        self.nodes = [n for n in session.snapshot.nodes if n.uuid in session.selected]
        self.status: dict[str, str] = session.data.setdefault("access", {})
        self.reasons: dict[str, str] = session.data.setdefault("access_reason", {})
        self.action = ""
        self.local = session.snapshot.kind == "3x-ui"
        # 3x-ui (§7.6): the one node is this very server.
        self.title = t("access.title.local") if self.local else t("access.title")
        self.seen_keys: dict[str, str] = {}  # node uuid -> host key fingerprint seen here

    # -- drawing -------------------------------------------------------------
    def table(self, rows: Optional[int] = None) -> Table:
        """All chosen nodes, or `rows` of them around the node being set up."""
        shown = self.nodes
        caption = None
        if rows is not None and len(shown) > rows:
            current = next((i for i, n in enumerate(shown) if self.status.get(n.uuid) is None),
                           len(shown) - 1)  # fmt: skip
            start = max(0, min(current - rows // 2, len(shown) - rows))
            shown = shown[start : start + rows]
            caption = t("pager.position", start=start + 1, end=start + len(shown),
                        total=len(self.nodes))  # fmt: skip
        table = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False, pad_edge=False,
                      caption=caption, caption_style="muted", caption_justify="left")  # fmt: skip
        first = "access.col.server" if self.local else "access.col.node"
        for title in (first, "access.col.address", "access.col.status"):
            table.add_column(t(title), no_wrap=True, overflow="ellipsis", header_style="muted")
        for node in shown:
            state = self.status.get(node.uuid)
            if state == OK:
                cell = Text(f"✓ {t('access.status.ok')}", style="ok")
            elif state in (NONE, DENIED):
                reason = self.reasons.get(node.uuid, "")
                cell = Text(f"✗ {t('access.status.' + state)}: {reason}", style="risk.high")
            else:
                cell = Text("…", style="muted")
            table.add_row(self.app.mask(node.name), self.app.mask(node.address), cell)
        return table

    def frame(self, *extra: RenderableType) -> Callable[[int, int], RenderableType]:
        def body(_width: int, height: int) -> RenderableType:
            tail: list[RenderableType] = []
            if self.action:
                tail += [Text(""), Text(self.action, style="accent")]
            if extra:
                tail += [Text(""), *extra]
            head = panel_line(self.app, self.session) if self.local else []
            return Fitted(self.table, tail, height, head)

        return body

    def show(self, action: str) -> None:
        self.action = action
        self.app.draw(self.title, self.frame())

    def ask_menu(
        self,
        prompt: RenderableType,
        items: list[tuple[str, str, str]],
        selected: int = 0,
        skip: str = "",
    ) -> str:
        """One question; Esc answers with the last item, which always skips."""
        menu = Menu(items, selected=selected)

        def handle(key: str) -> Optional[str]:
            if key == "esc":
                return items[-1][0]
            return menu.handle(key)

        keys = (
            ("↑↓", t("keys.select")),
            ("Enter", t("keys.next")),
            ("Esc", skip or t("keys.skip_node")),
            ("q", t("keys.quit")),
        )
        return self.app.interact(self.title, self.frame(prompt, Text(""), menu), keys, handle)

    def intro(self) -> bool:
        """«Проверка» promises to keep the settings: say first what S4 installs.

        Once per run, before the first node is set up. False: the person went back.
        """
        if self.session.mode != "check" or self.session.data.get("intro_seen"):
            return True
        notice = Notice("info", t("access.intro.local" if self.local else "access.intro"))

        def handle(key: str) -> Optional[str]:
            if key == "enter":
                return "go"
            if key == "esc":
                return "back"
            return None

        keys = (("Enter", t("keys.next")), ("Esc", t("keys.back")), ("q", t("keys.quit")))
        self.action = ""
        answer = self.app.interact(self.title, self.frame(notice), keys, handle)
        if answer == "back":
            return False
        self.session.data["intro_seen"] = True
        return True

    def ask_port(self, node: Node, port: int) -> Optional[int]:
        def check(value: str) -> Optional[str]:
            ok = value.isdigit() and 1 <= int(value) <= 65535
            return None if ok else t("access.port_invalid")

        field = TextInput(
            t("access.port_label", node=self.app.mask(node.name)),
            hint=t("access.port_hint", port=port),
            validate=check,
            value=str(port),
        )

        def handle(key: str) -> Optional[str]:
            if key == "esc":
                return ""
            return field.handle(key)

        keys = (("Enter", t("keys.next")), ("Esc", t("keys.skip_node")))
        value = self.app.interact(self.title, self.frame(field), keys, handle, typing=True)
        return int(value) if value else None

    def same_key(self, node: Node, value: str) -> list[str]:
        """Other chosen nodes known to show this host key: one image of the hoster."""
        records = self.app.env.state.nodes()
        names = []
        for other in self.nodes:
            if other.uuid == node.uuid:
                continue
            record = records.get(other.uuid)
            known = self.seen_keys.get(other.uuid) or (record.fingerprint if record else "")
            if known == value:
                names.append(self.app.mask(other.name))
        return names

    # -- one node --------------------------------------------------------------
    def ssh_target(self, node: Node, record: Optional[NodeRecord]) -> Target:
        """§8.2: the IPv4 of the node's name. A node set up by name before keeps its pinned
        key under the address: it is the same server, ssh still compares the key."""
        prober = self.app.env.prober
        target = target_of(node, record, prober.resolve if prober is not None else None)
        state = self.app.env.state
        if record is not None and not record.ssh_address and target.address != node.address:
            blob = state.pinned(node.address, target.port)
            if blob and state.pinned(target.address, target.port) is None:
                state.pin(target.address, target.port, "ssh-ed25519", blob)
        return target

    # -- host keys (K25) --------------------------------------------------------
    def scan(self, targets: list[Target]) -> list[Optional[Any]]:
        """ssh-keyscan of every target, a few at once; the keys in the order given."""
        transport = self.app.env.transport
        if len(targets) <= 1:
            return [transport.keyscan(x.address, x.port) for x in targets]
        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as pool:
            return list(pool.map(lambda x: transport.keyscan(x.address, x.port), targets))

    def fail(self, node: Node, status: str, reason: str) -> None:
        self.status[node.uuid] = status
        self.reasons[node.uuid] = reason

    def prepare(self, fresh: list[tuple[Node, Optional[NodeRecord]]]) -> Any:
        """The host keys of every node to set up: new ones in one table, changed ones
        one by one (§8.1). The (node, target) pairs to set up with their keys pinned,
        or BACK when the person went back before anything was installed."""
        transport, state = self.app.env.transport, self.app.env.state
        targets = {n.uuid: self.ssh_target(n, r) for n, r in fresh}
        self.show(t("access.scanning_keys", n=len(fresh)))
        keys = dict(zip([n.uuid for n, _ in fresh],
                        self.scan([targets[n.uuid] for n, _ in fresh])))  # fmt: skip
        ready = []
        for node, _record in fresh:
            target = targets[node.uuid]
            while keys[node.uuid] is None:
                self.action = t("access.checking_key", node=self.app.mask(node.name))
                port = self.ask_port(node, target.port)
                if port is None:
                    break
                target = Target(target.uuid, target.name, target.address, port)
                self.show(t("access.checking_key", node=self.app.mask(node.name)))
                keys[node.uuid] = transport.keyscan(target.address, port)
            if keys[node.uuid] is None:
                self.fail(node, NONE, t("access.reason.unreachable"))
                continue
            targets[node.uuid] = target
            self.seen_keys[node.uuid] = keys[node.uuid].fingerprint
            ready.append(node)
        new = [n for n in ready if state.pinned(targets[n.uuid].address, targets[n.uuid].port)
               is None]  # fmt: skip
        changed = [n for n in ready if n not in new and keys[n.uuid].blob !=
                   state.pinned(targets[n.uuid].address, targets[n.uuid].port)]  # fmt: skip
        intro = self.session.mode == "check" and not self.session.data.get("intro_seen")
        if new:
            chosen = self.confirm_new(new, keys, targets, intro)
            if chosen is None:
                return BACK
        elif ready and not self.intro():
            return BACK
        else:
            chosen = set()
        self.session.data["intro_seen"] = True
        accepted = []
        for node in ready:
            target, key = targets[node.uuid], keys[node.uuid]
            if node in new and node.uuid not in chosen:
                self.fail(node, DENIED, t("access.reason.declined"))
                continue
            if node in changed and not self.confirm_changed(node, target, key):
                self.fail(node, DENIED, t("access.reason.declined"))
                continue
            if node in new or node in changed:
                state.pin(target.address, target.port, key.type, key.blob)
            accepted.append((node, target))
        return accepted

    def confirm_new(self, new: list[Node], keys: dict, targets: dict, intro: bool) -> Any:
        """One table of the new host keys, all marked (K25): the uuids the person
        confirmed, or None on Esc. In «Проверка» the table also says what S4 installs."""
        rows = []
        for node in new:
            target = targets[node.uuid]
            address = self.app.mask(target.address)
            if target.port != 22:
                address += f":{target.port}"
            fingerprint = keys[node.uuid].fingerprint.removeprefix("SHA256:")
            rows.append([self.app.mask(node.name), address, fingerprint])
        checklist = Checklist(rows, [t("access.col.node"), t("access.col.address"),
                                     t("access.col.fingerprint.sha256")],
                              selected=set(range(len(new))), flexible=0, min_width=6)  # fmt: skip
        notes: list[RenderableType] = []
        groups: dict[str, list[str]] = {}
        for node in new:
            groups.setdefault(keys[node.uuid].fingerprint, []).append(node.uuid)
        for node in new:
            same = self.same_key(node, keys[node.uuid].fingerprint)
            group = groups[keys[node.uuid].fingerprint]
            if same and node.uuid == group[0]:
                names = [self.app.mask(node.name), *same]
                notes.append(Text(t("access.hostkey_same", nodes=", ".join(names)),
                                  style="risk.medium"))  # fmt: skip

        def body(_width: int, height: int) -> RenderableType:
            head: list[RenderableType] = []
            if intro:
                head += [Notice("info", t("access.intro")), Text("")]
            head.append(Text(t("access.hostkeys"), style="bold"))
            tail = [Text(t("access.hostkey_hint"), style="muted"), *notes]
            tail.append(Text(t("access.hostkeys.selected", n=len(checklist.selected),
                               total=len(new)), style="muted"))  # fmt: skip
            fixed = 5 + 2 * len(notes) + (6 if intro else 0)  # title, hint, notes, count
            checklist.viewport = max(4, height - fixed)
            return Group(*head, checklist, Text(""), *tail)

        def handle(key: str) -> Optional[str]:
            if key == "esc":
                return "back"
            return checklist.handle(key)

        keys_hint = ((t("keys.space"), t("keys.toggle")), ("a", t("keys.all")),
                     ("Enter", t("access.hostkeys.confirm")), ("Esc", t("keys.back")),
                     ("q", t("keys.quit")))  # fmt: skip
        self.action = ""
        if self.app.interact(self.title, body, keys_hint, handle) == "back":
            return None
        return {new[i].uuid for i in checklist.selected}

    def confirm_changed(self, node: Node, target: Target, key: Any) -> bool:
        """A changed key may be an interception: one Enter must not accept it (§8.1)."""
        pinned = self.app.env.state.pinned(target.address, target.port) or ""
        name = self.app.mask(node.name)
        lines: list[RenderableType] = [
            Notice("error", t("access.hostkey_changed", node=name)),
            Text(t("access.hostkey_old", fingerprint=fingerprint(pinned))),
            Text(t("access.hostkey_new", fingerprint=key.fingerprint)),
        ]
        same = self.same_key(node, key.fingerprint)
        if same:
            lines.append(Text(t("access.hostkey_same", nodes=", ".join(same)), style="risk.medium"))
        items = [("yes", t("access.accept_new"), ""), ("no", t("access.skip"), "")]
        return self.ask_menu(Group(*lines), items, 1) == "yes"

    def login(self, node: Node, target: Target) -> None:
        transport = self.app.env.transport
        self.show(t("access.trying_keys"))
        try:
            if transport.open_root(target, interactive=False):
                return
            # A node that lets root in only with a key would reject any password:
            # asking for one only wastes the person's tries (§8.2).
            offered = transport.offered_methods(target)
            if offered is not None and not PASSWORD_METHODS & set(offered):
                raise AccessFailed(NONE, t("access.reason.key_only"))
            message = t("access.password", node=self.app.mask(node.name))
            with self.app.term.suspend(message):
                ok = transport.open_root(target, interactive=True)
        except TransportError as exc:
            raise AccessFailed(NONE, reason_of(exc)) from exc
        if not ok:
            raise AccessFailed(NONE, t("access.reason.login"))

    def install(self, node: Node, target: Target, public_key: str) -> dict:
        transport = self.app.env.transport
        self.show(t("access.installing", node=self.app.mask(node.name)))
        script = bootstrap.install_script(public_key)
        result = transport.root_run(target, bootstrap.REMOTE_COMMAND, script, timeout=120)
        if result.code == bootstrap.NO_PYTHON:
            prompt = Text(t("access.no_python", node=self.app.mask(node.name)))
            items = [("yes", t("access.install_python"), ""), ("no", t("access.skip"), "")]
            if self.ask_menu(prompt, items) != "yes":
                raise AccessFailed(NONE, t("access.reason.python"))
            self.show(t("access.installing_python", node=self.app.mask(node.name)))
            installed = transport.root_run(target, bootstrap.INSTALL_PYTHON, timeout=600)
            if not installed.ok:
                raise AccessFailed(NONE, t("access.reason.python"))
            self.show(t("access.installing", node=self.app.mask(node.name)))
            result = transport.root_run(target, bootstrap.REMOTE_COMMAND, script, timeout=120)
        answer = bootstrap.parse_result(result.stdout)
        if not result.ok or "error" in answer:
            detail = str(answer.get("error") or result.stderr.strip()[:80] or result.code)
            raise AccessFailed(NONE, t("access.reason.failed", detail=detail))
        return answer

    def verify(self, node: Node, target: Target, public_key: str) -> dict:
        """A new connection with the KERBEROS key; on failure the key line goes away."""
        transport = self.app.env.transport
        self.show(t("access.verify"))
        try:
            return transport.agent(target, "version", fresh=True)
        except (TransportError, NodeAgentError) as exc:
            transport.root_run(
                target, bootstrap.REMOTE_COMMAND, bootstrap.remove_script(public_key)
            )
            raise AccessFailed(NONE, t("access.reason.verify")) from exc

    def setup(self, node: Node, target: Target, public_key: str) -> None:
        """Log in, install and prove the access of a node whose host key is pinned."""
        transport, state = self.app.env.transport, self.app.env.state
        self.login(node, target)
        try:
            answer = self.install(node, target, public_key)
            version = self.verify(node, target, public_key)
        finally:
            transport.close_root(target)
        key_blob = state.pinned(target.address, target.port) or ""
        state.save_node(
            NodeRecord(
                uuid=node.uuid,
                name=node.name,
                address=node.address,
                ssh_port=target.port,
                fingerprint=fingerprint(key_blob) if key_blob else "",
                agent=str(version.get("agent", "")),
                panel_ip=str(answer.get("panelIp", "")),
                access=OK,
                ssh_address=target.address if target.address != node.address else "",
            )
        )

    def setup_local(self, node: Node, public_key: str) -> None:
        """3x-ui (§7.6): this server is the node. No password and no question about
        the host key: KERBEROS is root here, installs the agent itself and reads the
        key from the server's own file. Agent calls then go over SSH to 127.0.0.1,
        so access changes are still confirmed by a new connection (§11.3)."""
        host, state = self.app.env.host, self.app.env.state
        self.show(t("access.local.installing"))
        result = host.run(["python3", "-"], input=bootstrap.local_install_script(public_key),
                          timeout=120)  # fmt: skip
        answer = bootstrap.parse_result(result.stdout)
        if not result.ok or "error" in answer:
            detail = str(answer.get("error") or result.stderr.strip()[:80] or result.code)
            raise AccessFailed(NONE, t("access.reason.failed", detail=detail))
        key = parse_key(host.read_text(LOCAL_HOST_KEY) or "")
        if key is None:
            raise AccessFailed(NONE, t("access.reason.local_key"))
        port = local_ssh_port(host)
        state.pin(LOCAL_ADDRESS, port, key.type, key.blob)
        target = Target(node.uuid, node.name, LOCAL_ADDRESS, port)
        try:
            version = self.app.env.transport.agent(target, "version", fresh=True)
        except (TransportError, NodeAgentError) as exc:
            host.run(["python3", "-"], input=bootstrap.remove_script(public_key), timeout=60)
            raise AccessFailed(NONE, t("access.reason.verify")) from exc
        state.save_node(
            NodeRecord(
                uuid=node.uuid,
                name=node.name,
                address=node.address,
                ssh_port=port,
                fingerprint=key.fingerprint,
                agent=str(version.get("agent", "")),
                panel_ip=LOCAL_ADDRESS,
                access=OK,
                ssh_address=LOCAL_ADDRESS,
            )
        )

    def refresh(self, node: Node, record: NodeRecord) -> bool:
        """Known node: check the agent and update it (§8.3). False: set up again."""
        transport = self.app.env.transport
        target = self.ssh_target(node, record)
        self.show(t("access.checking_agent", node=self.app.mask(node.name)))
        try:
            answer = transport.agent(target, "version")
            local = bootstrap.agent_sha256()
            if answer.get("sha256") != local:
                self.show(t("access.updating", node=self.app.mask(node.name)))
                answer = transport.agent(target, f"update {local}", data=bootstrap.agent_source())
            record.agent = str(answer.get("agent", record.agent))
            record.access = OK
            if target.address != (record.ssh_address or node.address):
                record.ssh_address = target.address
            self.app.env.state.save_node(record)
            return True
        except TransportError as exc:
            if exc.kind == "hostkey_changed":
                return False
            if exc.kind in ("auth", "failed"):
                return False  # the panel address may have changed (§8.4): set up again
            raise AccessFailed(NONE, reason_of(exc)) from exc
        except NodeAgentError as exc:
            raise AccessFailed(NONE, t("access.reason.failed", detail=exc.code)) from exc

    # -- the screen ------------------------------------------------------------
    def run(self) -> Any:
        try:
            public_key = ensure_key(self.app)
        except AccessFailed as exc:
            self.app.notice("error", exc.reason, self.title)
            return BACK
        state = self.app.env.state
        fresh: list[tuple[Node, Optional[NodeRecord]]] = []
        for node in self.nodes:
            if self.status.get(node.uuid) == OK:
                continue
            record = state.node(node.uuid)
            try:
                if record and record.access == OK and self.refresh(node, record):
                    self.status[node.uuid] = OK
                    continue
            except AccessFailed as exc:
                self.fail(node, exc.status, exc.reason)
                continue
            fresh.append((node, record))
        if fresh and self.local:
            if not self.intro():
                return BACK
            for node, _record in fresh:
                try:
                    self.setup_local(node, public_key)
                    self.status[node.uuid] = OK
                except AccessFailed as exc:
                    self.fail(node, exc.status, exc.reason)
        elif fresh:
            accepted = self.prepare(fresh)
            if accepted == BACK:
                return BACK
            for node, target in accepted:
                try:
                    self.setup(node, target, public_key)
                    self.status[node.uuid] = OK
                except AccessFailed as exc:
                    self.fail(node, exc.status, exc.reason)
        self.action = ""
        if self.local:
            # The person's own keys are already on this server: nothing to copy (§8.5).
            self.session.data["admin"] = {"mode": "local", "keys": [], "own": self.own_keys()}
        elif self.session.mode == "fix" and "admin" not in self.session.data:
            self.session.data["admin"] = self.admin_answer()
        return self.summary()

    # -- answers kept between runs (K25) ---------------------------------------
    def remembered_admin(self) -> Optional[dict]:
        """The answer of §8.5 from answers.json while it still fits: «Мои ключи» while one
        of its keys is still on the panel server, «Создать» while admin_ed25519 is."""
        state = self.app.env.state
        answer = state.answers().get("admin") if state is not None else None
        if not answer:
            return None
        if answer["mode"] == "create":
            return {"mode": "create", "keys": []} if state.admin_key.exists() else None
        wanted = set(answer["keys"])
        lines = [k.line for k in self.own_list() if k.fingerprint in wanted]
        return {"mode": "mine", "keys": lines} if lines else None

    def admin_answer(self) -> dict:
        """The remembered answer, else the question (§8.5); the answer is remembered."""
        return self.remembered_admin() or self.choose_admin(self.last_admin())

    def last_admin(self) -> Optional[dict]:
        """What to preselect when the question comes back: the session's answer, else the
        remembered one (its keys as lines of the panel server)."""
        if self.session.data.get("admin"):
            return self.session.data["admin"]
        state = self.app.env.state
        answer = state.answers().get("admin") if state is not None else None
        if not answer:
            return None
        wanted = set(answer["keys"])
        return {"mode": answer["mode"],
                "keys": [k.line for k in self.own_list() if k.fingerprint in wanted]}  # fmt: skip

    def choose_admin(self, previous: Optional[dict] = None) -> dict:
        answer = self.ask_admin(previous)
        state = self.app.env.state
        if state is not None:
            if answer["mode"] == "skip":
                state.remember(admin=None)  # it leaves the password login: asked again
            else:
                prints = {k.line: k.fingerprint for k in self.own_list()}
                keys = [prints[line] for line in answer["keys"] if line in prints]
                state.remember(admin={"mode": answer["mode"], "keys": keys})
        return answer

    def whois_answer(self) -> Optional[bool]:
        state = self.app.env.state
        return state.answers().get("whois") if state is not None else None

    def own_list(self) -> list:
        """The keys of the person, not of KERBEROS, that let root into this server."""
        text = self.app.env.host.read_text(ROOT_KEYS) or ""
        return [k for k in parse_authorized_keys(text) if not k.is_kerberos]

    def own_keys(self) -> int:
        return len(self.own_list())

    def summary(self) -> Any:
        ok = sum(1 for n in self.nodes if self.status.get(n.uuid) == OK)
        lines: list[RenderableType] = []
        if self.local:
            lines.append(Text(t("access.summary.local" if ok else "access.summary.local.none")))
        else:
            lines.append(Text(t("access.summary", ok=ok, total=len(self.nodes))))
            if ok < len(self.nodes):
                lines.append(Text(t("access.panel_only"), style="muted"))
            key_only = t("access.reason.key_only")
            if any(self.reasons.get(n.uuid) == key_only for n in self.nodes
                   if self.status.get(n.uuid) != OK):  # fmt: skip
                forwarded = self.app.env.transport.agent_forwarded
                hint = "access.key_only.hint.agent" if forwarded else "access.key_only.hint"
                lines.append(Notice("warning", t(hint)))
        admin = self.session.data.get("admin")
        if admin and admin["mode"] == "local":
            own = int(admin.get("own") or 0)
            key = "access.admin.local.some" if own else "access.admin.local.none"
            lines.append(Text(t(key, n=own), style="muted"))
        elif admin:
            mode = admin["mode"]
            lines.append(Text(t("access.answer.admin." + mode, n=len(admin.get("keys") or [])),
                              style="muted"))  # fmt: skip
        whois = self.whois_answer() if self.asks_whois() else None
        if whois is not None:
            lines.append(Text(t("access.answer.whois." + ("yes" if whois else "no")),
                              style="muted"))  # fmt: skip

        def handle(key: str) -> Optional[str]:
            if key == "enter":
                return NEXT
            if key == "esc":
                return BACK
            if hotkey(key) == "k" and admin and admin["mode"] != "local":
                return "admin"
            if hotkey(key) == "w" and whois is not None:
                return "whois"
            return None

        keys: list = [("Enter", t("keys.next")), ("Esc", t("keys.back"))]
        if admin and admin["mode"] != "local":
            keys.append(("k", t("keys.admin_key")))
        if whois is not None:
            keys.append(("w", t("keys.whois")))
        keys.append(("q", t("keys.quit")))
        self.action = ""
        answer = self.app.interact(self.title, self.frame(*lines), tuple(keys), handle)
        if answer == "admin":
            self.session.data["admin"] = self.choose_admin(admin)
            return self.summary()
        if answer == "whois":
            self.app.env.state.remember(whois=not whois)
            return self.summary()
        return answer

    def asks_whois(self) -> bool:
        """whois only matters with two nodes and more (§10.2, theme 1)."""
        return len(self.nodes) >= 2

    def ask_admin(self, previous: Optional[dict] = None) -> dict:
        """§8.5: which key keeps the person's own access; the last answer is preselected."""
        text = self.app.env.host.read_text(ROOT_KEYS) or ""
        own = [k for k in parse_authorized_keys(text) if not k.is_kerberos]
        items = []
        if own:
            items.append(("mine", t("access.admin.mine", n=len(own)), ""))
        items.append(("create", t("access.admin.create"), ""))
        items.append(("skip", t("access.admin.skip"), ""))
        modes = [item[0] for item in items]
        mode = (previous or {}).get("mode")
        intro = t("access.admin_keys") if own else t("access.no_admin_key")
        prompt = Group(Text(intro), Text(t("access.admin.later"), style="muted"))
        choice = self.ask_menu(prompt, items, modes.index(mode) if mode in modes else 0,
                               t("keys.skip"))  # fmt: skip
        if choice != "mine":
            return {"mode": choice, "keys": []}
        chosen = set((previous or {}).get("keys") or []) if mode == "mine" else set()
        marked = {i for i, k in enumerate(own) if k.line in chosen} or set(range(len(own)))
        rows = [[k.type, k.comment or "—", k.fingerprint] for k in own]
        checklist = Checklist(
            rows,
            [t("access.col.type"), t("access.col.comment"), t("access.col.fingerprint")],
            selected=marked,
        )

        def handle(key: str) -> Optional[str]:
            if key == "esc":
                return "skip"
            if checklist.handle(key) == "done":
                return "done" if checklist.selected else None
            return None

        keys = ((t("keys.space"), t("keys.toggle")), ("Enter", t("keys.next")),
                ("Esc", t("keys.skip")))  # fmt: skip
        body = Group(Text(t("access.admin.choose")), checklist)
        result = self.app.interact(t("access.admin.title"), body, keys, handle)
        if result == "skip":
            return {"mode": "skip", "keys": []}
        return {"mode": "mine", "keys": [own[i].line for i in sorted(checklist.selected)]}


def reason_of(exc: TransportError) -> str:
    if exc.kind == "hostkey_changed":
        return t("access.reason.hostkey")
    if exc.kind in ("refused", "timeout", "unreachable"):
        return t("access.reason.unreachable")
    if exc.kind == "auth":
        return t("access.reason.login")
    return t("access.reason.failed", detail=exc.kind)


def step(app: App, session: Session) -> Any:
    result = AccessScreen(app, session).run()
    if result == BACK:
        # 3x-ui has no S3: the node step sends the person on to S2 (§7.6).
        session.data["back_from_access"] = True
    return result
