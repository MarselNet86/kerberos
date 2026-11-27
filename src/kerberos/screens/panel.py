"""S2. Panel (tech.md §6, §7): find the panel, sign in from the window, read it.

Remnawave lets programs in only with an API token (§7.3): the saved one in
/var/lib/kerberos/panel.token; else KERBEROS makes its own with the admin's
login and password, typed here and forgotten at once (K30), or the person
pastes a token of their own. 3x-ui takes a login and a password, kept in memory.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any, Optional

from rich.console import Group, RenderableType
from rich.text import Text

from kerberos.copy import t
from kerberos.flow import BACK, EXIT_PANEL, NEXT
from kerberos.panel.client import SCOPES_CHECK, SCOPES_FIX, PanelClient, section_of
from kerberos.panel.discover import PanelLocation, discover, discover_xui
from kerberos.panel.errors import PanelError
from kerberos.panel.model import PanelSnapshot
from kerberos.ui.widgets import POINTER, Menu, Notice, Stack, TextInput

if TYPE_CHECKING:
    from kerberos.app import App, Session

API_RE = re.compile(r"^https?://[\w.\-\[\]:]+(:\d{1,5})?(/[\w.\-/]*)?$")
# An API token of the panel is a JWT: base64url parts and dots. Letters of another
# layout cannot be in it, and urllib could not send them anyway.
TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/=-]+")


def keys_form() -> tuple:
    return (
        ("Tab", t("keys.field")),
        ("Enter", t("keys.next")),
        ("Esc", t("keys.back")),
    )


def keys_field() -> tuple:
    return (("Enter", t("keys.next")), ("Esc", t("keys.back")))


UNREACHABLE = {"remnawave": "panel.err.unreachable", "3x-ui": "panel.xui.err.unreachable"}


def error_text(exc: PanelError, api: str = "", kind: str = "") -> str:
    """What went wrong and what to do; `kind` names the panel to check (§7.5, §7.6)."""
    if exc.code == "unauthorized":
        return t("panel.err.token")
    if exc.code == "forbidden":
        return forbidden_text(exc)
    if exc.code == "server_error":
        return t("panel.err.server", status=exc.status, operation=exc.operation)
    if exc.code == "timeout":
        return t("panel.err.timeout", operation=exc.operation)
    if exc.code == "unreachable":
        return t(UNREACHABLE.get(kind, "panel.err.unreachable.any"), api=api)
    if exc.code == "no_response":
        return t("panel.err.no_response", operation=exc.operation)
    if exc.code == "bad_request":
        return t("panel.err.bad_request", operation=exc.operation, detail=exc.detail)
    return t("panel.err.bad_response", detail=exc.detail or exc.operation)


def forbidden_text(exc: PanelError) -> str:
    """Which right of the API token the panel refused, and what to do (§7.5)."""
    section, kind = section_of(exc.operation)
    if not section:
        return t("panel.err.forbidden.other", operation=exc.operation)
    return t("panel.err.forbidden", kind=t(f"panel.right.{kind}"),
             section=t(f"panel.section.{section}"))  # fmt: skip


def found_lines(app: App, location: PanelLocation) -> list[RenderableType]:
    if location.version == "?":
        # Typed by hand (or found without a version): no «Нашёл Remnawave ?».
        lines = [Text(t("panel.manual", api=app.mask(location.api)), style="bold")]
    else:
        lines = [Text(t("panel.found", version=location.version), style="bold"),
                 Text(t("panel.api", api=app.mask(location.api)), style="muted")]  # fmt: skip
    if location.panel_domain:
        lines.append(Text(t("panel.domain", domain=app.mask(location.panel_domain)), style="muted"))
    return lines


def ask_api(app: App) -> Optional[str]:
    field = TextInput(
        t("panel.api_label"),
        hint=t("panel.api_hint"),
        validate=lambda v: None if API_RE.match(v.strip()) else t("panel.api_invalid"),
        value="http://127.0.0.1:3000/api",
    )

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return ""
        return field.handle(key)

    body = Group(Notice("warning", t("panel.not_found")), Text(""), field)
    value = app.interact(t("s2.title"), body, keys_form(), handle, typing=True)
    return value.strip() or None


def connect(app: App, client: PanelClient, location: PanelLocation) -> bool:
    """The panel answers (§7.3, step 1). False: the person gave up."""
    while True:
        try:
            client.reachable()
            return True
        except PanelError as exc:
            if not app.ask_retry(t("s2.title"), error_text(exc, location.api, location.kind)):
                return False


def token_help(write: bool) -> list[RenderableType]:
    """Where to make the token and which rights to give it, as the panel takes them pasted."""
    return [
        Text(t("panel.token_hint")),
        Text(""),
        Text(t("panel.token_rights.fix" if write else "panel.token_rights.check")),
        Text(json.dumps(SCOPES_FIX if write else SCOPES_CHECK)),
        Text(""),
    ]


def save_token(app: App, token: str, write: bool, uuid: Optional[str] = None) -> None:
    if app.env.state is not None:
        app.env.state.write_panel_token(token, write, uuid)


def settle_token(app: App, client: Any) -> None:
    """§7.3, after a run: a token the panel refused something is forgotten, and the next
    run asks for one; a token that made a change is known to have the rights for it."""
    state = app.env.state
    if state is None or not getattr(client, "token_source", ""):
        return
    if getattr(client, "refused", False):
        state.forget_panel_token()
    elif getattr(client, "wrote", False):
        state.mark_panel_token_writable()


def ask_keep(app: App, location: PanelLocation) -> Optional[str]:
    """«keep» or «new» for a saved token given for «Проверка» when a run changes the
    panel (§7.3); None: Esc."""
    menu = Menu([("keep", t("panel.token.keep"), t("panel.token.keep.hint")),
                 ("new", t("panel.token.new"), t("panel.token.new.hint"))])  # fmt: skip

    def handle(key: str) -> Optional[str]:
        return "back" if key == "esc" else menu.handle(key)

    body = Group(*found_lines(app, location), Text(""), Text(t("panel.token.readonly")),
                 Text(""), menu)  # fmt: skip
    keys = (("↑↓", t("keys.select")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
    choice = app.interact(t("s2.title"), body, keys, handle)
    return None if choice == "back" else choice


def ensure_write_token(app: App, session: Any) -> bool:
    """S6 `f`: «Исправление» on the client of the check needs a token that may change the
    panel. False: the person went back."""
    state = app.env.state
    if session.location.kind == "3x-ui" or state is None or state.panel_token_can_write():
        return True
    choice = ask_keep(app, session.location)
    if choice is None:
        return False
    if choice == "keep":
        return True
    return credentials(app, session.panel, session.location, True)


def credentials(
    app: App, client: PanelClient, location: PanelLocation, write: bool,
    error: Optional[str] = None,
) -> bool:  # fmt: skip
    """§7.3, steps 3 and 4: the admin's login and password, or the person's own token when
    the panel takes no password (K30). False: the person went back."""
    if not getattr(client, "password_login", True):
        return token_form(app, client, location, write, error, t("panel.admin.disabled"))
    return admin_form(app, client, location, write, error)


def admin_form(
    app: App, client: PanelClient, location: PanelLocation, write: bool,
    error: Optional[str] = None,
) -> bool:  # fmt: skip
    """§7.3, step 3 (K30): login and password; Tab, ↑↓ and Enter go from one field to the
    next, and the row under them opens the form for a token of the person's own. The
    password is cleared as soon as it went out. False: the person went back."""
    login = TextInput(t("panel.admin.login"))
    password = TextInput(t("panel.password"), secret=True)
    fields = [login, password]
    row = len(fields)  # the third stop of Tab: «У меня есть API-токен»
    state: dict[str, Any] = {"focus": 0, "error": error}

    def body(_w: int, _h: int) -> RenderableType:
        for i, item in enumerate(fields):
            item.focused = i == state["focus"]
        parts: list[RenderableType] = [Text(t("panel.admin.hint")), Text("")]
        for item in fields:
            parts += [item, Text("")]
        if state["error"]:
            # Under the fields, where the person looks; the note was read before (80×24).
            parts += [Notice("error", state["error"]), Text("")]
        current = state["focus"] == row
        line = Text(POINTER + " " if current else "  ", style="accent")
        line.append(t("panel.admin.token_instead"), style="accent" if current else "")
        parts.append(line)
        if not state["error"]:
            parts += [Text(""), Text(t("panel.admin.note"), style="muted")]
        return Stack(Group(*found_lines(app, location), Text("")), Group(*parts), flex=0)

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        if key in ("tab", "down"):
            state["focus"] = (state["focus"] + 1) % (row + 1)
            return None
        if key == "up":
            state["focus"] = (state["focus"] - 1) % (row + 1)
            return None
        if key == "enter":
            if state["focus"] == row:
                return "token"
            if not login.value.strip():
                state["focus"] = 0
            elif not password.value:
                state["focus"] = 1
            else:
                return "submit"
            return None
        if state["focus"] < row:
            fields[state["focus"]].handle(key)
            state["error"] = None
        return None

    while True:
        choice = app.interact(t("s2.title"), body, keys_form(), handle, typing=True)
        if choice == "back":
            password.clear()
            return False
        if choice == "token":
            password.clear()
            if token_form(app, client, location, write):
                return True
            state["focus"] = 0  # Esc in the token form: back to the login (§6 S2)
            continue
        name, secret = login.value.strip(), password.value
        password.clear()
        outcome = admin_sign_in(app, client, location, name, secret)
        secret = ""
        if outcome is True:
            return True
        if outcome is None:
            return False  # the panel did not answer and the person gave up
        state["error"], state["focus"] = outcome, 1


def admin_sign_in(app: App, client: PanelClient, location: PanelLocation, name: str,
                  secret: str) -> Any:  # fmt: skip
    """True: KERBEROS has its own API token now; a text: why not; None: no answer and the
    person gave up. The new token is saved with its uuid at once, before it is tried:
    a token the panel then refuses is forgotten, its uuid stays for the next login (K30)."""
    state = app.env.state
    previous = state.panel_token_uuid() if state is not None else None
    while True:
        app.draw(t("s2.title"), Text(t("panel.admin.signing_in")))
        try:
            token, uuid = client.make_token(name, secret, previous)
            break
        except PanelError as exc:
            if exc.operation == "POST /auth/login" and exc.code in ("forbidden", "unauthorized"):
                return t("panel.err.admin_login")
            if exc.code in ("forbidden", "unauthorized", "bad_request", "bad_response"):
                return t("panel.err.token_create", detail=exc.detail or exc.operation)
            if not app.ask_retry(t("s2.title"), error_text(exc, location.api, location.kind)):
                return None
    save_token(app, token, True, uuid)
    outcome = try_token(app, client, location, token)
    if outcome is True:
        client.token_source = "made"
        return True
    if state is not None:
        state.forget_panel_token()
    return outcome  # why the panel refused the token it has just made, or None


def token_form(
    app: App, client: PanelClient, location: PanelLocation, write: bool,
    error: Optional[str] = None, note: Optional[str] = None,
) -> bool:  # fmt: skip
    """§7.3, step 4: a token typed in, kept once GET /nodes passes. False: the person went back.

    `note`: why the form comes first (the panel takes no password, K30)."""
    token = TextInput(t("panel.token"), secret=True)
    state: dict[str, Any] = {"error": error}

    def body(_w: int, _h: int) -> RenderableType:
        parts: list[RenderableType] = [Text(note, style="bold"), Text("")] if note else []
        parts += token_help(write) + [token, Text("")]
        # The error takes the place of the note under the field; in a low terminal the
        # lines of where the panel is give way first (80×24, §14.2).
        if state["error"]:
            parts.append(Notice("error", state["error"]))
        else:
            parts.append(Text(t("panel.token_saved_note"), style="muted"))
        return Stack(Group(*found_lines(app, location), Text("")), Group(*parts), flex=0)

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        if key == "enter":
            return "submit" if token.value.strip() else None
        token.handle(key)
        state["error"] = None
        return None

    while True:
        if app.interact(t("s2.title"), body, keys_field(), handle, typing=True) == "back":
            token.clear()
            return False
        value = token.value.strip()
        token.clear()
        if not TOKEN_RE.fullmatch(value):
            state["error"] = t("panel.err.token")
            continue
        outcome = try_token(app, client, location, value)
        if outcome is True:
            save_token(app, value, write)
            client.token_source = "typed"
            return True
        if outcome is None:
            return False  # the panel did not answer and the person gave up
        state["error"] = outcome


def try_token(app: App, client: PanelClient, location: PanelLocation, value: str) -> Any:
    """True: the panel takes it; a text: why not; None: no answer and the person gave up.

    A retry sends the same token again: the panel shows a new token only once.
    """
    while True:
        client.set_token(value)
        app.draw(t("s2.title"), Text(t("panel.connecting")))
        try:
            client.nodes()
            return True
        except PanelError as exc:
            client.forget_token()
            if exc.code == "unauthorized":
                return t("panel.err.token")
            if exc.code == "forbidden":
                return forbidden_text(exc)
            if not app.ask_retry(t("s2.title"), error_text(exc, location.api, location.kind)):
                return None


def sign_in(app: App, client: PanelClient, location: PanelLocation, write: bool) -> bool:
    """§7.3, step 2: the saved token, if the panel still takes it; else KERBEROS makes
    its own with the admin's login and password, or the person pastes one (K30).

    A run that changes the panel asks first about a token pasted for «Проверка».
    """
    state = app.env.state
    saved = state.read_panel_token() if state is not None else None
    error = None
    if saved and write and not state.panel_token_can_write():
        choice = ask_keep(app, location)
        if choice is None:
            return False
        if choice == "new":
            saved = None
    while saved:
        client.set_token(saved)
        app.draw(t("s2.title"), Text(t("panel.connecting")))
        try:
            client.nodes()
            client.token_source = "saved"
            return True
        except PanelError as exc:
            client.forget_token()
            if exc.code in ("unauthorized", "forbidden"):
                error = t("panel.token.stale")  # deleted or expired in the panel
                break
            if not app.ask_retry(t("s2.title"), error_text(exc, location.api, location.kind)):
                return False
    return credentials(app, client, location, write, error)


def load(
    app: App, client: PanelClient, location: PanelLocation, write: bool = False
) -> Optional[PanelSnapshot]:
    while True:
        app.draw(t("s2.title"), Text(t("panel.loading")))
        try:
            return client.snapshot(location.version, location.panel_domain)
        except PanelError as exc:
            if exc.code in ("forbidden", "unauthorized"):
                # A right GET /nodes could not show is missing: another token, then again.
                client.forget_token()
                text = forbidden_text(exc) if exc.code == "forbidden" else t("panel.err.token")
                if not credentials(app, client, location, write, text):
                    return None
                continue
            if not app.ask_retry(t("s2.title"), error_text(exc, location.api, location.kind)):
                return None


def register_sensitive(app: App, snapshot: PanelSnapshot) -> None:
    """Domains of the fleet are masked on every screen and in the report."""
    masker = app.env.masker
    masker.register(snapshot.panel_domain)
    for node in snapshot.nodes:
        masker.register(node.address)
    for host in snapshot.hosts:
        masker.register(host.address, host.sni)
    for profile in snapshot.profiles:
        for inbound in profile.config.get("inbounds") or []:
            stream = (inbound or {}).get("streamSettings") or {}
            reality = stream.get("realitySettings") or {}
            for name in reality.get("serverNames") or []:
                if isinstance(name, str):
                    masker.register(name)
            dest = reality.get("target") or reality.get("dest")
            if isinstance(dest, str):
                masker.register(dest.rsplit(":", 1)[0])


PANELS = ("remnawave", "3x-ui")


def choose_panel(app: App, ask: bool = False) -> Any:
    """§6 S2, §7.6: which panel runs here, Remnawave or 3x-ui; the one found is first.

    (kind, location or None) or BACK. `--panel` answers without asking, and so does a
    server where only one panel was found (K25), unless `ask`.
    """
    app.draw(t("s2.title"), Text(t("panel.searching")))
    host = app.env.host
    found = {
        "remnawave": discover(host) if host is not None else None,
        "3x-ui": discover_xui(host) if host is not None else None,
    }
    wanted = getattr(app.env, "panel_kind", None)
    if wanted in PANELS:
        return wanted, found[wanted]
    present = [kind for kind in PANELS if found[kind] is not None]
    if len(present) == 1 and not ask:
        return present[0], found[present[0]]
    items = []
    for kind in PANELS:
        location = found[kind]
        hint = (t("panel.choose.found", version=location.version) if location
                else t("panel.choose.none"))  # fmt: skip
        items.append((kind, t(f"panel.kind.{kind}"), hint))
    first = 1 if found["3x-ui"] and not found["remnawave"] else 0
    menu = Menu(items, selected=first)

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return "back"
        return menu.handle(key)

    body = Group(Text(t("panel.choose"), style="bold"), Text(""), menu, Text(""),
                 Text(t("panel.choose.hint"), style="muted"))  # fmt: skip
    keys = (("↑↓", t("keys.select")), ("Enter", t("keys.next")), ("Esc", t("keys.back")))
    choice = app.interact(t("s2.title"), body, keys, handle)
    if choice == "back":
        return BACK
    return choice, found[choice]


def open_panel(app: App, kind: Optional[str] = None, write: bool = True) -> Any:
    """Find the panel and sign in. A (location, client) pair, BACK or EXIT_PANEL.

    `kind` skips the question (rollback and finalize know the panel of the run);
    `write`: the run changes the panel, so the token needs write rights too (§7.3).
    """
    if kind is None:
        ask = False
        while True:
            chosen = choose_panel(app, ask)
            if chosen == BACK:
                return BACK
            opened = sign_in_to(app, *chosen, write)
            if opened != BACK or getattr(app.env, "panel_kind", None) in PANELS:
                return opened
            ask = True  # Esc on the token: the choice the person did not see (K25)
    host = app.env.host
    finder = discover_xui if kind == "3x-ui" else discover
    location = finder(host) if host is not None else None
    return sign_in_to(app, kind, location, write)


def sign_in_to(app: App, kind: str, location: Optional[PanelLocation], write: bool) -> Any:
    if kind == "3x-ui":
        return open_xui(app, location)
    if location is None:
        api = ask_api(app)
        if api is None:
            return BACK
        location = PanelLocation(api=api, version="?")
    app.env.masker.register(location.panel_domain)
    client = PanelClient(location.api, app.env.panel_transport, app.env.clock)
    if not connect(app, client, location):
        return EXIT_PANEL
    if not sign_in(app, client, location, write):
        return BACK
    return location, client


# -- 3x-ui (§7.6) ------------------------------------------------------------------
XUI_URL_RE = re.compile(r"^https?://[\w.\-\[\]:]+(:\d{1,5})?(/[\w.\-/]*)?$")


def ask_xui_url(app: App) -> Optional[str]:
    field = TextInput(
        t("panel.xui.url_label"),
        hint=t("panel.xui.url_hint"),
        validate=lambda v: None if XUI_URL_RE.match(v.strip()) else t("panel.xui.url_invalid"),
        value="http://127.0.0.1:2053/",
    )

    def handle(key: str) -> Optional[str]:
        if key == "esc":
            return ""
        return field.handle(key)

    body = Group(Notice("warning", t("panel.xui.not_found")), Text(""), field)
    value = app.interact(t("s2.title"), body, keys_form(), handle, typing=True)
    return value.strip() or None


def xui_lines(app: App, location: PanelLocation) -> list[RenderableType]:
    """Where the panel is, without its secret path: that path is a password of sorts."""
    if location.version != "?":
        head = t("panel.xui.found", version=location.version)
    else:
        # Found here without a version, or typed by hand (no settings were read).
        head = t("panel.xui.found.unknown") if location.info else t("panel.xui.manual")
    lines: list[RenderableType] = [Text(head, style="bold")]
    if location.info.get("port"):
        lines.append(Text(t("panel.xui.port", port=location.info["port"]), style="muted"))
    if location.panel_domain:
        lines.append(Text(t("panel.domain", domain=app.mask(location.panel_domain)), style="muted"))
    return lines


def xui_login_form(app: App, client: Any, location: PanelLocation) -> bool:
    from kerberos.panel.xui import origin

    fields = [TextInput(t("panel.xui.login")), TextInput(t("panel.password"), secret=True)]
    if location.info.get("twoFactor"):
        fields.append(TextInput(t("panel.xui.code"), secret=True))
    state: dict[str, Any] = {"focus": 0, "error": None}

    def body(_w: int, _h: int) -> RenderableType:
        for i, item in enumerate(fields):
            item.focused = i == state["focus"]
        parts = xui_lines(app, location) + [Text(""), Text(t("panel.xui.login_hint")), Text("")]
        for item in fields:
            parts += [item, Text("")]
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
            if all(item.value.strip() for item in fields):
                return "submit"
            state["focus"] = next(i for i, item in enumerate(fields) if not item.value.strip())
            return None
        fields[state["focus"]].handle(key)
        state["error"] = None
        return None

    def forget() -> None:
        for item in fields[1:]:
            item.clear()

    while True:
        if app.interact(t("s2.title"), body, keys_form(), handle, typing=True) == "back":
            forget()
            return False
        app.draw(t("s2.title"), Text(t("panel.connecting")))
        values = [item.value for item in fields]
        try:
            client.login(values[0].strip(), values[1], values[2].strip() if len(values) > 2 else "")
            forget()
            return True
        except PanelError as exc:
            forget()
            if exc.code == "unauthorized":
                state["error"] = t("panel.xui.err.login")
            elif exc.code == "forbidden":
                state["error"] = t("panel.xui.err.forbidden")
            elif not app.ask_retry(t("s2.title"), error_text(exc, origin(location.api))):
                return False
            state["focus"] = 1


def open_xui(app: App, location: Optional[PanelLocation]) -> Any:
    from kerberos.panel.xui import XuiClient

    if location is None:
        url = ask_xui_url(app)
        if url is None:
            return BACK
        location = PanelLocation(api=url, version="?", kind="3x-ui")
    app.env.masker.register(location.panel_domain)
    client = XuiClient(location.api, app.env.xui_transport, app.env.clock, location.panel_domain)
    if not xui_login_form(app, client, location):
        return BACK
    return location, client


def public_ipv4(app: App, location: PanelLocation) -> Optional[str]:
    """The address the world reaches this server at: an interface, the panel domain, or asked."""
    from kerberos.agent import parse_ip_addr

    result = app.env.host.run(["ip", "-j", "addr", "show"], timeout=10)
    v4, _v6 = parse_ip_addr(result.stdout) if result.ok else ([], [])
    if v4:
        return v4[0]
    if location.panel_domain and app.env.prober is not None:
        found = [a for a in app.env.prober.resolve(location.panel_domain) if ":" not in a]
        if found:
            return found[0]
    field = TextInput(t("panel.xui.ip_label"), hint=t("panel.xui.ip_hint"),
                      validate=lambda v: None if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", v.strip())
                      else t("panel.xui.ip_invalid"))  # fmt: skip

    def handle(key: str) -> Optional[str]:
        return "" if key == "esc" else field.handle(key)

    value = app.interact(t("s2.title"), field, keys_form(), handle, typing=True).strip()
    return value or None


def load_xui(app: App, client: Any, location: PanelLocation) -> Optional[PanelSnapshot]:
    from kerberos.panel.xui import origin

    address = public_ipv4(app, location)
    if address is None:
        return None
    while True:
        app.draw(t("s2.title"), Text(t("panel.xui.loading")))
        try:
            return client.snapshot(location, address, app.env.host.hostname())
        except PanelError as exc:
            if not app.ask_retry(t("s2.title"), error_text(exc, origin(location.api))):
                return None


def panel_line(app: App, session: Session) -> list[RenderableType]:
    """«✓ Панель подключена: …» over S3 (on 3x-ui over S4): S2 does not stop for it (K25)."""
    location, snapshot = session.location, session.snapshot
    if location is None or snapshot is None:
        return []
    if location.kind == "3x-ui":
        line = Text(f"✓ {t('panel.xui.ok', inbounds=len(snapshot.hosts))}", style="ok")
        name = "3x-ui"
    else:
        line = Text(f"✓ {t('panel.ok', nodes=len(snapshot.nodes), hosts=len(snapshot.hosts))}",
                    style="ok")  # fmt: skip
        name = "Remnawave"
    extra = [name + ("" if location.version == "?" else f" {location.version}")]
    source = getattr(session.panel, "token_source", "")
    if source == "saved":
        extra.append(t("panel.token.used"))
    elif source == "made":
        extra.append(t("panel.token.made"))
    line.append(" · " + " · ".join(extra), style="muted")
    return [line]


def step(app: App, session: Session) -> Any:
    if session.snapshot is not None:
        # Back from S3 (on 3x-ui from S4): S2 has no screen of its own to stop at.
        return BACK
    write = session.mode != "check"
    opened = open_panel(app, write=write)
    if not isinstance(opened, tuple):
        return opened
    location, client = opened
    if location.kind == "3x-ui":
        snapshot = load_xui(app, client, location)
    else:
        snapshot = load(app, client, location, write)
    if snapshot is None:
        return EXIT_PANEL
    register_sensitive(app, snapshot)
    session.location, session.panel, session.snapshot = location, client, snapshot
    return NEXT
