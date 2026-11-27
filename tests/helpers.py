"""Shared builders for app-level tests."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Sequence
from functools import cache
from pathlib import Path
from typing import Optional

from kerberos.app import App, Env
from kerberos.clock import FakeClock
from kerberos.demo.fleet import build_host, build_nodes, build_panel
from kerberos.demo.nodes import auth_methods_of, build_prober, build_whois
from kerberos.demo.xui import attach_xui
from kerberos.host import FakeHost
from kerberos.mask import Masker
from kerberos.nodes.fake import FakeNode, FakeTransport
from kerberos.panel.fake import FakePanel
from kerberos.state import State
from kerberos.ui.terminal import FakeTerminal

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOTS = ROOT / "tests" / "snapshots"


def assert_snapshot(name: str, text: str) -> None:
    """Compare with tests/snapshots/<name>.txt; KERBEROS_UPDATE_SNAPSHOTS=1 rewrites it."""
    path = SNAPSHOTS / f"{name}.txt"
    if os.environ.get("KERBEROS_UPDATE_SNAPSHOTS") == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
        return
    assert path.exists(), f"no snapshot {path}; run with KERBEROS_UPDATE_SNAPSHOTS=1"
    expected = path.read_text(encoding="utf-8").rstrip("\n")
    assert text == expected, f"snapshot {name} differs"


def flat(frame: str) -> str:
    """Frame text without box borders and line breaks: wrapped plates read as one line."""
    import re

    text = re.sub(r"[│╭╮╰╯─]", " ", frame)
    return re.sub(r"\s+", " ", text)


def seen(term, text: str) -> bool:
    return any(text in flat(frame) for frame in term.frames)


LOGIN = ["enter"]  # S1: «Проверка» is the first item


def typed(text: str) -> list[str]:
    return ["space" if ch == " " else ch for ch in text]


TOKEN = "rw-test-token"  # the demo panel takes any API token (§7.3)


# S4 of the demo fleet (K25): kz-1 shows no SSH on port 22 (Esc on its port), one table
# confirms the four other host keys (Enter), de-1 has no python3 (Enter installs it).
S4_KEYS = ["esc", "enter", "enter"]


def login_keys(name: str = "admin", password: str = "admin-password") -> list[str]:
    """S2 with no saved token (K30): the admin's login, Tab, the password, Enter; KERBEROS
    makes its own API token. The defaults are the admin of the fake panel."""
    return typed(name) + ["tab"] + typed(password) + ["enter"]


def token_keys(token: str = TOKEN) -> list[str]:
    """S2 with no saved token, a token of the person's own: Tab twice to «У меня есть
    API-токен» under the login, Enter, the token, Enter (K30)."""
    return ["tab", "tab", "enter"] + typed(token) + ["enter"]


def make_app(
    keys: Sequence[str],
    *,
    width: int = 100,
    height: int = 30,
    demo: bool = True,
    mask: bool = False,
    panel: Optional[FakePanel] = None,
    host: Optional[FakeHost] = None,
    nodes: Optional[list[FakeNode]] = None,
    state: Optional[State] = None,
    panel_kind: Optional[str] = "remnawave",
) -> tuple[App, FakeTerminal]:
    clock = FakeClock()
    term = FakeTerminal(keys, width=width, height=height, on_idle=clock.advance)
    env = Env(terminal=term, clock=clock, masker=Masker(mask), demo=demo)
    env.host = host if host is not None else build_host()
    env.panel_transport = panel if panel is not None else build_panel()
    env.state = state or State(Path(tempfile.mkdtemp(prefix="kerberos-test-")))
    env.transport = FakeTransport(nodes if nodes is not None else build_nodes(), env.state)
    env.prober = build_prober(env.panel_transport, list(env.transport.nodes.values()))
    env.prober.auth = auth_methods_of(list(env.transport.nodes.values()))
    env.whois = build_whois()
    # Scenarios of Remnawave skip the question of S2; tests of the choice pass None.
    env.panel_kind = panel_kind
    attach_xui(env)
    return App(env), term


@cache
def demo_plan() -> tuple:
    """Plan items of the demo fleet as TO_PLAN reaches S7, in plan order."""
    from demo_input import demo_input

    from kerberos.checks import run_checks
    from kerberos.fixes.plan import build_plan

    _env, data = demo_input()
    admin = {"mode": "mine", "keys": ["ssh-ed25519 AAAA admin@laptop"]}
    names = {n.node.uuid: n.node.name for n in data.nodes}
    plan = build_plan(run_checks(data), data, admin, {})
    return tuple((item, names) for item in plan)


def _who(item, names: dict) -> str:
    kind, _, ref = item.target.partition(":")
    return names.get(ref, ref) if kind == "node" else kind


def plan_rows() -> tuple[tuple[str, str], ...]:
    """Items of the demo plan as (who, fixId), in plan order. `who` is the node name for
    node targets, else host, template or panel. Reserve pairs come only with `r`."""
    return tuple((_who(item, names), item.fix_id) for item, names in demo_plan())


def plan_index(who: str, fix_id: str) -> int:
    """Index of an item in session.data["plan"] of the demo fleet."""
    return plan_rows().index((who, fix_id))


def on(who: str, fix_id: str, *keys: str) -> list[str]:
    """S7 (K23): the keys that take the cursor to the row of (who, fix_id) of the demo
    plan, press `keys` there and fold its group again with ←, so every call starts from
    folded groups. `keys` must stay on S7 (Space, d, e, p, g, r and what they ask)."""
    from kerberos.report.areas import plan_group
    from kerberos.screens.fix import plan_rows as layout

    items = [item for item, _names in demo_plan()]
    target = plan_index(who, fix_id)
    upper, domains = layout(items, set())
    rows = upper + domains
    if fix_id == "self_steal":
        index = next(n for n, r in enumerate(rows) if r.kind == "domain" and r.indexes == [target])
        return ["home"] + ["down"] * index + list(keys)
    group = plan_group(fix_id)
    index = next(n for n, r in enumerate(rows) if r.kind == "group" and r.group == group)
    position = rows[index].indexes.index(target)
    return ["home"] + ["down"] * index + ["right"] + ["down"] * (position + 1) + [*keys, "left"]


def on_group(group: str, *keys: str) -> list[str]:
    """S7 (K23): the keys that take the cursor to a group row of the demo plan."""
    from kerberos.screens.fix import plan_rows as layout

    upper, _domains = layout([item for item, _names in demo_plan()], set())
    index = next(n for n, r in enumerate(upper) if r.kind == "group" and r.group == group)
    return ["home"] + ["down"] * index + list(keys)
