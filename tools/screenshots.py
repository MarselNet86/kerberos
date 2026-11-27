"""Screenshots for README and docs (tech.md §2.7, §12.4): the demo fleet, masked.

Runs the scenario of docs/video.md on the built-in fleet with masking on, the
way `./kerberos --demo --mask` would, and saves chosen screens as SVG (Rich
export) to docs/screens/. Only demo data and documentation addresses can
appear in them. Development tool; KERBEROS does not use it.

    python3 tools/screenshots.py
"""

from __future__ import annotations

import io
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "vendor")]

from rich.console import Console, RenderableType  # noqa: E402

from kerberos.app import App, Env  # noqa: E402
from kerberos.clock import FakeClock  # noqa: E402
from kerberos.copy import t  # noqa: E402
from kerberos.demo.fleet import attach  # noqa: E402
from kerberos.mask import Masker  # noqa: E402
from kerberos.ui.palette import theme  # noqa: E402
from kerberos.ui.terminal import FakeTerminal  # noqa: E402

OUT = ROOT / "docs" / "screens"
WIDTH = 100


def typed(text: str) -> list[str]:
    return ["space" if ch == " " else ch for ch in text]


# S2 API token (the demo panel takes any); S3 all nodes; S4: kz-1 skipped, one table of
# host keys, python3 for de-1, «Мои ключи», the summary; whois allowed; S6 → S7. The keys
# of S7 come from the plan itself (plan_keys).
TO_PLAN = typed("rw-demo-token") + ["enter"]
TO_PLAN += ["enter"] + ["esc", "enter", "enter"] + ["enter", "enter"]
TO_PLAN += ["enter", "enter", "enter"]
APPLY = ["enter", "enter", "enter"]  # S7 → consent → accept → S9 Enter


def plan_keys(app: App, items: list[Any]) -> list[str]:
    """In S7 (K23): all that can run, the group of new SSH ports (`a` leaves it to the
    person, §6), the confirmed CDN nets, a domain in every row of the own domain."""
    from kerberos.screens.fix import plan_rows

    upper, domains = plan_rows(items, set())
    keys = ["a"]
    for index, row in enumerate(upper + domains):
        go = ["home"] + ["down"] * index
        if row.kind == "group" and row.group == "ssh_port":
            keys += go + ["space"]
        elif row.kind == "group" and any(items[i].fix_id == "cdn.edge_only" for i in row.indexes):
            keys += go + ["e", "enter"]
        elif row.kind == "domain":
            name = app.session_name(items[row.indexes[0]].node_uuid)
            keys += go + ["d"] + typed(f"{name}.example.com") + ["enter"]
    return keys


class ShotTerminal(FakeTerminal):
    """The fake terminal that also keeps every frame in colour, for SVG export."""

    def __init__(self, keys: list[str], height: int, clock: FakeClock) -> None:
        super().__init__(keys, width=WIDTH, height=height, on_idle=clock.advance)
        self.shots: list[tuple[str, str]] = []  # (first line of the frame, svg)
        self.app: Optional[App] = None
        self.planned = False

    def draw(self, renderable: RenderableType) -> None:
        super().draw(renderable)
        head = self.frames[-1].splitlines()[0]
        console = Console(file=io.StringIO(), width=self.width, height=self.height,
                          theme=theme(), force_terminal=True, color_system="truecolor",
                          markup=False, emoji=False, highlight=False, record=True,
                          legacy_windows=False, soft_wrap=False)  # fmt: skip
        console.print(renderable, end="")
        self.shots.append((head, console.export_svg(title="kerberos")))
        if not self.planned and self.app is not None and head.startswith(self.title("plan")):
            self.planned = True
            items = self.app.session.data["plan"]
            self._keys.extendleft(reversed(plan_keys(self.app, items)))

    @staticmethod
    def title(screen: str) -> str:
        key = {"plan": "plan.title", "s6": "s6.title", "s8": "s8.title", "s9": "done.title"}
        return f"/// kerberos  {t(key[screen])}"

    def screens(self, screen: str) -> list[str]:
        return [svg for head, svg in self.shots if head.startswith(self.title(screen))]


def app_for(keys: list[str], height: int) -> tuple[App, ShotTerminal]:
    clock = FakeClock()
    term = ShotTerminal(keys, height, clock)
    env = Env(terminal=term, clock=clock, masker=Masker(True), demo=True)
    env.panel_kind = "remnawave"  # the README shows the Remnawave scenario
    # A short neutral path: the report line shows where the state lives.
    attach(env, Path(tempfile.mkdtemp(prefix="kerberos-", dir="/tmp")))
    app = App(env)
    term.app = app
    return app, term


def main(out: Path = OUT) -> int:
    from kerberos.screens import fix

    # S9 shows the commands to roll back and finalize: with the path of an installed
    # KERBEROS (§5.1), never of the checkout the screenshots are taken in.
    checkout, fix.launcher = fix.launcher, lambda: "/opt/kerberos/kerberos"
    try:
        return shoot(out)
    finally:
        fix.launcher = checkout


def shoot(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    app, term = app_for(["q", "enter"], 30)
    app.run(None)
    shots = {"s1.svg": term.shots[0][1]}

    app, term = app_for(TO_PLAN + APPLY, 40)
    app.run("fix")
    board = term.screens("s8")
    shots.update({
        "s6.svg": term.screens("s6")[0],
        "s7.svg": term.screens("plan")[-1],
        "s8.svg": board[len(board) // 2],
        "s9.svg": term.screens("s9")[0],
    })  # fmt: skip
    for name, svg in shots.items():
        (out / name).write_text(svg, encoding="utf-8")
    print(f"{', '.join(shots)} -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
