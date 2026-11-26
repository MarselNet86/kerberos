"""Widgets (tech.md §14.4).

Each widget renders with Rich; interactive ones take key names from the
Terminal port through `handle(key)`. Widgets never read keys themselves and
never print: the app draws whole frames through the terminal.
Texts arrive already masked (`Masker`) and come from copy.py.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Callable, Optional, Union

from rich import box
from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.segment import Segment
from rich.table import Table
from rich.text import Text

from kerberos.copy import t
from kerberos.ui.keys import hotkey
from kerberos.ui.logo import LOGO, big_number
from kerberos.ui.palette import (
    SYMBOL_FAIL,
    SYMBOL_OK,
    SYMBOL_ROLLED_BACK,
    SYMBOL_RUNNING,
    score_style,
)

Body = Union[RenderableType, Callable[[int, int], RenderableType]]
# Keys of the footer; a callable gives them per frame (S7: the keys of the current row).
KeyHints = Union[Sequence[tuple[str, str]], Callable[[], Sequence[tuple[str, str]]]]

POINTER = "›"
# Without colour the reverse video of the cursor is lost: a bar marks its place.
CURSOR_BAR = "▏"
SCROLL_KEYS = ("up", "down", "pgup", "pgdn", "home", "end")


def text(value: Union[str, Text], style: str = "") -> Text:
    """Plain Text from a string; never parsed as markup."""
    if isinstance(value, Text):
        return value
    return Text(value, style=style)


def bold(value: str, style: str = "") -> Text:
    """Bold text in a colour of the palette: a palette name cannot share one style
    string with «bold», Rich would read it as a colour."""
    line = Text(value, style=style)
    line.stylize("bold")
    return line


class Screen:
    """Frame of every screen: header, body, footer with the keys of this screen."""

    def __init__(
        self,
        title: str,
        body: Body,
        keys: KeyHints = (),
        *,
        flags: Sequence[str] = (),
    ) -> None:
        self.title = title
        self.body = body
        self.keys = keys
        self.flags = flags

    @staticmethod
    def chrome_height() -> int:
        """Lines taken by header, rules and footer."""
        return 4

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        width = options.max_width
        height = options.height or console.height
        header = Table.grid(expand=True)
        header.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        header.add_column(justify="right", no_wrap=True)
        header.add_row(
            Text.assemble((LOGO, "logo"), "  ", (self.title, "bold")),
            Text(" · ".join(self.flags), style="muted"),
        )
        footer = Text(no_wrap=True, overflow="ellipsis")
        keys = self.keys() if callable(self.keys) else self.keys
        for i, (glyph, label) in enumerate(keys):
            if i:
                footer.append("  ")
            footer.append(glyph, style="bold")
            footer.append(" " + label, style="muted")
        body_height = max(1, height - self.chrome_height())
        body = self.body(max(10, width - 2), body_height) if callable(self.body) else self.body
        parts: list[tuple[RenderableType, int]] = [
            (header, 1),
            (Rule(style="muted"), 1),
            (Padding(body, (0, 1)), body_height),
            (Rule(style="muted"), 1),
            (footer, 1),
        ]
        first = True
        for renderable, lines_count in parts:
            lines = console.render_lines(
                renderable, options.update(width=width, height=lines_count), pad=True
            )
            for line in lines:
                if not first:
                    yield Segment.line()
                first = False
                yield from line


class Menu:
    """Choice of one item: ↑ ↓ move, Enter or the item number selects."""

    def __init__(self, items: Sequence[tuple[str, str, str]], selected: int = 0) -> None:
        self.items = list(items)
        self.selected = selected

    def handle(self, key: str) -> Optional[str]:
        if not self.items:
            return None
        if key == "up":
            self.selected = (self.selected - 1) % len(self.items)
        elif key == "down":
            self.selected = (self.selected + 1) % len(self.items)
        elif key == "enter":
            return self.items[self.selected][0]
        elif len(key) == 1 and key.isdigit() and 1 <= int(key) <= len(self.items):
            self.selected = int(key) - 1
            return self.items[self.selected][0]
        return None

    def __rich__(self) -> RenderableType:
        grid = Table.grid(padding=(0, 1))
        grid.add_column(no_wrap=True)
        grid.add_column(no_wrap=True, overflow="ellipsis")
        grid.add_column(overflow="ellipsis")
        for i, (_key, label, hint) in enumerate(self.items):
            current = i == self.selected
            grid.add_row(
                Text(POINTER if current else " ", style="accent"),
                Text(label, style="accent" if current else ""),
                Text(hint or "", style="muted"),
            )
        return grid


def _yield_lines(lines: Sequence[Sequence[Segment]]) -> RenderResult:
    # Every line ends with a new line, as with Rich's own renderables: in a Group the
    # next part starts on a line of its own.
    for line in lines:
        yield from line
        yield Segment.line()


class Stack:
    """Parts one under another; the flexible part gets the lines the others leave.

    The other parts keep their whole height (wrapped to the width): what must be
    seen, a button, a command, a summary, stays on the screen, and the
    flexible part (a list, a long text) scrolls in the rest. When even the fixed
    parts do not fit, the parts above the flexible one give way first: the
    bottom ones (the consent button) stay.
    """

    def __init__(self, *parts: RenderableType, flex: int = -1) -> None:
        self.parts = list(parts)
        self.flex = flex % len(self.parts) if self.parts else 0

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        height = options.height
        if height is None or not self.parts:
            yield Group(*self.parts)
            return
        natural = options.update(height=None)
        top = [line for part in self.parts[: self.flex]
               for line in console.render_lines(part, natural, pad=False)]  # fmt: skip
        bottom = [line for part in self.parts[self.flex + 1 :]
                  for line in console.render_lines(part, natural, pad=False)]  # fmt: skip
        rest = height - len(top) - len(bottom)
        if rest < 0:
            top = top[: max(0, len(top) + rest)]
            rest = 0
        middle: list[list[Segment]] = []
        if rest:
            flexible = options.update(height=rest)
            middle = console.render_lines(self.parts[self.flex], flexible, pad=False)[:rest]
        yield from _yield_lines([*top, *middle, *bottom][:height])


class Clamp:
    """At most `lines` lines of a renderable, the last one cut with «…»; `pad` keeps
    the height constant, so the parts around it do not jump as its text changes."""

    def __init__(self, renderable: RenderableType, lines: int, pad: bool = False) -> None:
        self.renderable = renderable
        self.lines = lines
        self.pad = pad

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        rendered = console.render_lines(self.renderable, options.update(height=None), pad=False)
        if len(rendered) > self.lines:
            rendered = rendered[: self.lines]
            last = list(rendered[-1])
            if Segment.get_line_length(last) > options.max_width - 1:
                last = Segment.adjust_line_length(last, options.max_width - 1)
            while last and not last[-1].text.rstrip():
                last.pop()
            if last:
                last[-1] = Segment(last[-1].text.rstrip(), last[-1].style)
            rendered[-1] = [*last, Segment("…", last[-1].style if last else None)]
        if self.pad:
            rendered += [[] for _ in range(self.lines - len(rendered))]
        yield from _yield_lines(rendered)


def hang(console: Console, line: Text, width: int, indent: int) -> list[Text]:
    """`line` wrapped to `width`; continuation lines start `indent` cells in, under
    the text and not at the edge of the screen."""
    wrapped = list(line.wrap(console, width))
    if len(wrapped) <= 1:
        return wrapped
    rest = line[len(wrapped[0].plain) :]
    rest = rest[len(rest.plain) - len(rest.plain.lstrip(" ")) :]
    tail = [Text(" " * indent).append_text(part)
            for part in rest.wrap(console, max(10, width - indent))]  # fmt: skip
    return [wrapped[0], *tail]


class Hanging:
    """A line whose wrapped continuation keeps an indent, so long items stay readable."""

    def __init__(self, value: Union[str, Text], indent: int = 2, style: str = "") -> None:
        self.text = text(value, style)
        self.indent = indent

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        yield from hang(console, self.text, options.max_width, self.indent)


def _scroll(offset: int, cursor: int, visible: int) -> int:
    if cursor < offset:
        return cursor
    if cursor >= offset + visible:
        return cursor - visible + 1
    return offset


MARK_WIDTH = 5  # "› [✓]"


def fit_widths(natural: Sequence[int], floors: Sequence[int], available: int) -> list[int]:
    """Column widths that fit `available`: every column starts at its floor and they
    grow one cell at a time, in turn, up to their natural width, so no single long
    column eats the others."""
    widths = [min(f, n) for f, n in zip(floors, natural)]
    remaining = available - sum(widths)
    while remaining > 0:
        growing = [i for i, w in enumerate(widths) if w < natural[i]]
        if not growing:
            break
        for i in growing:
            if remaining == 0:
                break
            widths[i] += 1
            remaining -= 1
    return widths


class Checklist:
    """Table with marks (S3, S7): Space marks, `a` marks all, Enter goes on.

    Disabled rows are muted and never get a mark; the cursor skips them unless
    `reach_disabled` (S7: the details under the table explain why a row is off).
    `flexible` names the column that gets the width the others leave (at least
    `min_width`); without it the longest column does.
    """

    def __init__(
        self,
        rows: Sequence[Sequence[Union[str, Text]]],
        columns: Sequence[str],
        selected: Optional[set[int]] = None,
        disabled: Optional[set[int]] = None,
        *,
        flexible: Optional[int] = None,
        min_width: int = 0,
        reach_disabled: bool = False,
    ) -> None:
        self.rows = [list(r) for r in rows]
        self.columns = list(columns)
        self.disabled = set(disabled or ())
        self.selected = set(selected or ()) - self.disabled
        self.flexible = flexible
        self.min_width = min_width
        self.reach_disabled = reach_disabled
        enabled = self.enabled
        self.cursor = enabled[0] if enabled else 0
        self.viewport: Optional[int] = None
        self._offset = 0

    @property
    def enabled(self) -> list[int]:
        return [i for i in range(len(self.rows)) if i not in self.disabled]

    def _move(self, step: int) -> None:
        reachable = list(range(len(self.rows))) if self.reach_disabled else self.enabled
        if not reachable:
            return
        if self.cursor not in reachable:
            self.cursor = reachable[0]
            return
        idx = reachable.index(self.cursor) + step
        self.cursor = reachable[max(0, min(len(reachable) - 1, idx))]

    def handle(self, key: str) -> Optional[str]:
        if key == "up":
            self._move(-1)
        elif key == "down":
            self._move(1)
        elif key == "space":
            if self.cursor in self.enabled:
                self.selected ^= {self.cursor}
        elif hotkey(key) == "a":
            enabled = set(self.enabled)
            self.selected = set() if enabled <= self.selected else enabled
        elif key == "enter":
            return "done"
        return None

    def _named_widths(self, width: int, longest: list[int]) -> list[int]:
        """Widths of the data columns when the caller named the flexible one.

        The table then pads cells on the right only: between two columns go the
        padding and the separator, 2 cells; the mark column is 5 wide.
        """
        available = width - MARK_WIDTH - 2 * len(self.columns)
        floors = [
            self.min_width if i == self.flexible else min(longest[i], max(len(c), 6))
            for i, c in enumerate(self.columns)
        ]
        return fit_widths(longest, floors, available)

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        height = self.viewport or options.height or len(self.rows) + 3
        visible = max(1, height - 3)
        self._offset = _scroll(self._offset, self.cursor, visible)
        # A narrow terminal (S7) needs every cell: with a named flexible column the
        # cells are padded on the right only.
        padding = (0, 1, 0, 0) if self.flexible is not None else (0, 1)
        table = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False, pad_edge=False,
                      padding=padding)  # fmt: skip
        table.add_column("", no_wrap=True, width=MARK_WIDTH)
        longest = [
            max([text(row[i]).cell_len for row in self.rows if i < len(row)] + [len(column)])
            for i, column in enumerate(self.columns)
        ]
        if self.flexible is not None:
            widths = self._named_widths(options.max_width, longest)
            for index, column in enumerate(self.columns):
                flex = index == self.flexible
                table.add_column(column, no_wrap=True, overflow="ellipsis", header_style="muted",
                                 width=widths[index], ratio=1 if flex else None)  # fmt: skip
        else:
            # The widest column takes what is left and is cut with an ellipsis; the
            # others keep their width, so marks and names never shrink to "…".
            flexible = longest.index(max(longest)) if longest else -1
            for index, column in enumerate(self.columns):
                table.add_column(column, no_wrap=True, overflow="ellipsis", header_style="muted",
                                 ratio=1 if index == flexible else None)  # fmt: skip
        for i in range(self._offset, min(len(self.rows), self._offset + visible)):
            off = i in self.disabled
            mark = " - " if off else ("[✓]" if i in self.selected else "[ ]")
            current = i == self.cursor and (self.reach_disabled or not off)
            pointer = POINTER if current else " "
            style = "muted" if off else ("accent" if current else "")
            cells = [text(c) for c in self.rows[i]]
            table.add_row(Text(f"{pointer} {mark}"), *cells, style=style)
        yield table


class TextInput:
    """One-line input; `secret` hides the characters (passwords, tokens)."""

    def __init__(
        self,
        label: str,
        hint: str = "",
        secret: bool = False,
        validate: Optional[Callable[[str], Optional[str]]] = None,
        value: str = "",
    ) -> None:
        self.label = label
        self.hint = hint
        self.secret = secret
        self.validate = validate
        self.value = value
        self.pos = len(value)
        self.error: Optional[str] = None
        self.focused = True

    def clear(self) -> None:
        self.value = ""
        self.pos = 0

    def handle(self, key: str) -> Optional[str]:
        """Return the value on Enter when it is valid; None otherwise."""
        if key == "enter":
            self.error = self.validate(self.value) if self.validate else None
            return None if self.error else self.value
        if key == "backspace":
            if self.pos > 0:
                self.value = self.value[: self.pos - 1] + self.value[self.pos :]
                self.pos -= 1
        elif key == "delete":
            self.value = self.value[: self.pos] + self.value[self.pos + 1 :]
        elif key == "left":
            self.pos = max(0, self.pos - 1)
        elif key == "right":
            self.pos = min(len(self.value), self.pos + 1)
        elif key == "home":
            self.pos = 0
        elif key == "end":
            self.pos = len(self.value)
        else:
            char = " " if key == "space" else key
            if len(char) != 1 or not char.isprintable():
                return None
            self.value = self.value[: self.pos] + char + self.value[self.pos :]
            self.pos += 1
        self.error = None
        return None

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        yield self.render(color=not (console.no_color or console.color_system is None))

    def render(self, color: bool = True) -> RenderableType:
        shown = "•" * len(self.value) if self.secret else self.value
        if self.focused and color:
            line = Text(POINTER + " ", style="accent")
            line.append(shown[: self.pos])
            line.append(shown[self.pos] if self.pos < len(shown) else " ", style="reverse")
            line.append(shown[self.pos + 1 :])
        elif self.focused:
            line = Text(POINTER + " " + shown[: self.pos] + CURSOR_BAR + shown[self.pos :])
        else:
            line = Text("  " + shown)
        label_style = "bold" if self.focused else "muted"
        parts: list[RenderableType] = [Text(self.label, style=label_style), line]
        hint = self.hint
        if self.secret:
            hint = (hint + " " if hint else "") + t("input.hidden")
        if hint:
            parts.append(Text(hint, style="muted"))
        if self.error:
            parts.append(
                Text(f"{SYMBOL_FAIL} " + t("input.invalid", reason=self.error), style="risk.high")
            )
        return Group(*parts)


class Consent:
    """Consent screen of S7, of rollback and of finalization: only Enter agrees.

    The summary scrolls (↑ ↓, PgUp, PgDn, Home, End); the button and the hint
    stay pinned under it, so every warning can be read and the way to agree or
    to go back is always on the screen. Any other key goes back.
    """

    def __init__(
        self, summary: RenderableType, accept_label: str, keys: Optional[str] = None
    ) -> None:
        self.summary = summary
        self.accept_label = accept_label
        self.keys = t("consent.keys") if keys is None else keys
        self.pager = Pager(summary)

    def handle(self, key: str) -> Optional[bool]:
        """True: accepted; False: back; None: the summary scrolled."""
        if key == "enter":
            return True
        if key in SCROLL_KEYS:
            self.pager.handle(key)
            return None
        return False

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        button = Panel(
            Text(f"{SYMBOL_OK} {self.accept_label}", style="ok"),
            box=box.HEAVY,
            border_style="ok",
            expand=False,
        )
        # Called, not yielded: Rich renders a yielded renderable without the height,
        # and the button is pinned to the bottom of exactly this height.
        stack = Stack(self.pager, Text(""), button, Text(self.keys, style="muted"), flex=0)
        yield from stack.__rich_console__(console, options)


STEP_VIEW = {
    "pending": ("·", "muted"),
    "running": (SYMBOL_RUNNING, "accent"),
    "ok": (SYMBOL_OK, "ok"),
    "failed": (SYMBOL_FAIL, "risk.high"),
    "rolled_back": (SYMBOL_ROLLED_BACK, "risk.medium"),
    "skipped": ("–", "muted"),
}


class ProgressBoard:
    """Apply board of S8: nodes by rows, steps of the current fix by columns.

    Why a change did not apply is a sentence, too long for a column: it goes
    under the table, one line per node, wrapped to the width of the screen.
    """

    def __init__(self, nodes: Sequence[str], steps: Sequence[str]) -> None:
        self.nodes = list(nodes)
        self.steps = list(steps)
        self.cells: dict[tuple[str, str], str] = {}
        self.current: dict[str, str] = {n: "" for n in self.nodes}
        self.result: dict[str, Text] = {n: Text("") for n in self.nodes}
        self.node_title = ""
        self.fix_title = ""
        self.legend = ""

    def start(self, node: str, fix_label: str) -> None:
        self.current[node] = fix_label
        for step in self.steps:
            self.cells[(node, step)] = "pending"

    def set(self, node: str, step: str, state: str) -> None:
        self.cells[(node, step)] = state

    def finish(self, node: str, result: Text) -> None:
        self.result[node] = result

    def __rich__(self) -> RenderableType:
        table = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False, pad_edge=False)
        table.add_column(self.node_title, no_wrap=True, overflow="ellipsis", header_style="muted",
                         max_width=16)  # fmt: skip
        table.add_column(self.fix_title, no_wrap=True, overflow="ellipsis", header_style="muted",
                         ratio=1)  # fmt: skip
        for step in self.steps:
            table.add_column(step, no_wrap=True, overflow="ellipsis", justify="center",
                             header_style="muted")  # fmt: skip
        for node in self.nodes:
            cells = []
            for step in self.steps:
                symbol, style = STEP_VIEW[self.cells.get((node, step), "pending")]
                cells.append(Text(symbol, style=style))
            table.add_row(Text(node), Text(self.current.get(node, "")), *cells)
        parts: list[RenderableType] = [table]
        for node in self.nodes:
            if self.result[node].plain:
                line = Text(f"{node}: ", style="bold")
                line.append_text(self.result[node])
                parts.append(line)
        if self.legend:
            parts.append(Text(self.legend, style="muted"))
        return Group(*parts)


class ScoreBadge:
    """Large score with the colour of §12.2 and a word, so it reads without colour.

    `compact`: one line for low terminals, where the large digits would leave
    no room for what was found.
    """

    def __init__(self, score: int, before: Optional[int] = None, compact: bool = False) -> None:
        self.score = max(0, min(100, score))
        self.before = before
        self.compact = compact

    def line(self) -> Text:
        style = score_style(self.score)
        line = Text(t("report.score", score=self.score), style="bold")
        if self.before is not None:
            line.append(", " + t("score.was", before=self.before), style="bold")
        line.append(" · ")
        filled = self.score // 10
        line.append("█" * filled, style=style)
        line.append("░" * (10 - filled), style="muted")
        line.append(" · ")
        line.append(self.level(), style=style)
        return line

    def level(self) -> str:
        if self.score >= 85:
            return t("score.green")
        if self.score >= 60:
            return t("score.yellow")
        return t("score.red")

    def __rich__(self) -> RenderableType:
        if self.compact:
            return self.line()
        style = score_style(self.score)
        digits = Text("\n".join(big_number(self.score)), style=style)
        filled = self.score // 5
        bar = Text("█" * filled, style=style)
        bar.append("░" * (20 - filled), style="muted")
        lines: list[RenderableType] = [
            digits,
            Text(t("report.score", score=self.score), style="bold"),
            bar,
            Text(self.level(), style=style),
        ]
        if self.before is not None:
            lines.append(Text(t("score.before_after", before=self.before, score=self.score)))
        return Panel(Group(*lines), box=box.ROUNDED, border_style=style, expand=False)


def cell_lines(console: Console, cells: Sequence[tuple[Text, int]]) -> list[Text]:
    """Cells side by side, each wrapped to its width; one space between them."""
    wrapped = [list(cell.wrap(console, width, overflow="fold")) or [Text("")]
               for cell, width in cells]  # fmt: skip
    lines = []
    for row in range(max(len(w) for w in wrapped)):
        line = Text()
        for column, (_cell, width) in enumerate(cells):
            part = wrapped[column][row].copy() if row < len(wrapped[column]) else Text("")
            part.truncate(width, pad=True)
            if column:
                line.append(" ")
            line.append_text(part)
        line.rstrip()
        lines.append(line)
    return lines


@dataclass
class Column:
    """A column of a block: the natural width of its cells up to `most`, or with
    `flex` a share of what the other columns leave (never below `least`)."""

    most: int = 40
    least: int = 4
    flex: int = 0


@dataclass
class BlockRow:
    """One row of a block: cells side by side; `details` show under it when open."""

    cells: list
    details: list = field(default_factory=list)
    key: object = None  # identity of the row in BlockList.expanded
    muted: bool = False
    main: int = 1  # the cell that lights up on the cursor row


@dataclass
class Block:
    """A framed block (K23). The title carries a symbol and a word, so a block reads
    without colour; `note` stands at the right of the bottom border."""

    title: str
    rows: list
    columns: list
    style: str = "muted"
    note: str = ""


class BlockList:
    """Blocks one under another (S6, the plan, S9; K23): ↑ ↓ move by row across the
    blocks, PgUp PgDn by a screenful, Home End to the first and the last row; Space
    opens the details of a row that has them.

    Every line is drawn here, borders too, so the list scrolls by lines and the row
    under the cursor always shows with the title of its block when it is the first.
    """

    def __init__(self, blocks: Sequence[Block] = ()) -> None:
        self.blocks = list(blocks)
        self.cursor = 0
        self.expanded: set = set()
        self.viewport: Optional[int] = None
        self._offset = 0
        self._page = 1

    @property
    def rows(self) -> list[BlockRow]:
        return [row for block in self.blocks for row in block.rows]

    def current(self) -> Optional[BlockRow]:
        rows = self.rows
        if not rows:
            return None
        self.cursor = max(0, min(self.cursor, len(rows) - 1))
        return rows[self.cursor]

    @staticmethod
    def key_of(index: int, row: BlockRow) -> object:
        return row.key if row.key is not None else index

    def handle(self, key: str) -> Optional[str]:
        rows = self.rows
        if not rows:
            return None
        last = len(rows) - 1
        moves = {"up": -1, "down": 1, "pgup": -self._page, "pgdn": self._page}
        if key in moves:
            self.cursor = max(0, min(last, self.cursor + moves[key]))
        elif key == "home":
            self.cursor = 0
        elif key == "end":
            self.cursor = last
        elif key == "space":
            row = self.current()
            if row is not None and row.details:
                self.expanded ^= {self.key_of(self.cursor, row)}
        return None

    @staticmethod
    def _widths(block: Block, room: int) -> list[int]:
        """Widths of the cells of a block; `room` is the width the cells share."""
        columns = block.columns
        widths = []
        for i, column in enumerate(columns):
            longest = max([text(r.cells[i]).cell_len for r in block.rows if i < len(r.cells)]
                          + [0])  # fmt: skip
            widths.append(0 if column.flex else min(column.most, longest))
        flexible = [i for i, c in enumerate(columns) if c.flex]
        need = sum(columns[i].least for i in flexible) - (room - sum(widths))
        while need > 0:  # the widest fixed columns give way first
            shrinking = [i for i, c in enumerate(columns) if not c.flex and widths[i] > c.least]
            if not shrinking:
                break
            widest = max(shrinking, key=lambda i: widths[i])
            widths[widest] -= 1
            need -= 1
        rest = room - sum(widths)
        weight = sum(columns[i].flex for i in flexible) or 1
        given = 0
        for n, i in enumerate(flexible):
            share = rest - given if n == len(flexible) - 1 else rest * columns[i].flex // weight
            widths[i] = max(columns[i].least, share)
            given += widths[i]
        return widths

    @staticmethod
    def _top(block: Block, width: int) -> Text:
        title = bold(block.title, "" if block.style == "muted" else block.style)
        title.truncate(max(1, width - 5), overflow="ellipsis")
        line = Text("╭─ ", style=block.style)
        line.append_text(title)
        line.append(" " + "─" * max(0, width - 5 - title.cell_len) + "╮", style=block.style)
        return line

    @staticmethod
    def _bottom(block: Block, width: int) -> Text:
        if not block.note:
            return Text("╰" + "─" * max(0, width - 2) + "╯", style=block.style)
        note = Text(block.note, style="muted")
        note.truncate(max(1, width - 6), overflow="ellipsis")
        line = Text("╰" + "─" * max(0, width - 5 - note.cell_len) + " ", style=block.style)
        line.append_text(note)
        line.append(" ─╯", style=block.style)
        return line

    @staticmethod
    def _side(content: Text, width: int, style: str) -> Text:
        """A line inside the frame: only the borders take the block's colour, the base
        style of the line would colour every cell of the row."""
        inner = content.copy()
        inner.truncate(max(1, width - 4), pad=True)
        line = Text()
        line.append("│ ", style=style)
        line.append_text(inner)
        line.append(" │", style=style)
        return line

    def _cells(self, index: int, row: BlockRow, widths: list[int]) -> list[tuple[Text, int]]:
        current = index == self.cursor
        cells = [(Text(POINTER if current else " ", style="accent"), 1)]
        for i, (cell, width) in enumerate(zip(row.cells, widths)):
            value = text(cell).copy()
            if row.muted:
                value = Text(value.plain, style="muted")
            elif current and i == row.main:
                value.stylize("accent")
            cells.append((value, width))
        return cells

    def lines(self, console: Console, width: int) -> tuple[list[Text], list[tuple[int, int]]]:
        """All lines of the blocks, and the lines of each row (with the title of its
        block for the first row, with the bottom border for the last)."""
        lines: list[Text] = []
        spans: list[tuple[int, int]] = []
        inner = max(10, width - 4)
        index = 0
        for block in self.blocks:
            if not block.rows:
                continue
            lines.append(self._top(block, width))
            # The pointer and the space after it, then one space between the cells.
            widths = self._widths(block, inner - 1 - len(block.columns))
            for n, row in enumerate(block.rows):
                start = len(lines) - (1 if n == 0 else 0)
                body = cell_lines(console, self._cells(index, row, widths))
                if row.details and self.key_of(index, row) in self.expanded:
                    indent = 2 + sum(widths[: max(0, row.main)]) + max(0, row.main)
                    for detail in row.details:
                        line = Text(" " * indent).append_text(text(detail))
                        body.extend(hang(console, line, inner, indent))
                lines.extend(self._side(line, width, block.style) for line in body)
                spans.append((start, len(lines)))
                index += 1
            lines.append(self._bottom(block, width))
            spans[-1] = (spans[-1][0], len(lines))
        return lines, spans

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        height = self.viewport or options.height or 10**6
        lines, spans = self.lines(console, options.max_width)
        if spans:
            self.cursor = max(0, min(self.cursor, len(spans) - 1))
            start, end = spans[self.cursor]
            if start < self._offset:
                self._offset = start
            elif end > self._offset + height:
                self._offset = min(start, end - height)
            self._offset = max(0, min(self._offset, max(0, len(lines) - height)))
            bottom = self._offset + height
            shown = [s for s, e in spans if s >= self._offset and e <= bottom]
            self._page = max(1, len(shown) - 1)
        yield from lines[self._offset : self._offset + height]


# An info plate stays neutral: red is the brand and the selection, not a warning.
NOTICE_STYLE = {"info": "muted", "warning": "risk.medium", "error": "risk.high"}


class Notice:
    """Plate with a word in the title (info, warning, error): not colour alone."""

    def __init__(self, kind: str, text_value: str) -> None:
        self.kind = kind
        self.text = text_value

    def __rich__(self) -> RenderableType:
        style = NOTICE_STYLE.get(self.kind, "muted")
        title_style = {"error": "danger.bg", "info": "bold"}.get(self.kind, style)
        return Panel(
            Text(self.text),
            title=Text(f" {t('notice.' + self.kind)} ", style=title_style),
            title_align="left",
            border_style=style,
            box=box.ROUNDED,
        )


class Pager:
    """Scrolling of a long text or of any renderable (full report on `s`, the
    consent summary, the list of changes on S9). The position line shows only
    when there is more than fits."""

    def __init__(self, content: Union[str, RenderableType]) -> None:
        self.text = content
        self.offset = 0
        self.viewport: Optional[int] = None
        self._page = 1
        self._total = 0

    def handle(self, key: str) -> Optional[str]:
        step = {"up": -1, "down": 1, "pgup": -self._page, "pgdn": self._page, "space": self._page}
        if key in step:
            self.offset += step[key]
        elif key == "home":
            self.offset = 0
        elif key == "end":
            self.offset = self._total
        self.offset = max(0, min(self.offset, max(0, self._total - self._page)))
        return None

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        height = self.viewport or options.height or 20
        content = Text(self.text) if isinstance(self.text, str) else self.text
        lines = console.render_lines(content, options.update(height=None), pad=False)
        self._total = len(lines)
        overflow = self._total > height
        self._page = max(1, height - 1) if overflow else height
        self.offset = max(0, min(self.offset, max(0, self._total - self._page)))
        shown = lines[self.offset : self.offset + self._page]
        if overflow:
            end = min(self._total, self.offset + self._page)
            position = Text(t("pager.position", start=self.offset + 1, end=end, total=self._total),
                            style="muted", no_wrap=True, overflow="ellipsis")  # fmt: skip
            shown = [*shown, *console.render_lines(position, options.update(height=None),
                                                   pad=False)[:1]]  # fmt: skip
        yield from _yield_lines(shown)
