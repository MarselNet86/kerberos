import io

import pytest
from rich.text import Text

from kerberos.copy import t
from kerberos.ui.terminal import FakeTerminal, frame_text, make_console
from kerberos.ui.widgets import (
    Block,
    BlockList,
    BlockRow,
    Checklist,
    Column,
    Consent,
    Menu,
    Notice,
    Pager,
    ProgressBoard,
    ScoreBadge,
    Screen,
    TextInput,
)


def render(renderable, width=100, height=30) -> str:
    term = FakeTerminal(width=width, height=height)
    term.draw(renderable)
    return term.last


def test_menu_wraps_and_selects():
    menu = Menu([("a", "A", ""), ("b", "B", "hint")])
    assert menu.handle("up") is None and menu.selected == 1
    assert menu.handle("enter") == "b"
    assert menu.handle("1") == "a"
    assert "hint" in render(menu)


def test_checklist_skips_disabled_and_selects_all_enabled():
    rows = [["nl-1"], ["us-1"], ["de-1"]]
    cl = Checklist(rows, ["Нода"], disabled={1})
    cl.handle("down")
    assert cl.cursor == 2
    cl.handle("space")
    assert cl.selected == {2}
    cl.handle("a")
    assert cl.selected == {0, 2}
    cl.handle("a")
    assert cl.selected == set()
    cl.handle("ф")  # Russian layout
    assert cl.selected == {0, 2}
    assert cl.handle("enter") == "done"
    frame = render(cl)
    assert " - " in frame and "[✓]" in frame


def test_checklist_scrolls_to_cursor():
    rows = [[f"node-{i}"] for i in range(40)]
    cl = Checklist(rows, ["Нода"])
    cl.viewport = 8
    for _ in range(30):
        cl.handle("down")
    frame = render(cl)
    assert "node-30" in frame and "node-0 " not in frame


def test_text_input_editing_and_validation():
    field = TextInput("Домен", validate=lambda v: None if "." in v else "нужна точка")
    for key in "examplecom":
        field.handle(key)
    for _ in range(3):
        field.handle("left")
    field.handle(".")
    assert field.value == "example.com"
    field.handle("end")
    field.handle("backspace")
    assert field.handle("enter") == "example.co"
    field.value, field.pos = "nodot", 5
    assert field.handle("enter") is None
    assert "нужна точка" in render(field)
    field.handle("space")
    assert field.value == "nodot "


def test_secret_input_never_shows_characters():
    field = TextInput(t("panel.password"), secret=True)
    for key in "s3cr3t":
        field.handle(key)
    frame = render(field)
    assert "s3cr3t" not in frame and "••••••" in frame
    assert t("input.hidden") in frame


def test_consent_accepts_only_enter():
    consent = Consent(Text("plan"), t("consent.accept"))
    assert consent.handle("enter") is True
    assert consent.handle("y") is False and consent.handle("space") is False
    assert consent.handle("down") is None, "the arrows scroll, they never go back"
    assert t("consent.accept") in render(consent)


def test_progress_board_symbols():
    board = ProgressBoard(["nl-1"], ["бэкап", "применение"])
    board.start("nl-1", "mptcp.guard")
    board.set("nl-1", "бэкап", "ok")
    board.set("nl-1", "применение", "failed")
    frame = render(board)
    assert "✓" in frame and "✗" in frame


@pytest.mark.parametrize("width", [80, 100])
def test_progress_board_keeps_the_whole_reason(width):
    steps = [t(f"step.{s}") for s in ("backup", "apply", "check", "confirm")]
    board = ProgressBoard(["fi-1", "хост FI CDN"], steps)
    board.start("fi-1", t("fix.xhttp.padding.label"))
    reason = t("apply.rolled_back", reason=t("error.port_closed"))
    board.finish("fi-1", Text(reason))
    frame = render(board, width=width)
    assert max(len(line) for line in frame.splitlines()) <= width
    assert " ".join(frame.split()).count(reason) == 1, "the reason is never cut"
    assert "fi-1: " in frame


def test_score_badge_words_and_colours():
    assert t("score.red") in render(ScoreBadge(42))
    assert t("score.yellow") in render(ScoreBadge(60))
    assert t("score.green") in render(ScoreBadge(85, before=40))
    assert t("score.before_after", before=40, score=85) in render(ScoreBadge(85, before=40))


COLUMNS = [Column(most=10), Column(flex=1)]


def test_block_list_frames_its_blocks_and_opens_details():
    rows = [
        BlockRow(
            [Text("● высокий"), Text("Вход по паролю")],
            [Text("sshd -T: passwordauthentication yes")],
        ),  # fmt: skip
        BlockRow([Text("● средний"), Text("Порт 22")]),
    ]
    listing = BlockList([Block("✓ Блок 1", rows[:1], COLUMNS, note="1"),
                         Block("✎ Блок 2", rows[1:], COLUMNS)])  # fmt: skip
    frame = render(listing)
    assert "✓ Блок 1" in frame and "✎ Блок 2" in frame and "sshd -T" not in frame
    assert frame.splitlines()[0].startswith("╭─ ✓ Блок 1") and "─ 1 ─╯" in frame
    listing.handle("space")
    assert "sshd -T" in render(listing)
    listing.handle("down")
    assert listing.cursor == 1 and listing.current() is rows[1]
    listing.handle("space")  # no details: nothing opens
    assert listing.expanded == {0}


def test_notice_has_a_word_title():
    assert t("notice.error") in render(Notice("error", "boom"))


def test_pager_scrolls():
    pager = Pager("\n".join(f"line {i}" for i in range(100)))
    pager.viewport = 10
    render(pager)
    pager.handle("pgdn")
    frame = render(pager)
    assert "line 9" in frame and "line 0\n" not in frame
    pager.handle("end")
    assert "line 99" in render(pager)


def test_screen_keeps_footer_when_body_overflows():
    body = Text("\n".join(f"row {i}" for i in range(100)))
    frame = render(Screen("Заголовок", body, [("q", t("keys.quit"))]), height=20)
    lines = frame.splitlines()
    assert len(lines) == 20
    assert t("keys.quit") in lines[-1]


def test_color_frames_use_palette_and_no_color_strips_it():
    styled = frame_text(Text("x", style="risk.high"), 20, 2, color=True)
    assert "\x1b[" in styled
    plain = frame_text(Text("x", style="risk.high"), 20, 2, color=False)
    assert "\x1b[" not in plain


def test_markup_is_never_interpreted():
    console = make_console(io.StringIO(), 40, 5, color=False, record=True)
    console.print("[bold]not markup[/bold]")
    assert "[bold]" in console.export_text()
