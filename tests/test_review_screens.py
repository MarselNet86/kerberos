"""Screens S6-S9, their widgets and the report after the K13 review (tech.md §6, §12, §14).

Every test comes from a failure the review saw on a screen of 80×24 or 100×30
(or in report.md): it reproduces the scenario and checks what the person sees.
"""

import re
import tempfile
from pathlib import Path

import pytest
from helpers import flat, login_keys, make_app, on, on_group, plan_index, seen, typed
from hypothesis import given
from hypothesis import strategies as st
from rich.console import Group
from rich.text import Text

from kerberos.copy import t
from kerberos.demo.fleet import build_nodes
from kerberos.fixes.journal import RunStore
from kerberos.flow import EXIT_INTERRUPTED, EXIT_OK
from kerberos.report import markdown
from kerberos.state import State
from kerberos.ui.terminal import FakeTerminal, frame_text
from kerberos.ui.widgets import (
    Block,
    BlockList,
    BlockRow,
    Checklist,
    Clamp,
    Column,
    Consent,
    Pager,
    ScoreBadge,
    Screen,
    Stack,
    TextInput,
    fit_widths,
)

# S2 login, S3, S4: five host keys (de-1 also installs python3), kz-1 skipped.
TO_S4_END = login_keys() + ["enter", "enter"] + ["enter"] * 5 + ["esc"]
# «Проверка» opens S4 with what it installs (one more Enter), then the same keys.
CHECK_S4_END = login_keys() + ["enter", "enter", "enter"] + ["enter"] * 5 + ["esc"]
TO_S6_CHECK = CHECK_S4_END + ["enter", "enter"]  # S4 summary, whois yes
# «Исправление»: the admin key («Мои ключи» and its list), S4 summary, whois, S6 → S7.
TO_PLAN = TO_S4_END + ["enter", "enter"] + ["enter", "enter", "enter"]
LAUNCHER = "/opt/kerberos/kerberos"
XUI_TO_PLAN = ["down", "enter"] + typed("admin") + ["enter"] + typed("pw") + ["enter"]
XUI_TO_PLAN += ["enter", "enter", "enter"]  # S2 summary, S4 summary, S6 → S7
XUI_STEAL = ["end"]  # the own domain of the server: the last row of S7 (K23)


def short_state() -> State:
    """State under /tmp: the report path fits one line of S6 and S9 on every machine."""
    return State(Path(tempfile.mkdtemp(prefix="kerberos-test-", dir="/tmp")))


@pytest.fixture(autouse=True)
def installed_launcher(monkeypatch):
    # The commands on S9 carry the path of an installed KERBEROS, not of this checkout.
    monkeypatch.setattr("kerberos.screens.fix.launcher", lambda: LAUNCHER)


def titled(term, key):
    head = "/// kerberos  " + t(key)
    return [f for f in term.frames if f.splitlines()[0].startswith(head)]


def body_lines(frame):
    """The lines between the rule under the header and the rule above the footer."""
    lines = frame.splitlines()
    rules = [i for i, line in enumerate(lines) if line and set(line) == {"─"}]
    return lines[rules[0] + 1 : rules[-1]]


def run_fix(keys, *, width=80, height=24, nodes=None, state=None, panel_kind="remnawave"):
    start = TO_PLAN if panel_kind == "remnawave" else XUI_TO_PLAN
    app, term = make_app(start + list(keys), width=width, height=height, nodes=nodes,
                         state=state or short_state(), panel_kind=panel_kind)  # fmt: skip
    code = app.run("fix")
    return app, term, code


def last_run(app):
    return RunStore(app.env.state, app.env.clock).runs()[0]


# -- UX 1: the consent screen scrolls, its button and keys stay on the screen ----------------
def test_consent_at_80x24_shows_the_button_and_scrolls_to_every_warning():
    app, term, _code = run_fix(["enter", "down", "pgdn", "end", "esc", "esc", "q", "enter"])
    consent = titled(term, "consent.title")
    assert len(consent) == 4, "↓, PgDn and End scroll: they never go back to the plan"
    for frame in consent:
        assert t("consent.accept") in frame and t("consent.keys") in flat(frame)
    assert t("fix.key_only.warning") in flat(consent[-1]) or seen(term, t("fix.key_only.warning"))
    assert t("fix.padding.warning") in flat(consent[-1]), "End reaches the last warning"
    assert app.env.panel_transport.mutations == [], "nothing changes before Enter"
    assert titled(term, "plan.title")[-1] is term.frames[-3], "Esc goes back to the plan"


def test_rollback_consent_at_80x24_keeps_its_button_and_own_keys():
    app, term, code = run_fix(["enter", "enter", "enter"], height=40)
    assert code == EXIT_OK
    term.height = 24
    term.feed("enter", "enter", "end", "esc", "esc", "esc")  # run, changes, consent, back
    assert app.run("rollback") == EXIT_OK
    rollback = [f for f in titled(term, "rb.title") if t("rb.accept") in f]
    assert rollback and all(t("rb.keys") in flat(f) for f in rollback)
    assert t("consent.keys") not in flat(rollback[0]), "no «вернуться к плану» without a plan"


# -- UX 2, 9, 13, 22: S9 pins what matters above a list that scrolls --------------------------
def test_s9_at_80x24_pins_the_new_ssh_port_summary_and_rollback_command():
    keys = on("nl-1", "ssh.port", "space") + ["enter", "enter", "pgdn", "enter"]
    app, term, code = run_fix(keys)
    assert code == EXIT_OK
    run = last_run(app)
    port = next(c for c in run["changes"] if c["fixId"] == "ssh.port")["details"]["newPort"]
    s9 = titled(term, "done.title")
    first = s9[0]
    line = t("s9.save.ssh", node="nl-1", command=f"ssh -p {port} root@203.0.113.10")
    assert t("s9.block.save") in first and line in first
    assert "kerberos ssh" not in first, "no administrator key on this server: no kerberos ssh"
    assert t("s9.applied", ok=len(run["changes"]), total=len(run["changes"])) in first
    lines = [line.strip() for line in body_lines(first)]
    rollback = f"sudo {LAUNCHER} rollback {run['runId']}"
    assert lines[lines.index(t("done.rollback")) + 1] == rollback, "the command on its own line"
    assert s9[1] != first and line in s9[1], "PgDn scrolls the blocks, the new port stays"


def test_finalize_consent_at_80x24_has_its_own_keys():
    keys = on("nl-1", "self_steal", "d", *"nl-1.example.com")
    app, term, code = run_fix(keys + ["enter", "enter", "enter", "enter"], height=30)
    assert code == EXIT_OK
    app.env.clock.advance(24 * 3600 + 1)
    term.height = 24
    term.feed("down", "esc")  # the panel takes the token the fix run saved
    assert app.run("finalize") == EXIT_OK
    consent = [f for f in titled(term, "fin.title") if t("fin.accept") in f]
    assert len(consent) == 2 and all(t("fin.keys") in flat(f) for f in consent)
    assert last_run(app)["pending"], "Esc leaves the old names in place"


def test_kerberos_ssh_is_offered_only_with_the_administrator_key():
    # «Создать ключ на сервере панели»: the key exists, so `kerberos ssh` works.
    keys = TO_S4_END + ["down", "enter", "enter", "enter", "enter"]
    keys += on("nl-1", "ssh.port", "space") + ["enter", "enter", "enter"]
    app, term = make_app(keys, height=30, state=short_state())
    assert app.run("fix") == EXIT_OK
    assert app.env.state.admin_key.exists()
    port = next(c for c in last_run(app)["changes"] if c["fixId"] == "ssh.port")
    command = f"ssh -p {port['details']['newPort']} root@203.0.113.10"
    assert seen(term, t("s9.save.ssh", node="nl-1", command=command))
    assert seen(term, t("s9.save.kerberos_ssh"))


def test_s9_counts_what_did_not_apply():
    nodes = {n.name: n for n in build_nodes()}
    nodes["nl-2"].state["fail"] = {"mptcp.guard": "mptcp_absent"}
    app, term, _code = run_fix(["enter", "enter", "enter"], nodes=list(nodes.values()))
    run = last_run(app)
    ok = sum(1 for c in run["changes"] if c["state"] in ("applied", "confirmed"))
    first = titled(term, "done.title")[0]
    assert t("s9.applied", ok=ok, total=len(run["changes"])) in first
    assert t("s9.failed", n=1) in first


def test_finalize_is_automatic_on_s9_only_with_a_timer():
    # The demo panel server has no systemd-run: the timer is not set (§10.4 step 6).
    keys = on("nl-1", "self_steal", "d", *"nl-1.example.com")
    app, term, code = run_fix(keys + ["enter", "f", "enter", "enter", "enter"], height=30)
    assert code == EXIT_OK
    run = last_run(app)
    assert run["pending"] and run.get("finalizeTimer") is None
    assert not seen(term, t("s9.finalize.auto"))
    first = titled(term, "done.title")[0]
    lines = [line.strip() for line in body_lines(first)]
    command = f"sudo {LAUNCHER} finalize {run['runId']}"
    assert lines[lines.index(t("s9.finalize")) + 1] == command


def test_a_change_that_did_not_roll_back_is_never_shown_as_rolled_back():
    from kerberos.screens.fix import step_done

    app, term, _code = run_fix(["enter", "enter", "enter"])
    session = app.session
    run = session.data["run"]
    change = next(c for c in run["changes"] if c["fixId"] == "mptcp.guard")
    change.update(error="rollback_failed", state="applied")
    change["details"]["failure"] = "recheck_failed"
    term.feed("enter")
    step_done(app, session)
    reason = t("apply.rollback_failed", reason=t("error.recheck_failed"))
    frame = flat(term.last)
    assert reason in frame and f"✗ nl-1: {t('fix.mptcp.guard.label')}" in frame
    assert t("s9.rollback_failed", n=1) in frame
    text = markdown.render(run)
    assert t("report.rollback_failed") in text and reason in text


# -- UX 4, 6, 18, 19: the plan at 80 columns ----------------------------------------------
def test_plan_at_80_columns_keeps_the_fix_names_and_explains_the_current_row():
    # K23: the group «Новый порт SSH» opened, the cursor on its first row, nl-1's.
    keys = on_group("ssh_port", "right", "down") + ["esc", "q", "enter"]
    app, term, _code = run_fix(keys)
    plan = titled(term, "plan.title")[-1]
    port = app.session.data["plan"][plan_index("nl-1", "ssh.port")].params["port"]
    row = next(line for line in plan.splitlines() if "›" in line)
    assert t("fix.ssh.port.label", port=port) in row, "the name of the measure keeps its width"
    assert t("fix.ssh_port.warning", port=port)[:40] in flat(plan), "the warning under the blocks"
    assert "Esc " + t("keys.back") in plan.splitlines()[-1]


def test_a_blocked_row_can_be_reached_and_tells_why():
    # «Пропустить» the administrator key: «Вход только по ключу» cannot run (§8.5).
    keys = TO_S4_END + ["down", "down", "enter", "enter", "enter", "enter"]
    keys += on_group("access", "right") + ["down"] * 8 + ["esc", "q", "enter"]
    app, term = make_app(keys, state=short_state())
    app.run("fix")
    items = app.session.data["plan"]
    assert any(item.blocked == "no_admin_key" for item in items)
    frames = titled(term, "plan.title")
    reason = t("plan.details.blocked", reason=t("plan.blocked.no_admin_key"))
    assert any(reason in flat(f) for f in frames)


def test_a_marks_everything_but_the_ssh_port_and_takes_it_back():
    app, term, _code = run_fix(["a", "a", "esc", "q", "enter"], width=100, height=30)
    items = app.session.data["plan"]
    notes = [re.search(r"отмечено (\d+) из (\d+)", f) for f in titled(term, "plan.title")]
    marked, cleared = int(notes[1].group(1)), int(notes[2].group(1))
    assert cleared == 0, "the second press takes back what the first marked"
    in_groups = [i for i in items if i.fix_id != "self_steal" and not i.blocked]
    ports = [i for i in in_groups if i.fix_id == "ssh.port"]
    waiting = [i for i in in_groups if i.fix_id == "cdn.edge_only"]
    assert marked == len(in_groups) - len(ports) - len(waiting)
    assert not any(i.selected for i in items if i.fix_id == "self_steal"), "they wait for a domain"
    assert t("keys.all_but_port") in titled(term, "plan.title")[0].splitlines()[-1]


def test_several_new_ssh_ports_get_one_warning():
    keys = on("nl-1", "ssh.port", "space") + on("nl-2", "ssh.port", "space")
    app, term, _code = run_fix(keys + ["enter", "esc", "esc", "q", "enter"], height=46)
    items = app.session.data["plan"]
    ports = {app.session_name(i.node_uuid): i.params["port"] for i in items
             if i.fix_id == "ssh.port" and i.selected}  # fmt: skip
    listed = ", ".join(f"{name}: {port}" for name, port in ports.items())
    consent = flat(titled(term, "consent.title")[0])
    assert t("fix.ssh_port.warning.many", ports=listed) in consent
    for port in ports.values():
        assert t("fix.ssh_port.warning", port=port) not in consent


def test_plan_footer_follows_the_row_and_help_lists_its_keys():
    keys = on("nl-1", "self_steal") + ["?", "x", "esc", "q", "enter"]
    app, term, _code = run_fix(keys)
    plan = titled(term, "plan.title")
    footer = plan[-1].splitlines()[-1]
    assert footer.startswith("d " + t("keys.domain")) and "Esc " + t("keys.back") in footer
    assert "d " + t("keys.domain") not in plan[0].splitlines()[-1], "d only on «Свой домен»"
    assert t("help.s7").splitlines()[0] in titled(term, "help.title")[0]


def test_waiting_domains_leave_the_plan_its_rows():
    keys = on("nl-1", "self_steal", "d", *"late1.example.com", "enter")
    keys += on("nl-2", "self_steal", "d", *"late2.example.com", "enter")
    app, term, _code = run_fix(keys + ["esc", "q", "enter"])
    plan = titled(term, "plan.title")[-1]
    assert "late1.example.com" in plan and "late2.example.com" in plan, "both rows stay"
    record = t("plan.domain.wait", record="A late2.example.com → 203.0.113.11")
    assert record in flat(plan), "the record of the current row, in full"


def test_finalize_line_shows_only_with_a_marked_own_domain():
    app, term, _code = run_fix(["esc", "q", "enter"], width=100, height=30)
    assert not seen(term, t("plan.finalize.manual"))
    keys = on("nl-1", "self_steal", "d", *"nl-1.example.com")
    app, term, _code = run_fix(keys + ["enter", "esc", "q", "enter"], width=100, height=30)
    assert flat(t("plan.finalize.manual")) in flat(titled(term, "plan.title")[-1])


# -- UX 5, 17: 3x-ui ------------------------------------------------------------------
def test_xui_consent_warns_about_3x_ui_and_not_about_remnawave():
    keys = XUI_STEAL + ["d"] + list("vpn.example.com") + ["enter"]
    app, term, _code = run_fix(keys + ["enter", "esc", "esc", "q", "enter"], height=40,
                               panel_kind=None)  # fmt: skip
    consent = flat(titled(term, "consent.title")[0])
    assert t("fix.xui_steal.warning") in consent
    for key in ("fix.self_steal.warning", "fix.profile.warning"):
        assert t(key) not in consent
    assert "Hysteria2" not in consent


def test_xui_plan_names_the_address_and_hides_reserve_and_cdn_keys():
    keys = XUI_STEAL + ["d", "esc", "esc", "q", "enter"]
    app, term, _code = run_fix(keys, panel_kind=None)
    assert seen(term, t("plan.domain.hint", ip="203.0.113.50"))
    for frame in titled(term, "plan.title"):
        footer = frame.splitlines()[-1]
        assert "r " + t("keys.reserve") not in footer and "e " + t("keys.edges") not in footer
    assert "r " not in t("help.s7.xui")


# -- UX 10, 11, 14, 16, 20, 21: S6 -------------------------------------------------------
def check_app(keys, *, width=80, height=24):
    app, term = make_app(TO_S6_CHECK + list(keys), width=width, height=height,
                         state=short_state())  # fmt: skip
    return app, term, app.run("check")


def test_s6_at_80x24_pages_through_findings_with_a_one_line_score():
    app, term, _code = check_app(["pgdn", "end", "q", "enter"])
    s6 = titled(term, "s6.title")
    run = last_run(app)
    assert body_lines(s6[0])[0].strip().startswith(t("report.score", score=run["scoreBefore"]))
    pointer = [next(line for line in f.splitlines() if "›" in line) for f in s6]
    assert pointer[0] != pointer[1] != pointer[2], "PgDn and End move through the findings"
    assert t("s6.info.row", n=0).split(":")[0] in pointer[2], "End: the last row, explanations"
    path = str(RunStore(app.env.state, app.env.clock).path(run["runId"]) / "report.md")
    assert any(path in line for line in body_lines(s6[0])), "the path is never cut"
    lines = body_lines(s6[0])
    after_path = next(i for i, line in enumerate(lines) if "report.md" in line) + 1
    for line in lines[after_path:]:
        # K23: under the summary every line belongs to a block, wrapped cells too.
        assert not line.strip() or line.strip()[0] in "╭│╰", f"a line out of its block: {line!r}"


def test_s6_texts_are_plain_words():
    # K23: what a problem threatens is in the details of its row, so every row is
    # opened; wide enough that no cell wraps.
    keys = ["space", "down"] * 60 + ["q", "enter"]
    app, term, _code = check_app(keys, width=200, height=400)
    text = " ".join(flat(f) for f in titled(term, "s6.title"))
    for jargon in ("Маленький scMaxEachPostBytes", "пустой fingerprint", "Клиент шлёт ClientHello",
                   "Параметры sc*", "журналы CT", "клиентским сертификатом",
                   "(sub.template)"):  # fmt: skip
        assert jargon not in text, jargon
    for key in ("check.xhttp.extra_outer.title", "check.node_api.public.threat",
                "check.fleet.one_zone.threat"):  # fmt: skip
        assert flat(t(key)) in text, key
    assert flat(t("check.host.fingerprint.title", host="NL Reality")) in text
    how = t("check.reserve.missing.how")
    assert flat(how[:1].upper() + how[1:]) in text


def test_esc_on_s6_neither_collects_nor_asks_whois_again():
    app, term, _code = check_app(["esc", "esc", "q", "enter"])
    facts = [cmd for _a, cmd in app.env.transport.log if cmd == "facts"]
    assert len(facts) == 4, "one collection for the four nodes with access"
    whois = [f for f in term.frames if t("s5.whois.question")[:30] in flat(f)]
    assert len(whois) == 1


def test_f_on_s6_goes_on_to_the_plan_on_the_same_data():
    # The token of the check (keep it), the admin key, plan, consent, S9.
    keys = ["f", "enter", "enter", "enter", "enter", "enter", "enter"]
    app, term, code = check_app(keys, width=100, height=30)
    assert code == EXIT_OK
    runs = RunStore(app.env.state, app.env.clock).runs()
    fix, check = runs[0], runs[1]
    assert (fix["mode"], check["mode"]) == ("fix", "check")
    assert fix["findings"] == check["findings"] and fix["changes"]
    # One sign-in: «Исправление» goes on with the panel of the check, no second S2.
    assert [p for _m, p, _b in app.env.panel_transport.log].count("/auth/status") == 1
    assert len([f for f in term.frames if t("s5.whois.question")[:30] in flat(f)]) == 1
    assert seen(term, t("access.admin.choose")), "the administrator key is asked"
    assert seen(term, t("panel.token.readonly")), "a token given for the check is asked about"
    assert titled(term, "plan.title") and titled(term, "done.title")


def test_full_report_on_s6_reads_without_markdown_and_is_masked():
    app, term, _code = check_app(["m", "s", "esc", "q", "enter"], width=100, height=40)
    full = [f for f in term.frames if t("report.title.check") in f][0]
    assert "**" not in full and "# " not in full and "═" in full


def test_full_report_follows_masking_on_the_screen(monkeypatch):
    real = "198.18.0.10"  # RFC 2544 benchmarking range: reserved, nobody's; masking replaces it
    monkeypatch.setattr(RunStore, "report_text", lambda self, run_id: f"| Нода | {real} |")
    app, term, _code = check_app(["m", "s", "esc", "q", "enter"], width=100, height=30)
    full = [f for f in term.frames if "Нода" in f and t("s6.title") in f.splitlines()[0]]
    assert full and real not in full[-1]


# -- UX 12, 15: report.md ------------------------------------------------------------
def test_report_names_hosts_templates_and_the_panel_kind():
    app, _term, _code = run_fix(["enter", "enter", "enter"], height=40)
    text = RunStore(app.env.state, app.env.clock).report_text(last_run(app)["runId"])
    assert t("target.template", name="Default") in text
    assert t("target.host", name="FI CDN") in text
    assert t("panel.kind.remnawave") + " 2.8.1" in text
    run = last_run(app)
    run["panel"]["kind"] = "3x-ui"
    head = markdown.render(run).splitlines()[2]
    assert "Панель: 3x-ui 2.8.1" in head and "Remnawave" not in head


# -- UX 24: interrupting S8 ------------------------------------------------------------
def test_interrupt_asks_with_its_own_keys_and_ends_on_prervano():
    app, term, code = run_fix(["enter", "enter", "ctrl-c", "enter", "enter"])
    assert code == EXIT_INTERRUPTED
    assert seen(term, flat(t("apply.interrupt.keys")))
    assert not titled(term, "done.title") and titled(term, "apply.interrupted.title")


# -- UX 25: without colour ------------------------------------------------------------
def test_cursor_and_colour_samples_without_colour():
    field = TextInput("Домен", value="nl1.example.com")
    for _ in range(4):
        field.handle("left")
    assert "nl1.example▏.com" in frame_text(field, 40, 3, color=False)
    assert "▏" not in frame_text(field, 40, 3, color=True)
    keys = on("nl-1", "self_steal") + ["esc", "q", "enter"]
    _app, term, _code = run_fix(keys)
    assert "██" not in titled(term, "plan.title")[-1]
    app, term = make_app(TO_PLAN + keys, state=short_state())
    term.color = True  # a terminal with colour gets the samples of the site's colours
    app.run("fix")
    assert "██ ██ ██" in titled(term, "plan.title")[-1]


# -- widgets ------------------------------------------------------------------------
def render(renderable, width=80, height=24):
    term = FakeTerminal(width=width, height=height)
    term.draw(renderable)
    return term.last


def test_stack_pins_the_parts_after_the_flexible_one():
    long = Text("\n".join(f"row {i}" for i in range(50)))
    frame = render(Screen("x", Stack(Text("top"), Pager(long), Text("bottom"), flex=1)), height=12)
    lines = body_lines(frame)
    assert lines[0].strip() == "top" and lines[-1].strip() == "bottom"
    assert any("строки 1–" in line for line in lines)


def test_consent_keeps_the_button_on_a_tiny_screen():
    summary = Group(*[Text(f"line {i}") for i in range(40)])
    consent = Consent(summary, t("consent.accept"), "keys here")
    frame = render(Screen("x", consent), height=14)
    assert t("consent.accept") in frame and "keys here" in frame
    consent.handle("end")
    assert "line 39" in render(Screen("x", consent), height=14)


def test_clamp_cuts_with_an_ellipsis_and_pads():
    text = Text("word " * 60)
    lines = render(Clamp(text, 2), width=40).splitlines()
    assert len(lines) == 2 and lines[-1].endswith("…")
    assert len(render(Group(Clamp(Text("one"), 3, pad=True), Text("next"))).splitlines()) == 4


def test_checklist_named_column_keeps_its_width_at_80_columns():
    rows = [["шаблон Default", "Перенести SSH на порт 23446 и ещё", "средняя", "x" * 50]]
    checklist = Checklist(rows, ["Нода", "Исправление", "Важность", "Заметка"], flexible=1,
                          min_width=30)  # fmt: skip
    frame = render(checklist, width=78)
    assert "Перенести SSH на порт 23446 и е" in frame
    assert all(len(line) <= 78 for line in frame.splitlines())


def test_checklist_reaches_disabled_rows_only_when_asked():
    rows = [["a"], ["b"], ["c"]]
    skipping = Checklist(rows, ["Нода"], disabled={1})
    skipping.handle("down")
    assert skipping.cursor == 2
    reaching = Checklist(rows, ["Нода"], disabled={1}, reach_disabled=True)
    reaching.handle("down")
    reaching.handle("space")
    assert reaching.cursor == 1 and reaching.selected == set()


def test_compact_score_badge_is_one_line_with_words():
    assert len(render(ScoreBadge(60, before=38, compact=True)).splitlines()) == 1
    line = render(ScoreBadge(60, before=38, compact=True))
    assert t("score.yellow") in line and t("score.was", before=38) in line


def test_block_list_pages_across_its_rows():
    rows = [BlockRow([Text(f"Находка {i}"), Text(f"n{i}")]) for i in range(30)]
    listing = BlockList([Block("Блок", rows, [Column(flex=1), Column(most=4)])])
    listing.viewport = 10
    render(listing)
    listing.handle("pgdn")
    assert listing.cursor > 1
    listing.handle("end")
    assert listing.cursor == 29 and "Находка 29" in render(listing)
    listing.handle("home")
    assert listing.cursor == 0 and "Блок" in render(listing), "the first row shows its block"


@given(
    st.lists(st.integers(1, 60), min_size=1, max_size=6),
    st.integers(0, 40),
    st.integers(20, 200),
)
def test_fit_widths_fits_and_never_goes_below_floors(natural, floor, available):
    floors = [min(floor, n) for n in natural]
    widths = fit_widths(natural, floors, available)
    assert all(f <= w <= n for f, w, n in zip(floors, widths, natural))
    if sum(floors) <= available:
        assert sum(widths) <= available
        assert sum(widths) == min(available, sum(natural))


def test_plain_report_aligns_tables():
    text = "# T\n\n## S\n\n| Нода | Адрес |\n|---|---|\n| nl-1 | 203.0.113.10 |\n**b** `c`"
    out = markdown.plain(text).splitlines()
    assert out[:2] == ["T", "═"] and "S" in out and "─" in out
    assert "Нода  Адрес" in out and "nl-1  203.0.113.10" in out and "b c" in out
