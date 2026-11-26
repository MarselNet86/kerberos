"""Texts and screens S1–S4, rollback and finalize: findings of the K12 review.

Each test follows the failure scenario of a finding of the UX review (numbers in
the names of the sections below) through the fake terminal.
"""

from datetime import datetime

from helpers import TOKEN, flat, login_keys, make_app, on, seen, typed

from kerberos.copy import plural, t
from kerberos.demo.fleet import build_nodes, build_panel
from kerberos.demo.xui import XUI_DOMAIN
from kerberos.fixes.journal import RunStore
from kerberos.flow import EXIT_OK, EXIT_PANEL, EXIT_ROLLBACK_FAILED
from kerberos.host import FakeHost
from kerberos.nodes.keys import PublicKey, demo_blob, fingerprint
from kerberos.panel.discover import XUI_DB

TO_S4 = login_keys() + ["enter", "enter"]  # S2 summary, S3
INTRO = ["enter"]  # «Проверка»: what S4 installs, before the first node
# nl-1, nl-2, de-1 (and its python3), fi-1 confirm the host key; kz-1 is unreachable.
ALL_NODES = ["enter", "enter", "enter", "enter", "enter", "esc"]
QUIT = ["q", "enter"]
# «Исправление»: S4 with «Мои ключи» and the checklist, its summary, whois, S6 → S7.
TO_PLAN = TO_S4 + ALL_NODES + ["enter", "enter"] + ["enter", "enter", "enter"]
APPLY = ["enter", "enter", "enter"]  # S7 → consent → accept → S9 Enter
ROLLBACK = ["enter", "enter", "enter", "x"]  # run, changes, consent; the saved token
CHOOSE_XUI = ["down", "enter"]  # S2: 3x-ui is the second panel of the demo server
XUI_LOGIN = typed("admin") + ["enter"] + typed("pw") + ["enter"]
SHARED = fingerprint(demo_blob("hoster-image"))  # nl-1 and nl-2: one image of the hoster


def strict_panel():
    panel = build_panel()
    panel.accept_any_token = False
    panel.add_api_token(TOKEN)
    return panel


def first(term, text):
    """Index of the first frame that shows `text`, wrapped or not; None if none does."""
    return next((i for i, f in enumerate(term.frames) if text in flat(f)), None)


def footer(frame):
    return frame.splitlines()[-1]


def title(frame):
    return frame.splitlines()[0]


def words(text):
    """A text as `flat` shows it: line breaks and runs of spaces become one space."""
    return " ".join(text.split())


def solid(frame):
    """Frame text without any spaces: a long path folded over lines reads as one."""
    return "".join(flat(frame).split())


def run_check(nodes=None, state=None, extra=INTRO + ALL_NODES, panel=None):
    keys = TO_S4 + list(extra) + ["enter", "x"] + QUIT
    app, term = make_app(keys, nodes=nodes, state=state, panel=panel or strict_panel())
    app.run("check")
    return app, term


def fix_with_self_steal(nodes=None):
    keys = TO_PLAN + on("nl-1", "self_steal", "d")
    keys += list("nl-1.example.com") + ["enter"] + APPLY
    app, term = make_app(keys, nodes=nodes, height=46)
    assert app.run("fix") == EXIT_OK
    return app, term


def store_of(app):
    return RunStore(app.env.state, app.env.clock)


def when(run):
    moment = datetime.strptime(run["startedAt"], "%Y-%m-%dT%H:%M:%SZ")
    return moment.strftime("%d.%m.%Y %H:%M") + " UTC"


# -- 3: «Проверка» says what S4 installs before it does -------------------------------
def test_s1_check_item_promises_only_what_check_keeps():
    app, term = make_app(QUIT)
    app.run()
    assert "ничего не меняет" not in term.frames[0]
    assert t("mode.check") in term.frames[0]


def test_check_explains_what_s4_installs_before_the_first_node():
    app, term = run_check()
    intro = first(term, t("access.intro"))
    question = first(term, t("access.hostkey", node="nl-1", fingerprint=SHARED))
    assert intro is not None and question is not None and intro < question
    assert "Enter" in footer(term.frames[intro]) and "Esc" in footer(term.frames[intro])
    assert first(term, t("access.intro")) == intro, "shown once"
    assert app.env.state.find_node("nl-1").access == "ok", "Enter goes on as before"


def test_esc_on_the_intro_goes_back_before_anything_is_installed():
    nodes = build_nodes()
    app, term = make_app(TO_S4 + ["esc", "esc", "esc"], nodes=nodes)
    assert app.run("check") == EXIT_OK
    intro = first(term, t("access.intro"))
    assert intro is not None and t("nodes.title") in term.frames[intro + 1]
    assert all(n.agent_sha is None for n in nodes)
    assert not any("kerberos-agent" in k for n in nodes for k in n.authorized_keys)
    assert not any(cmd.startswith(("open_root", "root ")) for _a, cmd in app.env.transport.log)


def test_fix_mode_asks_no_intro():
    app, term = make_app(TO_S4 + ALL_NODES + ["esc"] + QUIT)
    app.run("fix")
    assert first(term, t("access.intro")) is None
    assert seen(term, t("access.admin.chosen.skip"))


def test_3xui_check_says_what_it_installs_and_esc_returns_to_s2():
    app, term = make_app(CHOOSE_XUI + XUI_LOGIN + ["enter", "esc", "esc"], panel_kind=None)
    assert app.run("check") == EXIT_OK
    intro = first(term, t("access.intro.local"))
    assert intro is not None
    assert t("panel.xui.ok", inbounds=2) in flat(term.frames[intro + 1]), "back on S2"
    node = app.env.transport.nodes["127.0.0.1"]
    assert not any("command=" in k for k in node.authorized_keys)
    assert app.env.state.node("local") is None
    assert term.remaining == []


# -- 7: a changed host key is not accepted by one Enter -------------------------------
def test_changed_host_key_is_skipped_by_default_and_shows_the_old_key():
    nodes = build_nodes()
    app, _ = run_check(nodes)
    state = app.env.state
    nodes[0].host_key = PublicKey("ssh-ed25519", demo_blob("reinstalled"))
    # The intro, Enter on the changed key of nl-1, Esc on the port of kz-1.
    app, term = run_check(nodes, state, extra=INTRO + ["enter", "esc"])
    assert state.pinned("203.0.113.10", 22) == demo_blob("hoster-image")
    asked = first(term, t("access.hostkey_old", fingerprint=SHARED))
    assert asked is not None
    frame = term.frames[asked]
    assert t("access.hostkey_changed", node="nl-1") in flat(frame)
    new = fingerprint(demo_blob("reinstalled"))
    assert t("access.hostkey_new", fingerprint=new) in flat(frame)
    pointer = next(line for line in frame.splitlines() if "›" in line)
    assert t("access.skip") in pointer
    after = [cmd for addr, cmd in app.env.transport.log if addr == "203.0.113.10"]
    assert all(cmd.startswith(("keyscan", "version")) for cmd in after), after


def test_first_host_key_question_says_how_to_check_and_who_shares_the_key():
    app, term = run_check()
    nl1 = term.frames[first(term, t("access.hostkey", node="nl-1", fingerprint=SHARED))]
    assert words(t("access.hostkey_hint")) in flat(nl1)
    command = t("access.hostkey_hint").splitlines()[-1]
    assert any(line.strip() == command for line in nl1.splitlines()), "never wrapped"
    assert t("access.hostkey_same", nodes="nl-1") not in flat(nl1)
    nl2 = term.frames[first(term, t("access.hostkey", node="nl-2", fingerprint=SHARED))]
    assert t("access.hostkey_same", nodes="nl-1") in flat(nl2)
    de1 = fingerprint(demo_blob("de-1"))
    de1_frame = term.frames[first(term, t("access.hostkey", node="de-1", fingerprint=de1))]
    assert "nl-1" not in flat(de1_frame).split(words(t("access.hostkey_hint")))[1]


def test_s4_question_and_answers_fit_when_the_node_table_does_not():
    # A short window stands for a long fleet: the node rows give way, the question stays.
    keys = TO_S4 + INTRO + ALL_NODES + ["enter", "x"] + QUIT
    app, term = make_app(keys, width=80, height=20, panel=strict_panel())
    app.run("check")
    frame = term.frames[first(term, t("access.hostkey_same", nodes="nl-1"))]
    assert t("access.yes") in frame and t("access.no") in frame
    assert "nl-2" in frame and t("pager.position", start=1, end=2, total=5) in frame
    assert all(len(line) <= 80 for line in frame.splitlines())


# -- 8: finalization names what stays and what goes ------------------------------------
def test_finalize_lists_what_stays_and_what_goes():
    app, term = fix_with_self_steal()
    app.env.clock.advance(24 * 3600)
    term.feed("x")  # the panel takes the saved token; then leave the consent
    assert app.run("finalize") == EXIT_OK
    item = t("fin.item", node="nl-1", domain="nl-1.example.com", old="www.example.net")
    asked = first(term, item)
    assert asked is not None
    assert "serverNames" not in term.frames[asked]
    assert t("fin.consent") in flat(term.frames[asked])


def test_3xui_finalize_lists_what_stays_and_what_goes():
    keys = CHOOSE_XUI + XUI_LOGIN + ["enter", "enter", "enter"]  # S2, S4 summary, S6
    keys += ["end", "d"] + list(XUI_DOMAIN) + ["enter"] + APPLY  # its domain: the last row
    app, term = make_app(keys, panel_kind=None, height=44)
    assert app.run("fix") == EXIT_OK
    name = store_of(app).runs()[0]["pending"][0]["nodeName"]
    app.env.clock.advance(25 * 3600)
    term.feed(*(XUI_LOGIN + ["x"]))
    assert app.run("finalize") == EXIT_OK
    asked = first(term, t("fin.item", node=name, domain=XUI_DOMAIN, old="www.example.net"))
    assert asked is not None
    assert t("fin.consent.local") in flat(term.frames[asked])


# -- 10: Esc on the questions of S4 is named, and the admin question comes back --------
def test_s4_questions_name_esc_in_the_footer():
    app, term = run_check()
    question = term.frames[first(term, t("access.hostkey", node="nl-1", fingerprint=SHARED))]
    assert "Esc " + t("keys.skip_node") in footer(question)
    port = term.frames[first(term, t("access.port_label", node="kz-1"))]
    assert "Esc " + t("keys.skip_node") in footer(port)
    assert t("access.skip") not in footer(port), "lowercase in the footer"


def test_admin_key_question_comes_back_when_s4_is_entered_again():
    keys = TO_S4 + ALL_NODES + ["esc"]  # the admin question: Esc skips it
    keys += ["esc", "enter", "esc"]  # summary → S3 → S4 again; the port of kz-1 again
    keys += ["up", "up", "enter", "enter"]  # the question again: «Мои ключи», the checklist
    app, term = make_app(keys + QUIT)
    app.run("fix")
    asked = [i for i, f in enumerate(term.frames) if t("access.admin.later") in flat(f)]
    starts = [i for i in asked if i - 1 not in asked]
    assert len(starts) == 2
    footer_of_question = footer(term.frames[asked[0]])
    assert "Esc " + t("keys.skip") in footer_of_question
    assert seen(term, t("access.admin.chosen.mine"))


# -- 12: the result of a rollback, its scores and how runs are named -------------------
def fix_then(extra_nodes=None):
    nodes = {n.name: n for n in build_nodes()}
    app, term = make_app(TO_PLAN + ["enter", "enter", "enter"], nodes=list(nodes.values()),
                         height=40)  # fmt: skip
    assert app.run("fix") == EXIT_OK
    return app, term, nodes, store_of(app).runs()[0]


def test_rollback_result_shows_failures_the_hint_and_the_report():
    app, term, nodes, _fixed = fix_then()
    nodes["nl-1"].state["rollback_fails"] = True
    term.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_ROLLBACK_FAILED
    record = store_of(app).runs()[0]
    result = flat(term.frames[-1])
    assert t("rb.failed") in result
    assert "".join(t("report.saved", path="").split()) in solid(term.frames[-1])
    assert record["runId"] in solid(term.frames[-1])


def test_rollback_run_has_the_scores_the_other_way_round():
    app, term, _nodes, fixed = fix_then()
    term.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_OK
    record = store_of(app).runs()[0]
    assert record["mode"] == "rollback" and record["rolledBackRun"] == fixed["runId"]
    assert (record["scoreBefore"], record["scoreAfter"]) == (fixed["scoreAfter"],
                                                             fixed["scoreBefore"])  # fmt: skip
    report = store_of(app).report_text(record["runId"])
    line = t("report.score_before_after", before=fixed["scoreAfter"], after=fixed["scoreBefore"])
    assert line in report
    assert "".join(t("report.saved", path="").split()) in solid(term.frames[-1])
    assert record["runId"] in solid(term.frames[-1])


def test_runs_are_named_by_time_mode_changes_and_nodes():
    app, term, _nodes, fixed = fix_then()
    term.feed("esc")
    app.run("rollback")
    name = f"{when(fixed)} · {t('report.mode.fix')} · изменений: 19 · nl-1, nl-2, de-1, …"
    choice = term.frames[first(term, t("rb.choose"))]
    assert name in choice and fixed["runId"] not in choice
    term.feed("4", "esc", *QUIT)
    app.run()
    head = "/// kerberos  " + t("reports.title")
    reports = next(f for f in term.frames if title(f).startswith(head))
    assert name in reports


def test_check_runs_in_the_reports_menu_show_the_score():
    keys = TO_S4 + INTRO + ALL_NODES + ["enter", "enter", "enter"]  # S4, whois, S6 → the end
    app, term = make_app(keys)
    assert app.run("check") == EXIT_OK
    run = store_of(app).runs()[0]
    term.feed("4", "esc", *QUIT)
    app.run()
    name = (f"{when(run)} · {t('report.mode.check')} · защищённость {run['scoreBefore']}"
            " · nl-1, nl-2, de-1, …")  # fmt: skip
    assert seen(term, name)


# -- 15: an address typed by hand is not «found» ---------------------------------------
def test_typed_api_address_is_not_called_found():
    keys = ["enter"] + login_keys() + ["esc", "esc", "esc"]
    app, term = make_app(keys, host=FakeHost(), panel=strict_panel())
    app.run("check")
    assert seen(term, t("panel.manual", api="http://127.0.0.1:3000/api"))
    assert not seen(term, "Нашёл Remnawave ?")


def test_typed_3xui_address_is_not_called_found():
    app, term = make_app(["enter"] + XUI_LOGIN + ["esc"], panel_kind="3x-ui")
    del app.env.host.databases[XUI_DB]
    app.run("check")
    assert seen(term, t("panel.xui.manual"))
    assert not seen(term, "Нашёл 3x-ui ?")


# -- 16: no jargon on S1 and in the finalization ----------------------------------------
def test_finalization_speaks_without_jargon():
    app, term = fix_with_self_steal()
    app.env.clock.advance(24 * 3600)
    term.feed("enter", "enter", "x", *QUIT)  # S1: the finalize item first; the saved token
    assert app.run() == EXIT_OK
    s1 = term.frames[first(term, t("mode.finalize"))]
    assert "self-steal" not in s1
    assert seen(term, "убрать старое имя у 1 ноды")
    assert seen(term, "убраны у 1 ноды")
    assert not any("serverNames" in f or "self-steal" in f for f in term.frames)


# -- 17: the 3x-ui path speaks of this server -------------------------------------------
def test_s1_names_both_panels():
    app, term = make_app(QUIT)
    app.run()
    assert "Remnawave" in term.frames[0] and "3x-ui" in term.frames[0]


def test_3xui_access_speaks_of_this_server_and_of_the_own_keys():
    keys = CHOOSE_XUI + XUI_LOGIN + ["enter"] + INTRO + QUIT
    app, term = make_app(keys, panel_kind=None)
    app.run("check")
    summary = term.frames[first(term, t("access.summary.local"))]
    assert t("access.title.local") in title(summary)
    assert t("access.admin.local.some", n=1) in flat(summary)
    assert t("access.col.server") in summary
    assert not any("нод" in title(f) for f in term.frames if t("access.title.local") in f)


def test_3xui_without_own_keys_says_password_login_stays():
    keys = CHOOSE_XUI + XUI_LOGIN + ["enter"] + INTRO + QUIT
    app, term = make_app(keys, panel_kind=None)
    app.env.host.files["/root/.ssh/authorized_keys"] = ""
    app.run("check")
    assert seen(term, t("access.admin.local.none"))


# -- 23: errors say what to do ----------------------------------------------------------
def test_panel_errors_say_what_to_do():
    panel = strict_panel()
    panel.fail("GET", "/auth/status", 503, times=4)
    app, term = make_app(["esc"], panel=panel)
    assert app.run("check") == EXIT_PANEL
    assert "подождите минуту и нажмите Enter" in flat(term.last)
    panel = strict_panel()
    panel.fail("GET", "/auth/status", "refused", times=10)
    app, term = make_app(["esc"], panel=panel)
    assert app.run("check") == EXIT_PANEL
    message = flat(term.last)
    assert "http://127.0.0.1:3000/api" in message and "remnawave запущен" in message


def test_lost_confirmation_says_the_old_settings_are_back():
    nodes = {n.name: n for n in build_nodes()}
    nodes["de-1"].state["confirm_fails"] = True
    app, term = make_app(TO_PLAN + ["enter", "enter", "enter"], nodes=list(nodes.values()),
                         height=40)  # fmt: skip
    app.run("fix")
    assert seen(term, "прежние настройки возвращены; запустите «Исправление» ещё раз")


# -- 24: numbers agree with words, small slips -----------------------------------------
def test_plural_forms():
    forms = ("нода", "ноды", "нод")
    expected = {1: "нода", 2: "ноды", 4: "ноды", 5: "нод", 11: "нод", 12: "нод", 14: "нод",
                21: "нода", 22: "ноды", 25: "нод", 101: "нода", 111: "нод", 0: "нод"}  # fmt: skip
    assert {n: plural(n, *forms) for n in expected} == expected


def test_one_node_is_one_node():
    keys = login_keys() + ["enter", "a", "space", "enter"] + INTRO + ["enter"] + QUIT
    app, term = make_app(keys, panel=strict_panel())
    app.run("check")
    assert seen(term, "Доступ есть у 1 из 1 ноды")


def test_quit_dialog_has_a_capital_title():
    app, term = make_app(["q", "enter"])
    app.run()
    assert title(term.frames[1]).startswith("/// kerberos  " + t("quit.title"))
    assert t("quit.title")[0].isupper()
