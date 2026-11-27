"""S5 collection and S6 report in «Проверка» (tech.md §6, §12, K3)."""

import json
import re
import stat

from helpers import S4_KEYS, assert_snapshot, login_keys, make_app, seen
from test_review_screens import short_state

from kerberos.__main__ import Options, print_report
from kerberos.copy import t
from kerberos.fixes.journal import RunStore
from kerberos.mask import Masker
from kerberos.report import markdown
from kerberos.screens.check import write_report

# S2 summary, S3, the intro of «Проверка» on S4, five host keys, kz-1 skipped, S4 summary.
TO_S5 = login_keys() + ["enter"] + S4_KEYS + ["enter"]  # S3, S4 with its summary
WHOIS_YES = ["enter"]
READ_ONLY = {"version", "facts", "watch", "site-check", "edge-sources"}


def check_run(extra=(), height=34, mask=False, state=None):
    keys = TO_S5 + WHOIS_YES + list(extra) + ["enter", "x"] * 0 + ["q", "enter"]
    app, term = make_app(keys, height=height, mask=mask, state=state)
    app.run("check")
    return app, term


def s6_frames(term):
    return [f for f in term.frames if t("s6.title") in f.splitlines()[0]]


def test_s6_shows_score_findings_and_saved_report():
    app, term = check_run(state=short_state())
    frame = s6_frames(term)[0]
    runs = RunStore(app.env.state, app.env.clock).runs()
    assert len(runs) == 1 and runs[0]["mode"] == "check"
    assert t("report.score", score=runs[0]["scoreBefore"]) in frame
    assert runs[0]["scoreBefore"] < 60 and t("score.red") in frame
    assert t("s6.block.auto") in frame
    path = RunStore(app.env.state, app.env.clock).path(runs[0]["runId"])
    text = re.sub(r"\S*kerberos-test-\S*", "<state>", frame)
    assert_snapshot("s6", text.replace(runs[0]["runId"], "<run>"))
    assert path.is_dir()


def test_check_mode_changes_nothing():
    app, term = check_run()
    assert app.env.panel_transport.mutations == []
    agent_calls = {
        cmd.split()[0]
        for _addr, cmd in app.env.transport.log
        if not cmd.startswith(("keyscan", "open_root", "root ", "admin"))
    }
    assert agent_calls <= READ_ONLY, agent_calls


def test_report_files():
    app, _term = check_run()
    store = RunStore(app.env.state, app.env.clock)
    run = store.runs()[0]
    directory = store.path(run["runId"])
    for name in ("run.json", "report.md", "report.json", "kerberos.log"):
        assert stat.S_IMODE((directory / name).stat().st_mode) == 0o600, name
    report = (directory / "report.md").read_text(encoding="utf-8")
    assert report.startswith("# " + t("report.title.check"))
    assert t("report.score", score=run["scoreBefore"]) in report
    assert t("check.ssh.password.title") in report
    model = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    assert set(model) >= {
        "runId",
        "mode",
        "kerberos",
        "panel",
        "nodes",
        "findings",
        "changes",
        "scoreBefore",
        "scoreAfter",
        "pending",
        "startedAt",
        "finishedAt",
    }
    finding = model["findings"][0]
    assert set(finding) == {"checkId", "topic", "risk", "target", "ok", "evidence", "fixId"}
    for path in directory.iterdir():
        text = path.read_text(encoding="utf-8")
        assert "admin-password" not in text and "DEMO_KEY" not in text


def test_masked_report_files(tmp_path):
    app, _term = check_run()
    run = RunStore(app.env.state, app.env.clock).runs()[0]
    run["nodes"][0]["address"] = "198.18.0.10"
    app.env.masker = Masker(True)
    write_report(app, run)
    directory = RunStore(app.env.state, app.env.clock).path(run["runId"])
    for name in ("report.md", "report.json"):
        assert "198.18.0.10" not in (directory / name).read_text(encoding="utf-8")


def test_details_open_with_space_and_full_report_with_s():
    app, term = check_run(extra=["space", "s", "pgdn", "esc"], height=40)
    frames = s6_frames(term)
    # K23: the first row is the area «Свой домен»; Space lists its problems.
    title = t("check.reality.foreign_sni.title")
    assert title not in frames[0] and title in frames[1]
    assert any(t("report.title.check") in f for f in term.frames)


def test_without_whois_question_answer_no():
    keys = TO_S5 + ["down", "enter"] + ["q", "enter"]
    app, term = make_app(keys)
    app.run("check")
    assert app.env.whois.queries == []
    assert seen(term, t("s6.title"))
    run = RunStore(app.env.state, app.env.clock).runs()[0]
    assert not any(f["checkId"] in ("fleet.same_asn", "reserve.same_asn") for f in run["findings"])


def test_reports_menu_and_cli_print(capsys):
    app, term = check_run()
    store = RunStore(app.env.state, app.env.clock)
    run_id = store.runs()[0]["runId"]
    keys = ["4", "enter", "esc", "esc", "q", "enter"]
    term.feed(*keys)
    app.run()
    assert any(t("report.title.check") in f for f in term.frames)
    assert print_report(Options(command="report"), state=app.env.state) == 0
    assert capsys.readouterr().out.startswith("# " + t("report.title.check"))
    assert print_report(Options(command="report", arg=run_id), state=app.env.state) == 0
    assert print_report(Options(command="report", arg="nope"), state=app.env.state) == 2


def test_markdown_lists_nodes_and_topics():
    app, _term = check_run()
    run = RunStore(app.env.state, app.env.clock).runs()[0]
    text = markdown.render(run)
    assert "| nl-1 | 203.0.113.10 | 22 |" in text
    assert "## " + t("topic.scanning") in text
