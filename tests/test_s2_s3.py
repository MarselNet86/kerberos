"""S2 panel and S3 nodes: key scenarios (tech.md §6, §7, K1)."""

from helpers import TOKEN, assert_snapshot, flat, login_keys, make_app, token_keys, typed

from kerberos.copy import t
from kerberos.demo.fleet import build_panel
from kerberos.flow import EXIT_PANEL
from kerberos.host import FakeHost
from kerberos.panel.fake import FakePanel


def strict_panel(**kwargs) -> FakePanel:
    panel = build_panel()
    panel.accept_any_token = False
    panel.add_api_token(TOKEN)
    for key, value in kwargs.items():
        setattr(panel, key, value)
    return panel


def test_s2_connects_without_typing_an_address():
    keys = ["enter"] + login_keys() + ["enter", "esc", "q", "enter"]
    app, term = make_app(keys, panel=strict_panel())
    assert app.run("check") == 0
    assert any(t("panel.found", version="2.8.1") in f for f in term.frames)
    assert any(t("panel.ok", nodes=6, hosts=10) in f for f in term.frames)
    assert any(t("nodes.title") in f for f in term.frames)


def test_s2_wrong_token_then_right_one():
    keys = token_keys("nope") + typed(TOKEN) + ["enter", "esc", "esc", "esc"]
    app, term = make_app(keys, panel=strict_panel())
    app.run("check")
    assert any(t("panel.err.token") in f for f in term.frames)
    assert any(t("panel.ok", nodes=6, hosts=10) in f for f in term.frames)


def test_the_token_never_reaches_the_screen_and_is_kept_0600():
    panel = strict_panel(password_enabled=False)
    token = panel.add_api_token("rw-0123456789abcdef")
    keys = typed(token) + ["enter", "esc", "esc", "esc"]
    app, term = make_app(keys, panel=panel)
    app.run("check")
    assert all(token not in f for f in term.frames)
    assert any(t("panel.token") in f for f in term.frames)
    assert any(t("panel.ok", nodes=6, hosts=10) in f for f in term.frames)
    saved = app.env.state.panel_token
    assert app.env.state.read_panel_token() == token
    assert not app.env.state.panel_token_can_write(), "given for «Проверка»"
    assert oct(saved.stat().st_mode)[-3:] == "600"
    for path in app.env.state.root.rglob("*"):
        if path.is_file() and path != saved:
            assert token not in path.read_text(encoding="utf-8", errors="replace"), path


def test_a_saved_token_is_not_asked_for_again():
    panel = strict_panel()
    app, _ = make_app(login_keys() + ["esc", "esc", "esc"], panel=panel)
    app.run("check")
    state = app.env.state
    app, term = make_app(["esc", "esc", "esc"], panel=panel, state=state)
    app.run("check")
    assert any(t("panel.ok", nodes=6, hosts=10) in f for f in term.frames)
    assert any(t("panel.token.used") in f for f in term.frames)
    assert not any(t("panel.token_hint") in flat(f) for f in term.frames)


def test_a_saved_token_the_panel_dropped_is_replaced():
    panel = strict_panel()
    app, _ = make_app(token_keys() + ["esc", "esc", "esc"], panel=panel)
    app.run("check")
    state = app.env.state
    del panel.api_tokens[TOKEN]  # deleted in the panel
    fresh = panel.add_api_token("rw-fresh-token")
    app, term = make_app(token_keys(fresh) + ["esc", "esc", "esc"], panel=panel, state=state)
    app.run("check")
    assert any(t("panel.token.stale") in flat(f) for f in term.frames)
    assert any(t("panel.ok", nodes=6, hosts=10) in f for f in term.frames)
    assert state.read_panel_token() == fresh


def test_rights_to_give_follow_the_mode():
    import json

    from kerberos.panel.client import SCOPES_CHECK, SCOPES_FIX

    to_token = ["tab", "tab", "enter", "esc", "esc", "esc"]  # «У меня есть API-токен» (K30)
    app, term = make_app(to_token, panel=strict_panel())
    app.run("check")
    assert any(json.dumps(SCOPES_CHECK).replace(" ", "") in flat(f).replace(" ", "")
               for f in term.frames)  # fmt: skip
    app, term = make_app(to_token, panel=strict_panel())
    app.run("fix")
    assert any(json.dumps(SCOPES_FIX).replace(" ", "") in flat(f).replace(" ", "")
               for f in term.frames)  # fmt: skip
    assert "hosts:*" in json.dumps(SCOPES_FIX) and "hosts:read" in json.dumps(SCOPES_CHECK)


def test_a_token_without_a_right_is_told_which_and_another_one_goes_on():
    panel = strict_panel()
    reader = panel.add_api_token("rw-nodes-only", scopes=("nodes:read",))
    keys = token_keys(reader) + token_keys() + ["esc", "esc", "esc"]
    app, term = make_app(keys, panel=panel)
    app.run("check")
    wanted = t("panel.err.forbidden", kind=t("panel.right.read"),
               section=t("panel.section.hosts"))  # fmt: skip
    assert any(wanted in flat(f) for f in term.frames)
    assert any(t("panel.ok", nodes=6, hosts=10) in f for f in term.frames)
    assert app.env.state.read_panel_token() == TOKEN


def test_wrong_token_is_reported():
    panel = strict_panel(password_enabled=False)
    keys = typed("bad-token") + ["enter", "esc", "esc"]
    app, term = make_app(keys, panel=panel)
    app.run("check")
    assert any(t("panel.err.token") in f for f in term.frames)


def test_panel_not_found_asks_for_the_api_address():
    keys = ["enter"] + login_keys() + ["esc", "esc", "esc"]
    app, term = make_app(keys, host=FakeHost(), panel=strict_panel())
    app.run("check")
    assert t("panel.not_found") in term.frames[1]
    assert any(t("panel.ok", nodes=6, hosts=10) in f for f in term.frames)


def test_server_error_offers_retry_and_esc_exits_with_3():
    panel = strict_panel()
    panel.fail("GET", "/auth/status", 503, times=4)
    app, term = make_app(["esc"], panel=panel)
    assert app.run("check") == EXIT_PANEL
    assert t("panel.err.server", status=503, operation="GET /auth/status") in term.last
    panel = strict_panel()
    panel.fail("GET", "/auth/status", 503, times=4)
    keys = ["enter"] + login_keys() + ["esc", "esc", "esc"]
    app, term = make_app(keys, panel=panel)
    app.run("check")
    assert any(t("panel.ok", nodes=6, hosts=10) in f for f in term.frames)


def test_forbidden_while_reading_is_shown_with_the_operation():
    panel = strict_panel()
    panel.forbidden.add(("GET", "/internal-squads"))
    keys = login_keys() + ["esc"]
    app, term = make_app(keys, panel=panel)
    assert app.run("check") == EXIT_PANEL
    wanted = t("panel.err.forbidden", kind=t("panel.right.read"),
               section=t("panel.section.internal-squads"))  # fmt: skip
    assert any(wanted in flat(f) for f in term.frames)


def test_s3_snapshot_and_disabled_node():
    keys = login_keys() + ["down", "down", "down", "down", "space", "esc", "esc", "esc"]
    app, term = make_app(keys, panel=strict_panel(), height=24)
    app.run("check")
    s3 = next(f for f in term.frames if t("nodes.title") in f)
    assert_snapshot("s3", s3)
    us = next(line for line in s3.splitlines() if "us-1" in line)
    assert " - " in us and t("nodes.status.disabled") in us


def test_s3_needs_at_least_one_node():
    keys = login_keys() + ["a", "enter", "a", "enter", "esc", "q", "enter"]
    app, term = make_app(keys, panel=strict_panel())
    app.run("check")
    assert any(t("nodes.need_one") in f for f in term.frames)
    assert any(t("access.title") in f for f in term.frames)


def test_check_mode_makes_no_changes_in_the_panel():
    panel = strict_panel()
    keys = login_keys() + ["enter", "esc", "q", "enter"]
    app, _ = make_app(keys, panel=panel)
    app.run("check")
    assert panel.mutations == []


def test_s3_masks_addresses():
    keys = login_keys() + ["m", "esc", "esc", "esc"]
    app, term = make_app(keys, panel=strict_panel())
    app.run("check")
    masked = next(f for f in term.frames if t("nodes.title") in f and t("hdr.mask") in f)
    # documentation addresses are already safe and stay as they are
    assert "203.0.113.10" in masked
