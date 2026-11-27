"""K30: KERBEROS makes its own API token from the admin's login (tech.md v36, §6 S2, §7.3)."""

import json
from urllib.parse import urlsplit

import pytest
from helpers import TOKEN, flat, login_keys, make_app, seen, token_keys, typed
from hypothesis import given
from hypothesis import strategies as st

from kerberos.clock import FakeClock
from kerberos.copy import t
from kerberos.demo.fleet import build_panel
from kerberos.panel import schema
from kerberos.panel.client import (
    CLIENT_TYPE_HEADER,
    FORWARD_HEADERS,
    SCOPES_FIX,
    TOKEN_DAYS,
    TOKEN_NAME,
    PanelClient,
    password_login,
)
from kerberos.panel.errors import PanelError

API = "http://127.0.0.1:3000/api"
LEAVE = ["esc", "esc", "esc"]  # S3 back to S2 (nothing to stop at), S1, out


def strict_panel(**kwargs):
    """The demo fleet on a panel that takes only its own admin and the tokens it knows."""
    panel = build_panel()
    panel.accept_any_token = False
    panel.accept_any_login = False
    for key, value in kwargs.items():
        setattr(panel, key, value)
    return panel


class Recorder:
    """The fake panel, with the headers of every request kept (the log keeps bodies only)."""

    def __init__(self, panel):
        self.panel = panel
        self.requests = []  # (method, path, browser header, authorization)

    def __call__(self, method, url, headers, body, timeout):
        lowered = {k.lower(): v for k, v in headers.items()}
        path = urlsplit(url).path.removeprefix("/api")
        self.requests.append((method, path, lowered.get(CLIENT_TYPE_HEADER),
                              lowered.get("authorization", "")))  # fmt: skip
        return self.panel(method, url, headers, body, timeout)

    def __getattr__(self, name):
        return getattr(self.panel, name)


def made(panel):
    """The API tokens the panel made, as {uuid: {token, name, expiresInDays, scopes}}."""
    return panel.made_tokens


def call(panel, method, path, body=None, token=None, browser=False):
    headers = dict(FORWARD_HEADERS)
    if token:
        headers["authorization"] = f"Bearer {token}"
    if browser:
        headers[CLIENT_TYPE_HEADER] = "browser"
    data = json.dumps(body).encode() if body is not None else None
    status, raw = panel(method, f"{API}{path}", headers, data, 15)
    return status, json.loads(raw) if raw else None


def session_of(panel):
    status, answer = call(panel, "POST", "/auth/login",
                          {"username": "admin", "password": "admin-password"})  # fmt: skip
    assert status == 200
    return answer["response"]["accessToken"]


# -- the fake answers as 2.8.1 and 3.4.11 do (§7.4) ----------------------------------------
@pytest.mark.parametrize(
    "username, password, enabled",
    [("admin", "wrong", True), ("nobody", "admin-password", True),
     ("admin", "admin-password", False)],
)  # fmt: skip
def test_every_failed_login_is_403(username, password, enabled):
    panel = strict_panel(password_enabled=enabled)
    body = {"username": username, "password": password}
    status, answer = call(panel, "POST", "/auth/login", body)
    assert status == 403 and answer["errorCode"] == "A068"
    assert panel.logins == [username], "the panel notes every try"


def test_only_the_admin_login_token_with_the_browser_header_makes_tokens():
    panel = strict_panel()
    body = {"name": "KERBEROS", "expiresInDays": 30, "scopes": ["nodes:read"]}
    api = panel.add_api_token(scopes=("*",))
    assert call(panel, "POST", "/tokens", body, token=api)[0] == 403
    session = session_of(panel)
    status, answer = call(panel, "POST", "/tokens", body, token=session)
    assert status == 403 and "create own API-token" in answer["message"]
    status, answer = call(panel, "POST", "/tokens", body, token=session, browser=True)
    assert status == 201 and answer["response"]["token"] in panel.api_tokens


@pytest.mark.parametrize(
    "body, status",
    [
        ({"name": "KERBEROS", "scopes": ["nodes:read"]}, 400),  # no expiry: required
        ({"name": "KERBEROS", "expiresInDays": 0, "scopes": ["*"]}, 400),
        ({"name": "K", "expiresInDays": 30, "scopes": ["*"]}, 400),  # 2 to 30 characters
        ({"name": "KERBEROS", "expiresInDays": 30, "scopes": ["nodes:fly"]}, 400),  # A229
        ({"name": "KERBEROS", "expiresInDays": 30}, 201),  # scopes default to ['*']
    ],
)
def test_tokens_are_made_as_the_panel_makes_them(body, status):
    panel = strict_panel()
    answer = call(panel, "POST", "/tokens", body, token=session_of(panel), browser=True)
    assert answer[0] == status


@pytest.mark.parametrize("version, status", [("2.8.1", 200), ("3.4.11", 204)])
def test_a_token_is_deleted_as_each_version_answers(version, status):
    panel = strict_panel(version=version, major=int(version[0]))
    session = session_of(panel)
    body = {"name": "KERBEROS", "expiresInDays": 30, "scopes": ["*"]}
    uuid = call(panel, "POST", "/tokens", body, token=session, browser=True)[1]["response"]["uuid"]
    assert call(panel, "DELETE", f"/tokens/{uuid}", token=session, browser=True)[0] == status
    assert call(panel, "DELETE", f"/tokens/{uuid}", token=session, browser=True)[0] == 404


# -- the client (§7.3, step 3) --------------------------------------------------------------
def test_the_client_makes_the_token_of_kerberos_with_the_rights_of_changes():
    panel = strict_panel()
    client = PanelClient(API, panel, FakeClock())
    token, uuid = client.make_token("admin", "admin-password")
    item = made(panel)[uuid]
    assert item == {"token": token, "name": TOKEN_NAME, "expiresInDays": TOKEN_DAYS,
                    "scopes": SCOPES_FIX}  # fmt: skip
    assert TOKEN_NAME == "KERBEROS" and TOKEN_DAYS == 3650
    assert not client.authenticated, "the screen takes the token, after it is saved"
    assert not client.refused and not client.wrote, "nothing the API token did"


def test_the_browser_header_goes_with_the_admin_login_token_only():
    recorder = Recorder(strict_panel())
    client = PanelClient(API, recorder, FakeClock())
    old, _ = client.make_token("admin", "admin-password")
    old_uuid = next(iter(made(recorder.panel)))
    token, _uuid = client.make_token("admin", "admin-password", previous=old_uuid)
    client.set_token(token)
    client.nodes()
    sessions = recorder.panel.sessions
    for method, path, browser, auth in recorder.requests:
        admin = auth.removeprefix("Bearer ") in sessions
        assert (browser == "browser") == admin, (method, path)
        assert admin == path.startswith("/tokens"), (method, path)
    assert ("DELETE", f"/tokens/{old_uuid}") in [r[:2] for r in recorder.requests]
    assert old not in recorder.panel.api_tokens and token in recorder.panel.api_tokens


def test_a_wrong_password_is_not_a_refusal_of_the_token():
    panel = strict_panel()
    client = PanelClient(API, panel, FakeClock())
    client.set_token(panel.add_api_token(TOKEN, scopes=("nodes:read",)))
    with pytest.raises(PanelError) as caught:
        client.make_token("admin", "wrong")
    assert (caught.value.code, caught.value.operation) == ("forbidden", "POST /auth/login")
    assert not client.refused, "settle_token must not forget the saved token for it"


def test_the_tokens_of_the_person_are_never_deleted():
    panel = strict_panel()
    own = panel.add_api_token("rw-own-token", scopes=("*",))
    client = PanelClient(API, panel, FakeClock())
    client.make_token("admin", "admin-password", previous=None)
    assert own in panel.api_tokens
    assert not any(m == "DELETE" for m, _p, _b in panel.log)


def test_auth_status_tells_whether_the_password_is_taken():
    assert password_login({"isLoginAllowed": True,
                           "authentication": {"password": {"enabled": True}}})  # fmt: skip
    assert not password_login({"isLoginAllowed": True,
                               "authentication": {"password": {"enabled": False}}})  # fmt: skip
    assert not password_login({"isLoginAllowed": False, "authentication": None})
    assert password_login({}) and password_login(None), "another version: the login tells"


@given(
    st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(max_size=8),
        lambda inner: (
            st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=8), inner, max_size=3)
        ),
        max_leaves=12,
    )
)
def test_any_answer_is_read_without_a_crash(value):
    assert password_login(value) in (True, False)
    for read in (schema.access_token, schema.api_token):
        try:
            read(value)
        except PanelError as exc:
            assert exc.code == "bad_response"


# -- S2 (§6) ------------------------------------------------------------------------------
def test_s2_signs_in_with_the_login_and_kerberos_makes_its_token():
    panel = strict_panel()
    app, term = make_app(login_keys() + LEAVE, panel=panel)
    app.run("check")
    assert seen(term, t("panel.admin.hint")) and seen(term, t("panel.admin.token_instead"))
    assert seen(term, t("panel.ok", nodes=6, hosts=10)) and seen(term, t("panel.token.made"))
    ((uuid, item),) = made(panel).items()
    state = app.env.state
    assert state.read_panel_token() == item["token"] and state.panel_token_uuid() == uuid
    assert state.panel_token_can_write(), "the rights of changes, whatever the mode"
    assert oct(state.panel_token.stat().st_mode)[-3:] == "600"


def test_the_password_and_the_login_token_reach_no_file_and_no_screen():
    panel = strict_panel()
    app, term = make_app(login_keys(password="s3cret-Passw0rd") + LEAVE, panel=panel)
    panel.credentials = ("admin", "s3cret-Passw0rd")
    app.run("check")
    secrets = ["s3cret-Passw0rd", *panel.sessions]
    assert panel.sessions, "the login happened"
    assert not any(secret in frame for secret in secrets for frame in term.frames)
    token = app.env.state.read_panel_token()
    for path in app.env.state.root.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert not any(secret in text for secret in secrets), path
            assert path == app.env.state.panel_token or token not in text, path


def test_a_wrong_password_says_so_and_the_person_tries_again():
    panel = strict_panel()
    keys = login_keys(password="wrong") + typed("admin-password") + ["enter"] + LEAVE
    app, term = make_app(keys, panel=panel)
    app.run("check")
    error = next(f for f in term.frames if t("panel.err.admin_login") in f)
    assert t("panel.admin.token_instead") in error, "the way to a token of one's own stays"
    assert seen(term, t("panel.ok", nodes=6, hosts=10))
    assert panel.logins == ["admin", "admin"] and len(made(panel)) == 1


def test_the_error_fits_80x24():
    panel = strict_panel()
    app, term = make_app(login_keys(password="wrong") + ["esc"] + LEAVE, panel=panel,
                         width=80, height=24)  # fmt: skip
    app.run("check")
    frame = next(f for f in term.frames if t("panel.err.admin_login") in f)
    lines = frame.splitlines()
    assert len(lines) <= 24 and any(line.strip().startswith("╰") for line in lines)
    assert t("panel.admin.token_instead") in frame and t("panel.admin.login") in frame


def test_the_row_under_the_login_opens_the_token_form_and_esc_comes_back():
    panel = strict_panel()
    panel.add_api_token(TOKEN)
    keys = ["tab", "tab", "enter", "esc"] + login_keys() + LEAVE
    app, term = make_app(keys, panel=panel)
    app.run("check")
    first = next(i for i, f in enumerate(term.frames) if t("panel.token_hint")[:40] in flat(f))
    assert any(t("panel.admin.hint") in flat(f) for f in term.frames[first:]), "back to login"
    assert len(made(panel)) == 1


def test_a_pasted_token_still_works_and_is_kept_without_a_uuid():
    panel = strict_panel()
    panel.add_api_token(TOKEN)
    app, term = make_app(token_keys() + LEAVE, panel=panel)
    app.run("check")
    assert seen(term, t("panel.ok", nodes=6, hosts=10))
    state = app.env.state
    assert state.read_panel_token() == TOKEN and state.panel_token_uuid() is None
    assert not made(panel) and not panel.logins


def test_no_password_login_asks_for_a_token_at_once():
    panel = strict_panel(password_enabled=False)
    panel.add_api_token(TOKEN)
    app, term = make_app(typed(TOKEN) + ["enter"] + LEAVE, panel=panel)
    app.run("check")
    form = next(f for f in term.frames if t("panel.token") in f)
    assert t("panel.admin.disabled") in flat(form) and t("panel.admin.login") not in form
    assert seen(term, t("panel.ok", nodes=6, hosts=10)) and not panel.logins


def test_a_later_run_asks_nothing():
    panel = strict_panel()
    app, _term = make_app(login_keys() + LEAVE, panel=panel)
    app.run("check")
    app, term = make_app(LEAVE, panel=panel, state=app.env.state)
    app.run("fix")
    assert seen(term, t("panel.token.used")) and not seen(term, t("panel.admin.hint"))
    assert not seen(term, t("panel.token.readonly")), "a token KERBEROS made may change"
    assert panel.logins == ["admin"] and len(made(panel)) == 1


def test_a_token_dropped_in_the_panel_is_made_again_on_the_next_login():
    panel = strict_panel()
    app, _term = make_app(login_keys() + LEAVE, panel=panel)
    app.run("check")
    state = app.env.state
    old = state.panel_token_uuid()
    panel.api_tokens.pop(made(panel).pop(old)["token"])  # deleted in the panel's own list
    app, term = make_app(login_keys() + LEAVE, panel=panel, state=state)
    app.run("check")
    assert seen(term, t("panel.token.stale")) and seen(term, t("panel.token.made"))
    assert state.panel_token_uuid() not in (None, old) and len(made(panel)) == 1


def test_a_forgotten_token_of_kerberos_is_deleted_at_the_next_login():
    """§7.3, step 5: the token the panel refused something is forgotten, its uuid stays, and
    the next login deletes it in the panel, so that no token of KERBEROS is left behind."""
    panel = strict_panel()
    app, _term = make_app(login_keys() + LEAVE, panel=panel)
    app.run("check")
    state = app.env.state
    old = state.panel_token_uuid()
    state.forget_panel_token()
    assert state.read_panel_token() is None and state.panel_token_uuid() == old
    app, term = make_app(login_keys() + LEAVE, panel=panel, state=state)
    app.run("check")
    assert not seen(term, t("panel.token.stale")), "nothing saved to go stale"
    assert old not in made(panel) and len(made(panel)) == 1
    assert state.panel_token_uuid() in made(panel)


def test_check_mode_changes_nothing_in_the_panel_but_its_token():
    panel = strict_panel()
    app, _term = make_app(login_keys() + ["enter", "esc", "q", "enter"], panel=panel)
    app.run("check")
    assert panel.mutations == []
    assert [(m, p) for m, p, _b in panel.log if p.startswith("/tokens")] == [("POST", "/tokens")]


def test_the_panel_refusing_to_make_the_token_leads_to_a_pasted_one():
    panel = strict_panel()
    panel.fail("POST", "/tokens", 400)
    panel.add_api_token(TOKEN)
    keys = login_keys() + ["tab", "enter"] + typed(TOKEN) + ["enter"] + LEAVE
    app, term = make_app(keys, panel=panel)
    app.run("check")
    wanted = t("panel.err.token_create", detail="injected")
    assert any(wanted in flat(f) for f in term.frames)
    assert seen(term, t("panel.ok", nodes=6, hosts=10))
    assert app.env.state.read_panel_token() == TOKEN


def test_no_answer_to_making_the_token_is_not_repeated_without_the_person():
    panel = strict_panel()
    panel.fail("POST", "/tokens", "lost")  # made in the panel, the answer lost
    keys = login_keys() + ["esc"] + ["esc"] + LEAVE  # Esc: do not try again
    app, term = make_app(keys, panel=panel)
    app.run("check")
    assert seen(term, t("panel.err.no_response", operation="POST /tokens")[:40])
    assert [p for m, p, _b in panel.log if m == "POST" and p == "/tokens"] == ["/tokens"]
    assert app.env.state.read_panel_token() is None


def test_f_on_s6_asks_nothing_about_a_token_kerberos_made():
    from helpers import S4_KEYS

    keys = login_keys() + ["enter"] + S4_KEYS + ["enter", "enter"]  # S3, S4, summary, whois
    keys += ["f", "enter", "esc", "q", "enter"]  # S6 f, the admin key, out of the plan
    app, term = make_app(keys, height=30)
    app.run("check")
    assert not seen(term, t("panel.token.readonly"))
    assert seen(term, t("access.admin.choose"))


def test_a_wrong_password_after_f_keeps_the_saved_token():
    """S6 `f` with a token pasted for «Проверка»: «Войти заново», a wrong password, Esc.
    The saved token stays: the panel refused the password, not the token."""
    from helpers import S4_KEYS

    panel = strict_panel()
    panel.add_api_token(TOKEN, scopes=("*",))
    keys = token_keys() + ["enter"] + S4_KEYS + ["enter", "enter"]
    keys += ["f", "down", "enter"] + login_keys(password="wrong") + ["esc", "q", "enter"]
    app, term = make_app(keys, panel=panel, height=30)
    app.run("check")
    assert seen(term, t("panel.token.readonly")) and seen(term, t("panel.err.admin_login"))
    assert app.env.state.read_panel_token() == TOKEN


def test_writable_mark_keeps_the_uuid():
    import tempfile
    from pathlib import Path

    from kerberos.state import State

    state = State(Path(tempfile.mkdtemp(prefix="kerberos-test-")))
    uuid = "0b9f8e2a-4c4d-4a7e-9d0a-2b6c1f3e5a77"
    state.write_panel_token("rw-made", False, uuid)
    state.mark_panel_token_writable()
    assert state.panel_token_can_write() and state.panel_token_uuid() == uuid
    state.write_panel_token("rw-pasted", False)
    state.forget_panel_token()
    assert not state.panel_token.exists(), "a pasted token leaves nothing"
