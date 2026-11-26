"""K15: the portal in front of the panel (tech.md §10.10).

Remnawave behind Caddy in Docker gets caddy-security at a secret path; 3x-ui gets its
own random port and secret path. Both wait for the person to log in from a browser and
go back otherwise.
"""

import json

import pytest
from helpers import make_app, seen, typed
from portal_fakes import (
    CADDY_TEXT,
    CADDYFILE,
    COMPOSE,
    COMPOSE_TEXT,
    DOMAIN,
    ENV_PATH,
    FakeCaddy,
)
from test_self_steal_flow import TO_PLAN, store_of

from kerberos.copy import t
from kerberos.demo.fleet import build_host
from kerberos.demo.xui import XUI_MAIN_PID
from kerberos.fixes import portal
from kerberos.flow import EXIT_OK, EXIT_PARTIAL, EXIT_ROLLBACK_FAILED
from kerberos.host import CommandResult, FakeHost
from kerberos.panel.discover import XUI_BIN, XUI_DB

LOGIN, PASSWORD = "portaladmin7", "portal-pass-123"
# `a` twice clears the marks; then the group «Вход в панель» (K23): after the access to
# the servers, the new SSH port and the holes for scanners, on both panels.
ONLY_LAST_ROW = ["a", "a", "home"] + ["down"] * 3
CREDS = ["p"] + typed(LOGIN) + ["enter"] + typed(PASSWORD) + ["enter"] + typed(PASSWORD)
CREDS += ["enter"]
APPLY = ["enter", "enter"]  # S7 → consent, accept
ROLLBACK = ["enter", "enter", "enter"]  # run, changes, consent; no panel sign-in needed
NO_ANSWER = ["tick"] * (portal.LOGIN_WAIT + 1)


def remnawave(extra, fail=(), caddyfile=CADDY_TEXT):
    host = build_host()
    keys = TO_PLAN + ONLY_LAST_ROW + CREDS + APPLY + list(extra)
    app, term = make_app(keys, host=host, height=46)
    caddy = FakeCaddy(host, app.env.prober, caddyfile=caddyfile, fail=fail)
    return app, term, caddy


def portal_change(app, fix_id="panel.portal"):
    run = store_of(app).runs()[0]
    return run, next(c for c in run["changes"] if c["fixId"] == fix_id)


def untouched(host):
    return (host.files[CADDYFILE] == CADDY_TEXT and host.files[COMPOSE] == COMPOSE_TEXT
            and ENV_PATH not in host.files)  # fmt: skip


# -- Remnawave: the portal goes up ------------------------------------------------------
def test_portal_goes_up_and_the_person_logs_in():
    app, term, caddy = remnawave(["enter", "enter"])  # S8: logged in; S9: leave
    assert app.run("fix") == EXIT_OK
    run, change = portal_change(app)
    assert change["state"] == "confirmed" and caddy.portal
    assert len(caddy.route) == portal.ROUTE_LENGTH
    host = app.env.host
    assert "authenticate with kerberosportal" in host.files[CADDYFILE]
    assert "https://sub.example.com" in host.files[CADDYFILE], "other sites stay as they were"
    assert portal.IMAGE in host.files[COMPOSE] and portal.ENV_FILE in host.files[COMPOSE]
    assert host.modes[ENV_PATH] == 0o600
    assert f"AUTHP_ADMIN_SECRET={PASSWORD}" in host.files[ENV_PATH]
    journal = json.dumps(run)
    assert PASSWORD not in journal and caddy.route not in journal
    assert seen(term, t("s9.portal", link=f"https://{DOMAIN}/{caddy.route}"))
    after = {f["checkId"]: f for f in run["findingsAfter"]}
    assert after["panel.public"]["ok"], "the score after sees the portal"
    report = (store_of(app).path(run["runId"]) / "report.md").read_text(encoding="utf-8")
    assert f"https://{DOMAIN}/{caddy.route}" in report and PASSWORD not in report


def test_portal_goes_back_when_the_person_cannot_log_in():
    app, _term, caddy = remnawave(["esc", "enter"])
    assert app.run("fix") == EXIT_PARTIAL
    _run, change = portal_change(app)
    assert (change["state"], change["error"]) == ("rolled_back", "portal_login_failed")
    assert untouched(app.env.host) and not caddy.portal and caddy.ups == 2


def test_three_minutes_without_an_answer_put_everything_back():
    app, _term, caddy = remnawave(NO_ANSWER + ["enter"])
    assert app.run("fix") == EXIT_PARTIAL
    _run, change = portal_change(app)
    assert change["error"] == "portal_login_failed"
    assert untouched(app.env.host) and not caddy.portal


@pytest.mark.parametrize("fail, code", [
    ("pull", "image_pull_failed"),
    ("validate", "caddy_invalid"),
    ("config", "compose_invalid"),
    ("ignore", "portal_check_failed"),
    ("leak", "portal_check_failed"),
])  # fmt: skip
def test_a_failing_step_leaves_caddy_as_it_was(fail, code):
    app, _term, caddy = remnawave(["enter"], fail={fail})
    assert app.run("fix") == EXIT_PARTIAL
    _run, change = portal_change(app)
    assert (change["state"], change["error"]) == ("rolled_back", code)
    assert untouched(app.env.host) and not caddy.portal


def test_caddy_that_does_not_come_up_is_reported_not_rolled_back():
    """The files go back, but Caddy refuses to start either way: a person must look."""
    app, _term, _caddy = remnawave(["enter"], fail={"up"})
    assert app.run("fix") == EXIT_ROLLBACK_FAILED
    _run, change = portal_change(app)
    assert change["error"] == "rollback_failed"
    assert change["details"]["rollbackError"] == "compose_failed"
    assert app.env.host.files[CADDYFILE] == CADDY_TEXT, "the files went back all the same"


def test_kerberos_rollback_puts_caddy_back():
    app, _term, caddy = remnawave(["enter", "enter"])
    assert app.run("fix") == EXIT_OK
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_OK
    _run, change = portal_change(app)
    assert change["state"] == "rolled_back"
    assert untouched(app.env.host) and not caddy.portal


def test_rollback_asks_before_overwriting_a_caddyfile_edited_later():
    app, term, caddy = remnawave(["enter", "enter"])
    assert app.run("fix") == EXIT_OK
    edited = app.env.host.files[CADDYFILE] + "# a line of the person\n"
    app.env.host.files[CADDYFILE] = edited
    app.env.terminal.feed(*ROLLBACK, "esc", "esc", "x")  # leave the diff, refuse, close
    assert app.run("rollback") == EXIT_ROLLBACK_FAILED
    assert app.env.host.files[CADDYFILE] == edited and caddy.portal
    assert seen(term, t("rb.diff.question"))


# -- Remnawave: S7 ----------------------------------------------------------------------
def test_the_portal_row_waits_for_its_login():
    host = build_host()
    keys = TO_PLAN + ONLY_LAST_ROW + ["space", "enter", "esc", "q", "enter"]
    app, term = make_app(keys, host=host, height=46)
    FakeCaddy(host, app.env.prober)
    app.run("fix")
    assert seen(term, t("fix.panel.portal.label")) and seen(term, t("plan.portal.none"))
    assert seen(term, t("plan.need_portal"))
    assert not any(c[:2] == ("docker", "compose") and "up" in c for c in host.calls)


def test_bad_logins_and_passwords_are_refused_in_the_form():
    host = build_host()
    keys = TO_PLAN + ONLY_LAST_ROW + ["p"] + typed("Admin") + ["enter"] + typed(PASSWORD)
    keys += ["enter"] + typed(PASSWORD) + ["enter"]  # an upper-case login
    keys += ["esc", "esc", "q", "enter"]
    app, term = make_app(keys, host=host, height=46)
    FakeCaddy(host, app.env.prober)
    app.run("fix")
    assert seen(term, t("plan.portal.bad_login"))


def test_the_portal_row_is_never_marked_by_default_or_by_a():
    host = build_host()
    app, term = make_app(TO_PLAN + ["a", "esc", "q", "enter"], host=host, height=46)
    FakeCaddy(host, app.env.prober)
    app.run("fix")
    rows = [line for frame in term.frames if t("plan.title") in frame.splitlines()[0]
            for line in frame.splitlines() if t("area.panel_login") in line]  # fmt: skip
    assert rows and all("[ ]" in line for line in rows), "unmarked by default and after `a`"


# -- Remnawave: finding the scheme ------------------------------------------------------
def caddy_host(caddyfile=CADDY_TEXT):
    host = build_host()

    class Prober:
        responder = None

    FakeCaddy(host, Prober(), caddyfile=caddyfile)
    return host


def test_detection_finds_the_scheme_of_the_docs():
    found = portal.detect_caddy(caddy_host(), DOMAIN)
    assert found["proxy"] == "caddy" and found["service"] == "caddy"
    assert found["caddyfile"] == CADDYFILE and found["composeFile"] == COMPOSE


@pytest.mark.parametrize("caddyfile, proxy", [
    (CADDY_TEXT.replace("\treverse_proxy", "\tbasic_auth {\n\t\tadmin hash\n\t}\n\treverse_proxy"),
     "protected"),
    (CADDY_TEXT.replace("\treverse_proxy * http://remnawave:3000",
                        "\thandle /x {\n\t\trespond 204\n\t}\n\treverse_proxy remnawave:3000"),
     "custom"),
    (CADDY_TEXT.replace("panel.example.com", "other.example.net"), "custom"),
])  # fmt: skip
def test_detection_leaves_other_caddyfiles_alone(caddyfile, proxy):
    assert portal.detect_caddy(caddy_host(caddyfile), DOMAIN)["proxy"] == proxy


def test_no_caddy_no_fix_the_finding_stays_manual():
    assert portal.detect_caddy(build_host(), DOMAIN) == {"proxy": "none"}
    from demo_input import demo_input

    from kerberos.checks import run_checks

    _env, data = demo_input()
    found = next(f for f in run_checks(data) if f["checkId"] == "panel.public")
    assert not found["ok"] and found["fixId"] is None and found["evidence"]["proxy"] == "none"


def test_new_caddyfile_keeps_other_sites_and_is_not_applied_twice():
    new = portal.portal_caddyfile(CADDY_TEXT, DOMAIN, "/data/x.json")
    assert new is not None and new.startswith("{\n\torder authenticate before respond")
    assert "https://sub.example.com {\n\treverse_proxy * http://remnawave-subscription-page:3010"\
        in new  # fmt: skip
    assert new.count("reverse_proxy http://remnawave:3000") == 3
    blocks = portal.split_blocks(new)
    assert blocks is not None and len(blocks) == 4
    assert portal.portal_caddyfile(new, DOMAIN, "/data/x.json") is None, "a barrier is there"
    handle_order = [line.strip() for line in new.splitlines() if line.strip().startswith("handle")]
    assert handle_order[:3] == ["handle @kerberos_login {",
                                "handle /{$REMNAWAVE_CUSTOM_LOGIN_ROUTE}* {",
                                "handle_path /restricted* {"]  # fmt: skip


def test_compose_edit_keeps_the_layout():
    new = portal.compose_with_portal(COMPOSE_TEXT, "caddy")
    assert f"        image: {portal.IMAGE}\n        env_file:\n          - {portal.ENV_FILE}\n" \
        in new  # fmt: skip
    assert portal.compose_with_portal(new, "caddy") == new, "the env file is listed once"
    listed = COMPOSE_TEXT.replace(
        "        restart: always\n",
        "        restart: always\n        env_file:\n          - a.env\n",
    )
    assert "- a.env\n          - kerberos-portal.env" in portal.compose_with_portal(listed, "caddy")
    inline = COMPOSE_TEXT.replace("        restart: always\n", "        env_file: [a.env]\n")
    assert portal.compose_with_portal(inline, "caddy") is None
    assert portal.compose_with_portal(COMPOSE_TEXT, "nginx") is None


@pytest.mark.parametrize("password, ok", [
    ("portal-pass-123", True), ("short", False), ("with space1", False),
    ("dollar$sign1", False), ("quote'mark1", False), ("hash#mark12", False),
])  # fmt: skip
def test_passwords_the_env_file_can_carry(password, ok):
    assert bool(portal.PASSWORD_RE.fullmatch(password)) is ok


# -- 3x-ui: its own port and secret path ------------------------------------------------
XUI_TO_PLAN = ["down", "enter"] + typed("admin") + ["enter"] + typed("pw") + ["enter"]
XUI_TO_PLAN += ["enter", "enter", "enter"]  # S2, S4 summaries, S6 → S7


def xui(extra, height=44, host=None):
    keys = XUI_TO_PLAN + ONLY_LAST_ROW + ["space"] + APPLY + list(extra)
    app, term = make_app(keys, panel_kind=None, height=height, host=host)
    return app, term


def test_xui_panel_moves_and_the_person_logs_in():
    app, term = xui(["enter", "enter"])
    assert app.run("fix") == EXIT_OK
    run, change = portal_change(app, "xui.panel_hide")
    settings = app.env.host.databases[XUI_DB]
    panel = app.env.xui_transport
    assert change["state"] == "confirmed"
    assert settings["webPort"] == str(change["details"]["newPort"]) != "2053"
    path = settings["webBasePath"]
    assert len(path.strip("/")) == portal.ROUTE_LENGTH and panel.base == path
    assert panel.port == change["details"]["newPort"]
    assert path.strip("/") not in json.dumps(run), "the secret path stays out of run.json"
    after = {f["checkId"]: f for f in run["findingsAfter"]}
    assert after["xui.panel_exposed"]["ok"], "KERBEROS read the panel at its new address"
    assert seen(term, path.strip("/"))
    assert ("kill", "-HUP", XUI_MAIN_PID) in app.env.host.calls


def test_xui_panel_goes_back_when_the_person_cannot_log_in():
    app, _term = xui(["esc", "enter"])
    assert app.run("fix") == EXIT_PARTIAL
    _run, change = portal_change(app, "xui.panel_hide")
    settings = app.env.host.databases[XUI_DB]
    assert (change["state"], change["error"]) == ("rolled_back", "portal_login_failed")
    assert (settings["webPort"], settings["webBasePath"]) == ("2053", "/")
    assert (app.env.xui_transport.port, app.env.xui_transport.base) == (2053, "/")


def test_a_setting_that_does_not_stick_changes_nothing():
    from kerberos.demo.fleet import build_host as demo_host

    host = demo_host()
    app, _term = xui(["enter"], host=host)
    host.on([XUI_BIN, "setting"], CommandResult(0, "Failed to set port\n"))  # exits 0 anyway
    assert app.run("fix") == EXIT_PARTIAL
    _run, change = portal_change(app, "xui.panel_hide")
    assert change["error"] == "xui_setting_failed"
    assert app.env.host.databases[XUI_DB]["webPort"] == "2053"


def test_xui_port_pinned_by_the_unit_moves_only_the_path():
    from kerberos.demo.fleet import build_host as demo_host

    host = demo_host()
    host.files["/etc/default/x-ui"] = "XUI_PORT=2053\n"
    app, _term = xui(["enter", "enter"], host=host)
    assert app.run("fix") == EXIT_OK
    _run, change = portal_change(app, "xui.panel_hide")
    settings = app.env.host.databases[XUI_DB]
    assert change["params"]["port"] is None and settings["webPort"] == "2053"
    assert settings["webBasePath"] != "/"


def test_kerberos_rollback_puts_the_xui_panel_back():
    app, _term = xui(["enter", "enter"])
    assert app.run("fix") == EXIT_OK
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_OK
    settings = app.env.host.databases[XUI_DB]
    assert (settings["webPort"], settings["webBasePath"]) == ("2053", "/")


def test_hup_goes_to_the_main_process_only():
    host = FakeHost()
    host.on(["systemctl", "show"], CommandResult(0, "777\n"))
    host.on(["kill"], CommandResult(0))
    assert portal.xui_hup(host)
    assert ("kill", "-HUP", "777") in host.calls
    assert not any(c[:2] == ("systemctl", "kill") for c in host.calls), "Xray is in the cgroup"


def test_xui_panel_row_is_never_marked_by_default_or_by_a():
    keys = XUI_TO_PLAN + ["a", "esc", "q", "enter"]
    app, term = make_app(keys, panel_kind=None, height=44)
    app.run("fix")
    rows = [line for frame in term.frames if t("plan.title") in frame.splitlines()[0]
            for line in frame.splitlines() if t("area.panel_login") in line]  # fmt: skip
    assert rows and all("[ ]" in line for line in rows)


def test_masking_hides_the_secret_path_on_screen_and_in_the_report():
    host = build_host()
    keys = TO_PLAN + ONLY_LAST_ROW + CREDS + APPLY + ["enter", "enter"]
    app, term = make_app(keys, host=host, height=46, mask=True)
    caddy = FakeCaddy(host, app.env.prober)
    assert app.run("fix") == EXIT_OK
    assert caddy.portal and caddy.route
    assert not any(caddy.route in frame for frame in term.frames)
    run = store_of(app).runs()[0]
    report = (store_of(app).path(run["runId"]) / "report.md").read_text(encoding="utf-8")
    assert caddy.route not in report


def test_arm64_server_gets_no_portal_the_image_is_amd64_only():
    host = caddy_host()
    host.on(["uname", "-m"], CommandResult(0, "aarch64\n"))
    assert portal.detect_caddy(host, DOMAIN) == {"proxy": "arch"}


# -- the review of K15 -------------------------------------------------------------------
def test_ctrl_c_at_the_login_prompt_rolls_back_and_stops():
    from kerberos.flow import EXIT_INTERRUPTED

    app, _term, caddy = remnawave(["ctrl-c", "enter"])
    assert app.run("fix") == EXIT_INTERRUPTED
    _run, change = portal_change(app)
    assert (change["state"], change["error"]) == ("rolled_back", "portal_login_failed")
    assert untouched(app.env.host) and not caddy.portal


def test_q_at_the_login_prompt_is_no_way_out():
    app, _term, caddy = remnawave(["q", "esc", "enter"])  # q is ignored; Esc says no
    assert app.run("fix") == EXIT_PARTIAL
    _run, change = portal_change(app)
    assert change["error"] == "portal_login_failed" and untouched(app.env.host)


def test_an_unexpected_error_rolls_the_portal_back():
    app, _term, caddy = remnawave(["enter"])
    host = app.env.host
    plain_write = host.write_text

    def broken(path, text, mode=None):
        if path == CADDYFILE and "authenticate with" in text:
            raise OSError("disk full")
        plain_write(path, text, mode)

    host.write_text = broken
    assert app.run("fix") == EXIT_PARTIAL
    _run, change = portal_change(app)
    assert (change["state"], change["error"]) == ("rolled_back", "internal_error")
    assert untouched(host) and not caddy.portal


def test_a_failed_config_check_does_not_restart_caddy():
    app, _term, caddy = remnawave(["enter"], fail={"config"})
    assert app.run("fix") == EXIT_PARTIAL
    assert untouched(app.env.host) and caddy.ups == 0


def test_the_report_names_no_portal_login():
    app, _term, _caddy = remnawave(["enter", "enter"])
    assert app.run("fix") == EXIT_OK
    run = store_of(app).runs()[0]
    report = (store_of(app).path(run["runId"]) / "report.md").read_text(encoding="utf-8")
    assert LOGIN not in report and LOGIN not in json.dumps(run)


def test_a_marks_no_portal_row_even_with_its_login():
    host = build_host()
    keys = TO_PLAN + ONLY_LAST_ROW + CREDS + ["a", "a", "esc", "q", "enter"]
    app, term = make_app(keys, host=host, height=46)
    FakeCaddy(host, app.env.prober)
    app.run("fix")
    plan = [f for f in term.frames if t("plan.title") in f]
    row = [line for line in plan[-1].splitlines() if t("area.panel_login") in line]
    assert row and "[✓]" in row[0], "`a` twice leaves the portal row as the person set it"


def test_masked_prompt_says_where_the_full_link_is():
    host = build_host()
    keys = TO_PLAN + ONLY_LAST_ROW + CREDS + APPLY + ["enter", "enter"]
    app, term = make_app(keys, host=host, height=46, mask=True)
    FakeCaddy(host, app.env.prober)
    assert app.run("fix") == EXIT_OK
    assert seen(term, "Ссылка скрыта маскировкой")


def test_two_blocks_for_the_panel_domain_are_left_alone():
    two = CADDY_TEXT + "\nhttp://panel.example.com {\n\treverse_proxy remnawave:3000\n}\n"
    assert portal.portal_caddyfile(two, DOMAIN, "/data/x.json") is None


def test_the_token_bypass_keeps_login_and_status_behind_the_portal():
    new = portal.portal_caddyfile(CADDY_TEXT, DOMAIN, "/data/x.json")
    matcher = new[new.index("@kerberos_token {") : new.index("}", new.index("@kerberos_token {"))]
    assert "not path /api/auth/*" in matcher and 'header Authorization "Bearer *"' in matcher


def test_a_quoted_hash_is_no_comment():
    noted = CADDY_TEXT.replace(
        "\treverse_proxy * http://remnawave:3000",
        '\theader X-Note "a#b"\n\treverse_proxy * http://remnawave:3000',
    )
    new = portal.portal_caddyfile(noted, DOMAIN, "/data/x.json")
    assert new is not None and '\theader X-Note "a#b"\n' in new


@pytest.mark.parametrize(
    "extra", ["import common.caddy\n", "\ttls /etc/ssl/a.pem /etc/ssl/a.key\n"]
)
def test_files_the_validation_cannot_see_are_left_alone(extra):
    text = CADDY_TEXT.replace(
        "\treverse_proxy * http://remnawave-subscription-page:3010\n",
        extra + "\treverse_proxy * http://remnawave-subscription-page:3010\n",
    )
    assert portal.portal_caddyfile(text, DOMAIN, "/data/x.json") is None


def test_compose_v1_only_is_left_alone():
    host = caddy_host()
    host.on(["docker", "compose", "version"], CommandResult(1, "", "unknown command"))
    assert portal.detect_caddy(host, DOMAIN)["proxy"] == "custom"


def test_compact_env_file_list_gets_the_env_file_at_its_indent():
    compact = COMPOSE_TEXT.replace(
        "        restart: always\n", "        restart: always\n        env_file:\n        - a.env\n"
    )
    new = portal.compose_with_portal(compact, "caddy")
    assert "        env_file:\n        - a.env\n        - kerberos-portal.env\n" in new


def test_xui_link_names_the_panel_domain():
    from kerberos.demo.fleet import build_host as demo_host

    host = demo_host()
    app, term = xui(["enter", "enter"], host=host)
    host.databases[XUI_DB]["webDomain"] = "panel-xui.example.com"
    app.env.xui_transport.domain = "panel-xui.example.com"
    assert app.run("fix") == EXIT_OK
    _run, change = portal_change(app, "xui.panel_hide")
    assert seen(term, f"panel-xui.example.com:{change['details']['newPort']}/")


def test_findings_after_a_3x_ui_move_see_no_stray_old_port():
    app, _term = xui(["enter", "enter"])
    assert app.run("fix") == EXIT_OK
    run = store_of(app).runs()[0]
    after = next(f for f in run["findingsAfter"] if f["checkId"] == "ports.public")
    assert not any(str(p).startswith("2053") for p in after["evidence"].get("ports", []))


def test_whole_rollback_on_3x_ui_after_a_panel_move_and_a_self_steal():
    from kerberos.demo.xui import XUI_DOMAIN

    keys = XUI_TO_PLAN + ["a", "a", "end", "d"] + list(XUI_DOMAIN) + ["enter"]
    keys += ONLY_LAST_ROW[2:] + ["space"] + APPLY + ["enter", "enter"]
    app, _term = make_app(keys, panel_kind=None, height=44)
    assert app.run("fix") == EXIT_OK
    run, _change = portal_change(app, "xui.panel_hide")
    assert any(c["fixId"] == "xui.reality" and c["state"] == "applied" for c in run["changes"])
    login = typed("admin") + ["enter"] + typed("pw") + ["enter"]
    app.env.terminal.feed("enter", "enter", "enter", *login, "x")
    assert app.run("rollback") == EXIT_OK
    reality = app.env.xui_transport.stream(1)["realitySettings"]
    assert XUI_DOMAIN not in reality.get("serverNames", [])
    settings = app.env.host.databases[XUI_DB]
    assert (settings["webPort"], settings["webBasePath"]) == ("2053", "/")
