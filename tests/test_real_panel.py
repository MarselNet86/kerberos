"""K14: KERBEROS against the real Remnawave 2.8.1 and 3.4.11 (tech.md v19, §7, §10.4–§10.9).

Each test covers what the first run on a live panel and a read of the backend's
source showed: the fake panel used to accept what the real one refuses.
"""

import re
import string

from helpers import TOKEN, make_app, seen, token_keys
from hypothesis import given
from hypothesis import strategies as st
from test_self_steal_flow import (
    APPLY,
    NL1_SELF_STEAL,
    TO_PLAN,
    domain_keys,
    fleet,
    profile_of,
    run_fix,
    store_of,
)

from kerberos.clock import FakeClock
from kerberos.copy import t
from kerberos.demo.fleet import build_panel
from kerberos.flow import EXIT_OK, EXIT_PARTIAL
from kerberos.panel.client import SCOPES_CHECK, PanelClient
from kerberos.panel.errors import PanelError

ROLLBACK = ["enter", "enter", "enter", "x"]  # run, changes, consent, close; the saved token
API = "http://127.0.0.1:3000/api"


def logged_in(panel):
    client = PanelClient(API, panel, FakeClock())
    client.set_token(panel.add_api_token())
    return client


def on_2_8(panel):
    panel.version, panel.major = "2.8.1", 2
    return panel


def host_named(panel, remark):
    return next(h for h in panel.hosts if h["remark"] == remark)


def units(text):
    return len(text.encode("utf-16-le")) // 2


# -- the fake answers as the real panel does (§7.3, §7.4) ---------------------------------
def test_fake_refuses_the_admin_login_token_without_the_browser_header():
    panel = build_panel()
    status, raw = panel("POST", f"{API}/auth/login", fake_headers(),
                        b'{"username": "admin", "password": "admin-password"}', 15)  # fmt: skip
    import json

    session = json.loads(raw)["response"]["accessToken"]
    headers = {**fake_headers(), "authorization": f"Bearer {session}"}
    status, raw = panel("GET", f"{API}/nodes", headers, None, 15)
    assert status == 403 and b"create own API-token" in raw
    status, _raw = panel("GET", f"{API}/nodes", {**headers, "X-Remnawave-Client-Type": "browser"},
                         None, 15)  # fmt: skip
    assert status == 200


def fake_headers():
    from kerberos.panel.client import FORWARD_HEADERS

    return dict(FORWARD_HEADERS)


def test_fake_checks_the_scopes_of_an_api_token():
    panel = build_panel()
    client = PanelClient(API, panel, FakeClock())
    client.set_token(panel.add_api_token(scopes=("nodes:read", "hosts:read")))
    assert client.nodes() and client.hosts()
    try:
        client.profiles()
        raise AssertionError("config-profiles:read was not given")
    except PanelError as exc:
        assert exc.code == "forbidden" and exc.operation == "GET /config-profiles"
    host = panel.hosts[0]
    try:
        client.patch_host(host["uuid"], {"fingerprint": "firefox"})
        raise AssertionError("hosts:write was not given")
    except PanelError as exc:
        assert exc.code == "forbidden" and exc.operation == "PATCH /hosts"


# -- 3.4.11 answers bulk calls and deletes with 204 and no body (§7.2) ----------------------
def test_bulk_calls_and_deletes_without_a_body_are_success():
    panel = build_panel()  # 3.4.11
    client = logged_in(panel)
    host = host_named(panel, "NL Reality")
    client.disable_hosts([host["uuid"]])
    assert host["isDisabled"] is True
    client.enable_hosts([host["uuid"]])
    assert host["isDisabled"] is False
    client.delete_host(host["uuid"])
    assert host not in panel.hosts


def test_old_hosts_go_back_on_when_the_answer_to_disable_never_came():
    """§10.4 step 4: the list is journaled before the request."""
    panel, nodes = fleet()
    panel.fail("POST", "/hosts/bulk/disable", "lost")  # applied, but no answer
    old = host_named(panel, "NL Reality")
    _app, _term, code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                                panel, nodes)  # fmt: skip
    assert code == EXIT_PARTIAL
    assert old["isDisabled"] is False
    assert not [h for h in panel.hosts if h.get("sni") == "nl-1.example.com"]


# -- 2.8.1 switches a host on when a PATCH lacks isDisabled (§7.4) --------------------------
def test_patching_a_disabled_host_keeps_it_off_on_2_8():
    panel = on_2_8(build_panel())
    client = logged_in(panel)
    host = host_named(panel, "NL Reality")
    client.disable_hosts([host["uuid"]])
    client.patch_host(host["uuid"], {"fingerprint": "firefox"})
    assert host["isDisabled"] is True


def test_old_hosts_stay_off_on_2_8_after_the_panel_fixes():
    panel, nodes = fleet(on_2_8(build_panel()))
    old = host_named(panel, "NL Reality")
    _app, _term, code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                                panel, nodes)  # fmt: skip
    assert code == EXIT_OK
    patched = [b for m, p, b in panel.log if (m, p) == ("PATCH", "/hosts")
               and b["uuid"] == old["uuid"]]  # fmt: skip
    assert patched, "a panel fix wrote to the old host after self-steal switched it off"
    assert old["isDisabled"] is True


# -- template names, remarks and tags within the panel's limits (§7.4, §10.9) ----------------
def test_kerberos_templates_have_names_the_panel_takes():
    panel, nodes = fleet()
    _app, _term, code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                                panel, nodes)  # fmt: skip
    assert code == EXIT_OK
    names = {tpl["name"] for tpl in panel.templates}
    assert {"KERBEROS", "KERBEROS single"} <= names
    assert all(re.fullmatch(r"[A-Za-z0-9_\s-]{2,255}", name) for name in names)


def test_a_long_reality_remark_still_gets_its_hysteria2_host_on_2_8():
    panel, nodes = fleet(on_2_8(build_panel()))
    source = host_named(panel, "NL Reality")
    source["remark"] = "🇳🇱 Amsterdam premium Reality line"  # 34 code units: fits 40
    _app, _term, code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                                panel, nodes)  # fmt: skip
    assert code == EXIT_OK
    hy2 = [h for h in panel.hosts if h["remark"].endswith("Hysteria2")
           and h["address"] == "203.0.113.10"]  # fmt: skip
    assert len(hy2) == 1 and units(hy2[0]["remark"]) <= 40


@given(st.text(max_size=60))
def test_hysteria2_remark_always_fits(base):
    from kerberos.fixes.hosts import fit_remark

    remark = fit_remark(base, " Hysteria2")
    assert 1 <= units(remark) <= 40 and remark.endswith("Hysteria2")


NAME_CHARS = string.ascii_letters + string.digits + "-_ ." + "абвгдежзийклмнопрстуфхцчшщыэюя"


@given(st.text(alphabet=NAME_CHARS, min_size=1, max_size=60))
def test_pair_tags_always_fit_the_panel(name):
    from kerberos.fixes.subscription import pair_tags

    for tag in pair_tags(name).values():
        assert re.fullmatch(r"[A-Z0-9_:]+", tag) and len(tag) <= 32  # 2.2–2.7: 32


def test_long_names_with_one_start_get_different_pair_tags():
    from kerberos.fixes.subscription import pair_tags

    a = pair_tags("netherlands-amsterdam-premium-1")
    b = pair_tags("netherlands-amsterdam-premium-2")
    assert a["vless"] != b["vless"] and max(len(x) for x in [*a.values(), *b.values()]) <= 32


# -- a copy shows the domain to clients (§10.4 step 3) ---------------------------------------
def test_a_copy_turns_keep_sni_blank_off():
    panel, nodes = fleet()
    host_named(panel, "NL Reality")["keepSniBlank"] = True  # the panel would send an empty SNI
    _app, _term, code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                                panel, nodes)  # fmt: skip
    assert code == EXIT_OK
    copies = [h for h in panel.hosts if h.get("sni") == "nl-1.example.com"]
    assert copies and all(h["keepSniBlank"] is False for h in copies)


# -- what a client gets is the host's extra, or else the inbound's (§10.6) ------------------
def fi1_inbound(panel):
    profile = next(p for p in panel.profiles if p["name"] == "FI-1")
    return next(i for i in profile["config"]["inbounds"] if i["tag"] == "XHTTP-FI1")


def inherit(panel, extra):
    """The CDN host hands out the inbound's extra, which is `extra`."""
    host_named(panel, "FI CDN")["xhttpExtraParams"] = None
    fi1_inbound(panel)["streamSettings"]["xhttpSettings"]["extra"] = extra


def fix_findings(panel):
    """The findings of a fix run that stops on S7."""
    from test_xhttp_cdn_flow import LEAVE, last_run
    from test_xhttp_cdn_flow import run_fix as xhttp_fix

    app, _term, _code, _panel, _nodes = xhttp_fix(LEAVE, panel=panel)
    return [f for f in last_run(app)["findings"]]


def test_xhttp_checks_read_the_extra_a_client_gets():
    from kerberos.fixes.xhttp import padding_fields

    panel = build_panel()
    import random

    pad = padding_fields(random.Random(1))
    inherit(panel, {"noSSEHeader": True, "uplinkHTTPMethod": "GET",
                    "scMaxEachPostBytes": 20000, **pad})  # fmt: skip
    found = fix_findings(panel)
    by_check = {}
    for item in found:
        by_check.setdefault(item["checkId"], []).append(item)
    assert by_check["xhttp.padding"] and all(f["ok"] for f in by_check["xhttp.padding"])
    assert by_check["xhttp.uplink_get"] and all(f["ok"] for f in by_check["xhttp.uplink_get"])
    assert by_check["xhttp.post_size"] and all(f["ok"] for f in by_check["xhttp.post_size"])


def test_padding_leaves_a_host_that_follows_its_inbound_alone():
    from test_xhttp_cdn_flow import APPLY as X_APPLY
    from test_xhttp_cdn_flow import run_fix as xhttp_fix

    panel = build_panel()
    inherit(panel, {"noSSEHeader": True, "uplinkHTTPMethod": "GET"})
    _app, _term, code, panel, _nodes = xhttp_fix(X_APPLY, panel=panel)
    assert code == EXIT_OK
    server = fi1_inbound(panel)["streamSettings"]["xhttpSettings"]["extra"]
    assert "xPaddingBytes" in server and server["noSSEHeader"] is True
    assert host_named(panel, "FI CDN")["xhttpExtraParams"] is None  # gets the server's own


def test_uplink_get_copies_the_inbound_extra_and_rollback_gives_it_back():
    from test_xhttp_cdn_flow import APPLY as X_APPLY
    from test_xhttp_cdn_flow import run_fix as xhttp_fix

    panel = build_panel()
    xmux = {"maxConcurrency": "16-32", "hMaxReusableSecs": "1800-3000"}
    inherit(panel, {"noSSEHeader": True, "xmux": xmux})
    original = dict(fi1_inbound(panel)["streamSettings"]["xhttpSettings"]["extra"])
    app, _term, code, panel, _nodes = xhttp_fix(X_APPLY, panel=panel)
    assert code == EXIT_OK
    host = host_named(panel, "FI CDN")
    server = fi1_inbound(panel)["streamSettings"]["xhttpSettings"]["extra"]
    assert host["xhttpExtraParams"] == {**server, "uplinkHTTPMethod": "GET"}
    assert host["xhttpExtraParams"]["xmux"] == xmux  # not lost to the host's own extra
    app.env.terminal.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_OK
    assert host["xhttpExtraParams"] is None
    assert fi1_inbound(panel)["streamSettings"]["xhttpSettings"]["extra"] == original


# -- the panel stores a profile normalized (§10.4 step 2) ------------------------------------
MANAGED = ("vless", "trojan", "shadowsocks", "hysteria")


def normalized(config):
    """As the panel saves a profile: clients emptied, serverNames split and deduplicated
    (both from its XRayConfig), and its sort, which may reorder lists: inbounds by tag."""
    import copy

    config = copy.deepcopy(config)
    for inbound in config.get("inbounds") or []:
        if inbound.get("protocol") in MANAGED:
            inbound.setdefault("settings", {})["clients"] = []
        reality = (inbound.get("streamSettings") or {}).get("realitySettings") or {}
        if reality.get("serverNames"):
            names = [part.strip() for name in reality["serverNames"] for part in name.split(",")]
            reality["serverNames"] = list(dict.fromkeys(names))
    config["inbounds"] = sorted(config.get("inbounds") or [], key=lambda i: str(i.get("tag")))
    return config


def test_rollback_of_a_normalized_profile_does_not_ask():
    panel, nodes = fleet(build_panel())
    panel.normalize_profile = normalized
    before = profile_of(panel, "nl-1")["config"]
    app, term, code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                              panel, nodes)  # fmt: skip
    assert code == EXIT_OK
    app.env.terminal.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_OK
    assert not seen(term, t("rb.diff.question"))
    by_tag = {i["tag"]: i for i in profile_of(panel, "nl-1")["config"]["inbounds"]}
    assert by_tag == {i["tag"]: i for i in normalized(before)["inbounds"]}


def test_rollback_after_a_normalized_finalization_does_not_ask():
    """Finalization sends what it read from the panel, so this guards the path rather than
    showing the panel's normalization: the profile written is the panel's answer (§10.4)."""
    from kerberos.demo.fleet import build_host
    from kerberos.fixes.finalize import unattended
    from kerberos.host import CommandResult

    panel, nodes = fleet(build_panel())
    panel.normalize_profile = normalized
    host = build_host()
    host.on(["systemd-run"], CommandResult(0))
    keys = TO_PLAN + domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY
    app, term = make_app(keys, panel=panel, nodes=list(nodes.values()), height=46, host=host)
    assert app.run("fix") == EXIT_OK
    store = store_of(app)
    app.env.clock.advance(24 * 3600 + 1)
    assert unattended(store, panel, app.env.clock, store.runs()[0]["runId"]) == 0
    app.env.terminal.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_OK
    assert not seen(term, t("rb.diff.question"))


# -- a token without write rights: S8 says so in words (§7.5) -------------------------------
def test_a_read_only_token_fails_panel_fixes_with_a_reason():
    panel, nodes = fleet()
    panel.accept_any_token = False
    panel.add_api_token(TOKEN, scopes=tuple(SCOPES_CHECK))
    import copy

    before = copy.deepcopy((panel.hosts, panel.templates, panel.sub_settings, panel.profiles))
    _app, term, code = run_fix(APPLY, panel, nodes, keys_before=token_keys())  # pasted (K30)
    assert code == EXIT_PARTIAL, "refused writes leave nothing to roll back: not exit 5"
    assert seen(term, t("error.forbidden"))
    assert (panel.hosts, panel.templates, panel.sub_settings, panel.profiles) == before


def test_a_token_refused_a_change_is_forgotten_and_the_next_run_asks():
    panel, nodes = fleet()
    panel.accept_any_token = False
    panel.add_api_token(TOKEN, scopes=tuple(SCOPES_CHECK))
    app, _term, _code = run_fix(APPLY, panel, nodes, keys_before=token_keys())  # pasted (K30)
    assert app.env.state.read_panel_token() is None
    panel.add_api_token("rw-full-token")
    keys = token_keys("rw-full-token") + ["esc", "esc", "esc"]
    app, term = make_app(keys, panel=panel, nodes=list(nodes.values()), state=app.env.state)
    app.run("fix")
    assert seen(term, t("panel.admin.hint")) and seen(term, t("panel.token_hint"))
    assert app.env.state.read_panel_token() == "rw-full-token"


# -- review of K14: the token of a check, odd input, retries, the timer, half-landed writes ---
def test_a_token_given_for_the_check_is_asked_about_before_changes():
    panel = build_panel()
    app, _term = make_app(token_keys() + ["esc", "esc", "esc"], panel=panel)  # pasted (K30)
    app.run("check")
    state = app.env.state
    assert not state.panel_token_can_write()
    # «Исправление» later: keep it (Enter), then leave on S3.
    app, term = make_app(["enter", "esc", "esc", "esc"], panel=panel, state=state)
    app.run("fix")
    assert seen(term, t("panel.token.readonly"))
    assert any(t("panel.ok", nodes=6, hosts=10) in f for f in term.frames)
    # Or another one, typed under the rights for changes: it is kept as one for changes.
    keys = ["down", "enter"] + token_keys("rw-full-token") + ["esc", "esc", "esc"]
    app, term = make_app(keys, panel=panel, state=state)
    app.run("fix")
    assert seen(term, t("panel.token_rights.fix"))
    assert state.read_panel_token() == "rw-full-token" and state.panel_token_can_write()


def test_a_kept_token_that_made_a_change_is_not_asked_about_again():
    panel, nodes = fleet()
    app, _term = make_app(token_keys() + ["esc", "esc", "esc"], panel=panel)  # pasted (K30)
    app.run("check")
    state = app.env.state
    keep = ["enter"]  # the token of the check: keep it
    app, _term, code = run_fix(APPLY, panel, nodes, state=state, keys_before=keep)
    assert code == EXIT_OK and state.panel_token_can_write()


def test_a_token_in_another_layout_is_refused_without_a_crash():
    panel = build_panel()
    keys = token_keys("токен") + ["esc", "esc", "esc"]
    app, term = make_app(keys, panel=panel)
    app.run("check")
    assert seen(term, t("panel.err.token"))
    assert app.env.state.read_panel_token() is None


def test_retry_after_no_answer_sends_the_same_token_again():
    panel = build_panel()
    panel.fail("GET", "/nodes", 503, times=4)  # every try of the first request
    keys = token_keys() + ["enter"] + ["esc", "esc", "esc"]  # Enter: «повторить»
    app, term = make_app(keys, panel=panel)
    app.run("check")
    assert any(t("panel.ok", nodes=6, hosts=10) in f for f in term.frames)
    assert app.env.state.read_panel_token() == TOKEN


def test_retry_after_no_answer_keeps_the_token_kerberos_made():
    """K30: the panel made the token, then did not answer GET /nodes: Enter tries the same
    token again, no second login and no second token."""
    from helpers import login_keys

    panel = build_panel()
    panel.fail("GET", "/nodes", 503, times=4)
    app, term = make_app(login_keys() + ["enter"] + ["esc", "esc", "esc"], panel=panel)
    app.run("check")
    assert any(t("panel.ok", nodes=6, hosts=10) in f for f in term.frames)
    assert len(panel.made_tokens) == 1 and panel.logins == ["admin"]
    made = next(iter(panel.made_tokens.values()))["token"]
    assert app.env.state.read_panel_token() == made


def test_the_timer_leaves_a_3x_ui_run_to_the_terminal():
    import tempfile
    from pathlib import Path

    from kerberos.fixes.finalize import unattended
    from kerberos.fixes.journal import RunStore
    from kerberos.state import State

    clock = FakeClock()
    state = State(Path(tempfile.mkdtemp(prefix="kerberos-test-")))
    state.write_panel_token("rw-saved", True)
    store = RunStore(state, clock)
    run = store.new_run("fix", {"kind": "3x-ui", "version": "2.6.0", "api": ""}, [])
    run["pending"] = [{"changeId": "c-1", "action": "finalize", "due": "2026-11-16T12:00:00Z",
                       "panel": "3x-ui", "inbounds": ["1"], "domain": "a.example.com",
                       "nodeName": "local"}]  # fmt: skip
    store.save(run)
    assert unattended(store, build_panel(), clock, None) == 3
    assert store.runs()[0]["pending"], "kerberos finalize in the terminal does it"


def test_a_profile_patch_that_landed_without_an_answer_goes_back():
    panel, nodes = fleet(build_panel())
    panel.normalize_profile = normalized
    before = profile_of(panel, "nl-1")["config"]
    panel.fail("PATCH", "/config-profiles", "applied:500", times=4)  # stored, then 500
    _app, _term, code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                                panel, nodes)  # fmt: skip
    assert code == EXIT_PARTIAL, "the self-steal went back, nothing stayed in place"
    by_tag = {i["tag"]: i for i in profile_of(panel, "nl-1")["config"]["inbounds"]}
    assert by_tag == {i["tag"]: i for i in normalized(before)["inbounds"]}


def test_a_token_refused_in_a_rollback_is_forgotten():
    panel, nodes = fleet()
    app, _term, code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                               panel, nodes)  # fmt: skip
    assert code == EXIT_OK
    panel.accept_any_token = False
    panel.add_api_token("rw-hosts-only", scopes=("nodes:read", "hosts:*"))
    app.env.state.write_panel_token("rw-hosts-only", True)
    app.env.terminal.feed(*ROLLBACK)
    app.run("rollback")
    assert app.env.state.read_panel_token() is None
