"""Self-steal end to end on the demo fleet (tech.md §10.4, §10.9, K6)."""

import json

from helpers import S4_KEYS, login_keys, make_app, on, seen

from kerberos.checks import spec
from kerberos.copy import t
from kerberos.demo.fleet import build_nodes, build_panel
from kerberos.fixes.finalize import due_items, unattended
from kerberos.fixes.hosts import FINGERPRINTS
from kerberos.fixes.journal import RunStore
from kerberos.fixes.profile import server_names
from kerberos.flow import EXIT_OK, EXIT_PARTIAL, EXIT_ROLLBACK_FAILED

TO_PLAN = login_keys() + ["enter"] + S4_KEYS + ["enter", "enter"]  # S3, S4, admin key
TO_PLAN += ["enter", "enter", "enter"]  # S4 summary, whois, S6 → S7
NL1_SELF_STEAL, NL2_SELF_STEAL = "nl-1", "nl-2"  # rows of the block «Свой домен» (K23)


def domain_keys(node, domain):
    return on(node, "self_steal", "d", *domain, "enter")


def fleet(panel=None, nodes=None):
    panel = panel or build_panel()
    nodes = nodes or {n.name: n for n in build_nodes()}
    return panel, nodes


def run_fix(extra, panel, nodes, height=46, state=None, keys_before=None):
    """«Исправление» to S7, then `extra`. With a saved token S2 types none: `keys_before`
    answers its questions instead of the token."""
    start = TO_PLAN if keys_before is None else list(keys_before) + TO_PLAN[len(login_keys()) :]
    app, term = make_app(start + list(extra), panel=panel, nodes=list(nodes.values()),
                         height=height, state=state)  # fmt: skip
    return app, term, app.run("fix")


def store_of(app):
    return RunStore(app.env.state, app.env.clock)


def profile_of(panel, name):
    node = next(n for n in panel.nodes if n["name"] == name)
    ref = node["configProfile"]["activeConfigProfileUuid"]
    return next(p for p in panel.profiles if p["uuid"] == ref)


def reality_of(profile):
    return next(i for i in profile["config"]["inbounds"] if i["protocol"] == "vless"
                and i["streamSettings"]["security"] == "reality")  # fmt: skip


APPLY = ["enter", "enter", "enter"]  # S7 → consent → accept → S9 Enter


def test_self_steal_moves_the_node_to_its_domain():
    panel, nodes = fleet()
    key_before = reality_of(profile_of(panel, "nl-1"))["streamSettings"]["realitySettings"]
    hosts_before = {h["uuid"]: dict(h) for h in panel.hosts}
    app, term, code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                              panel, nodes)  # fmt: skip
    assert code == EXIT_OK
    reality = reality_of(profile_of(panel, "nl-1"))
    settings = reality["streamSettings"]["realitySettings"]
    assert settings["dest"] == "127.0.0.1:8445"
    assert settings["serverNames"] == ["nl-1.example.com", "www.example.net"]
    assert settings["privateKey"] == key_before["privateKey"]
    assert reality["tag"] == "VLESS-REALITY-NL1"
    hy2 = next(i for i in profile_of(panel, "nl-1")["inbounds"] if i["type"] == "hysteria")
    assert any(hy2["uuid"] in [i["uuid"] for i in s["inbounds"]] for s in panel.squads)
    created = [h for h in panel.hosts if h["uuid"] not in hosts_before]
    assert {h["sni"] for h in created} == {"nl-1.example.com"}
    assert all(not h["isDisabled"] and h["fingerprint"] in FINGERPRINTS for h in created)
    old = next(h for h in panel.hosts if h["remark"] == "NL Reality" and h["uuid"] in hosts_before)
    assert old["isDisabled"] is True
    log = [
        (m, p)
        for m, p, _b in panel.log
        if (m, p) in (("POST", "/hosts"), ("POST", "/hosts/bulk/disable"))
    ]
    assert log.index(("POST", "/hosts/bulk/disable")) > max(
        i for i, entry in enumerate(log) if entry == ("POST", "/hosts")
    ), "copies first"
    run = store_of(app).runs()[0]
    assert len(run["pending"]) == 1 and run["pending"][0]["domain"] == "nl-1.example.com"
    for warning in ("fix.self_steal.warning", "fix.profile.warning"):
        assert seen(term, t(warning))
    assert seen(term, t("fix.mount.warning", node="nl-1"))
    report = store_of(app).report_text(run["runId"])
    assert "DEMO_KEY" not in report and "DEMO_KEY" not in json.dumps(run)


def test_dns_must_match_before_applying():
    panel, nodes = fleet()
    keys = domain_keys(NL1_SELF_STEAL, "late.example.com") + ["space", "enter", "esc", "q",
                                                                "enter"]  # fmt: skip
    app, term, _code = run_fix(keys, panel, nodes)
    assert seen(term, t("plan.domain.wait", record="A late.example.com → 203.0.113.10"))
    assert seen(term, t("plan.domain.waiting"))
    assert seen(term, t("plan.need_domain"))
    assert all(m[1] != "/config-profiles" for m in panel.mutations)


def test_dns_is_checked_again_every_10_seconds():
    panel, nodes = fleet()
    keys = domain_keys(NL1_SELF_STEAL, "late.example.com")
    app, term = make_app(TO_PLAN + keys + ["tick"] * 3 + ["enter", "enter", "enter"],
                         panel=panel, nodes=list(nodes.values()), height=46)  # fmt: skip
    app.env.prober.dns["late.example.com"] = ["203.0.113.10"]  # the record appears later
    nodes["nl-1"].state["site"] = None
    code = app.run("fix")
    assert code == EXIT_OK
    assert seen(term, t("plan.domain.ok", domain="late.example.com"))


def test_failure_in_the_middle_undoes_everything():
    panel, nodes = fleet()
    profile_before = json.loads(json.dumps(profile_of(panel, "nl-1")["config"]))
    hosts_before = json.loads(json.dumps(panel.hosts))
    squads_before = json.loads(json.dumps(panel.squads))
    panel.fail("POST", "/hosts/bulk/disable", 500, times=4)
    app, term, code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                              panel, nodes)  # fmt: skip
    assert code == EXIT_PARTIAL
    assert profile_of(panel, "nl-1")["config"] == profile_before
    assert [h["uuid"] for h in panel.hosts] == [h["uuid"] for h in hosts_before]
    assert all(h["isDisabled"] == b["isDisabled"] for h, b in zip(panel.hosts, hosts_before))
    assert [s["inbounds"] for s in panel.squads] != [] and len(panel.squads) == len(squads_before)
    assert [i["uuid"] for i in panel.squads[0]["inbounds"]] == [
        i["uuid"] for i in squads_before[0]["inbounds"]
    ]
    assert nodes["nl-1"].state["site"] is None
    assert nodes["nl-1"].state["facts"]["remnanode"]["letsencryptMounted"] is False
    changes = [c for c in store_of(app).runs()[0]["changes"] if c["params"].get("domain")]
    assert {c["state"] for c in changes} <= {"rolled_back", "failed"}


def test_certificate_failure_changes_nothing_in_the_panel():
    panel, nodes = fleet()
    nodes["nl-1"].state["certbot_fails"] = True
    app, term, code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                              panel, nodes)  # fmt: skip
    assert code == EXIT_PARTIAL
    nl1 = profile_of(panel, "nl-1")["uuid"]
    # fi-1 still gets its XHTTP padding (K8): only nl-1's profile must stay untouched.
    assert not [b for m, p, b in panel.mutations
                if (m, p) == ("PATCH", "/config-profiles") and b["uuid"] == nl1]  # fmt: skip
    touched = {(m, p) for m, p, _b in panel.mutations}
    assert not touched & {("POST", "/hosts"), ("POST", "/hosts/bulk/disable")}
    assert seen(term, t("apply.rolled_back", reason=t("error.certbot_failed")))


def test_check_failure_after_profile_rolls_back():
    panel, nodes = fleet()
    nodes["nl-1"].state["no_site_after"] = True
    original = nodes["nl-1"].handlers["apply"]

    def apply(node, args, params):
        answer = original(node, args, params)
        if args[0] == "self_steal.site":
            node.state["site"] = "elsewhere.example.com"  # the stub is not reachable
        return answer

    nodes["nl-1"].handlers["apply"] = apply
    profile_before = json.loads(json.dumps(profile_of(panel, "nl-1")["config"]))
    app, _term, code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                               panel, nodes)  # fmt: skip
    assert code == EXIT_PARTIAL
    assert profile_of(panel, "nl-1")["config"] == profile_before
    assert app.env.clock.slept.count(5) >= 5, "TLS is asked again while Xray restarts"


def test_rollback_after_success_returns_everything():
    panel, nodes = fleet()
    profile_before = json.loads(json.dumps(profile_of(panel, "nl-1")["config"]))
    hosts_before = {h["uuid"]: h["isDisabled"] for h in panel.hosts}
    app, _term, _code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                                panel, nodes)  # fmt: skip
    app.env.terminal.feed("enter", "enter", "enter")  # run, all changes, consent
    app.env.terminal.feed(*list("admin"), "enter", *list("admin-password"), "enter", "x")
    assert app.run("rollback") == EXIT_OK
    assert profile_of(panel, "nl-1")["config"] == profile_before
    assert {h["uuid"]: h["isDisabled"] for h in panel.hosts} == hosts_before
    assert nodes["nl-1"].state["site"] is None
    assert store_of(app).load(store_of(app).runs()[1]["runId"])["pending"] == []


def test_rollback_asks_when_the_profile_was_edited_by_hand():
    panel, nodes = fleet()
    app, _term, _code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                                panel, nodes)  # fmt: skip
    profile_of(panel, "nl-1")["config"]["log"] = {"loglevel": "debug"}  # someone edited it
    keys = ["enter", "enter", "enter"] + list("admin") + ["enter"] + list("pw") + ["enter"]
    keys += ["esc", "esc", "x"]  # leave the pager, refuse to overwrite, close the result
    app.env.terminal.feed(*keys)
    assert app.run("rollback") == EXIT_ROLLBACK_FAILED
    assert profile_of(panel, "nl-1")["config"]["log"] == {"loglevel": "debug"}
    assert seen(app.env.terminal, t("rb.diff.question"))


def test_finalization_after_a_day_and_twice_changes_nothing():
    panel, nodes = fleet()
    app, _term, _code = run_fix(domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY,
                                panel, nodes)  # fmt: skip
    store = store_of(app)
    assert due_items(store, app.env.clock.now()) == []
    app.env.clock.advance(24 * 3600)
    keys = ["enter"] + list("admin") + ["enter"] + list("pw") + ["enter", "enter", "x"]
    keys += ["q", "enter"]
    app.env.terminal.feed(*keys)
    assert app.run() == EXIT_OK
    assert seen(app.env.terminal, t("app.pending", n=1))
    reality = reality_of(profile_of(panel, "nl-1"))
    assert reality["streamSettings"]["realitySettings"]["serverNames"] == ["nl-1.example.com"]
    patches = len([m for m in panel.mutations if m[1] == "/config-profiles"])
    app.env.terminal.feed("x")
    app.run("finalize")
    assert len([m for m in panel.mutations if m[1] == "/config-profiles"]) == patches


def test_unattended_finalization_with_the_saved_token():
    from kerberos.demo.fleet import build_host
    from kerberos.host import CommandResult

    panel, nodes = fleet()
    host = build_host()
    host.on(["systemd-run"], CommandResult(0))  # the timer is set
    keys = TO_PLAN + domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY
    app, term = make_app(keys, panel=panel, nodes=list(nodes.values()), height=46, host=host)
    app.run("fix")
    store = store_of(app)
    run = store.runs()[0]
    assert run["finalizeTimer"] and not (store.path(run["runId"]) / "finalize.token").exists()
    assert any(c[:1] == ("systemd-run",) for c in app.env.host.calls)
    assert seen(term, t("s9.finalize.auto"))
    app.env.clock.advance(24 * 3600 + 1)
    assert unattended(store, panel, app.env.clock, run["runId"]) == 0
    assert server_names(profile_of(panel, "nl-1")["config"]) == ["nl-1.example.com"]
    assert store.runs()[0]["pending"] == []


def test_unattended_finalization_without_a_saved_token_waits_for_the_person():
    from kerberos.demo.fleet import build_host
    from kerberos.host import CommandResult

    panel, nodes = fleet()
    host = build_host()
    host.on(["systemd-run"], CommandResult(0))
    keys = TO_PLAN + domain_keys(NL1_SELF_STEAL, "nl-1.example.com") + APPLY
    app, _term = make_app(keys, panel=panel, nodes=list(nodes.values()), height=46, host=host)
    app.run("fix")
    store = store_of(app)
    app.env.state.panel_token.unlink()  # the person removed it
    app.env.clock.advance(24 * 3600 + 1)
    assert unattended(store, panel, app.env.clock, store.runs()[0]["runId"]) == 3
    assert store.runs()[0]["pending"], "S1 reminds of it"


def test_two_nodes_get_different_stub_sites():
    panel, nodes = fleet()
    keys = domain_keys(NL1_SELF_STEAL, "nl-1.example.com")
    keys += domain_keys(NL2_SELF_STEAL, "nl-2.example.com") + APPLY
    app, _term, code = run_fix(keys, panel, nodes)
    assert code == EXIT_OK
    sites = {n: nodes[n].state["sites"][f"{n}.example.com"]["template"] for n in ("nl-1", "nl-2")}
    assert sites["nl-1"] != sites["nl-2"]
    findings = [f for f in spec("site.same_template").rule(_input_of(app)) if not f["ok"]]
    names = {app.env.state.nodes()[f["target"][5:]].name for f in findings}
    assert not names & {"nl-1", "nl-2"}


def _input_of(app):
    from demo_input import Collector, Progress  # noqa: F401 - reuse the real collector

    from kerberos.panel.client import PanelClient

    client = PanelClient("http://127.0.0.1:3000/api", app.env.panel_transport, app.env.clock)
    client.set_token(app.env.panel_transport.add_api_token())
    snapshot = client.snapshot("2.8.1", "panel.example.com")
    selected = [n.uuid for n in snapshot.nodes if not n.is_disabled]
    access = {u: r.access for u, r in app.env.state.nodes().items()}
    return Collector(app.env, snapshot, selected, access, False, Progress()).run()
