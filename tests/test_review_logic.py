"""Review K13, fix and rollback logic: each test replays a failure scenario of the review.

A change whose automatic rollback fails keeps the state it reached with error
rollback_failed (exit 5); a change cut short stays rollbackable; undo puts back
only what KERBEROS wrote and asks before overwriting edits made after it.
"""

import json
from urllib.parse import urlsplit

import pytest
from helpers import login_keys, make_app, on

from kerberos.demo.fleet import build_nodes, build_panel
from kerberos.fixes.engine import ROLLBACKABLE
from kerberos.fixes.journal import RunStore
from kerberos.flow import EXIT_OK, EXIT_PARTIAL, EXIT_ROLLBACK_FAILED
from kerberos.nodes import fake_fixes
from kerberos.nodes.keys import PublicKey, demo_blob, fingerprint
from kerberos.nodes.transport import NodeAgentError, TransportError

TO_PLAN = login_keys() + ["enter", "enter"] + ["enter"] * 5 + ["esc"] + ["enter", "enter"]
TO_PLAN += ["enter", "enter", "enter"]
APPLY = ["enter", "enter"]  # S7 → consent → accept
DONE = ["enter"]  # S9
# The run, all its changes, consent, the panel login; the result notice comes after.
ROLLBACK = ["enter", "enter", "enter"]  # run, changes, consent; the panel: the saved token
NL1, NL2 = "nl-1", "nl-2"  # rows of the block «Свой домен» of S7 (K23)


class Hooked:
    """The fake panel behind a hook: hook(method, path, n, body) may answer instead."""

    def __init__(self, panel, hook):
        self.panel, self.hook, self.counts = panel, hook, {}

    def __call__(self, method, url, headers, body, timeout):
        path = urlsplit(url).path.removeprefix("/api")
        key = (method, path)
        self.counts[key] = self.counts.get(key, 0) + 1
        data = json.loads(body.decode("utf-8")) if body else None
        answer = self.hook(method, path, self.counts[key], data)
        if answer is not None:
            return answer
        return self.panel(method, url, headers, body, timeout)

    def __getattr__(self, name):
        return getattr(self.panel, name)


class Died(BaseException):
    """The process ends here (SIGHUP when the SSH session drops)."""


def domain_keys(node, name):
    return on(node, "self_steal", "d", *name, "enter")


def fleet():
    return build_panel(), {n.name: n for n in build_nodes()}


def fix(keys, panel, nodes, height=46):
    app, term = make_app(TO_PLAN + list(keys), panel=panel, nodes=list(nodes.values()),
                         height=height)  # fmt: skip
    return app, term, app.run("fix")


def fix_run(app):
    return next(r for r in RunStore(app.env.state, app.env.clock).runs() if r["mode"] == "fix")


def changes_of(run, fix_id, node_uuid=None):
    found = [c for c in run["changes"] if c["fixId"] == fix_id]
    if node_uuid is not None:
        found = [c for c in found if node_uuid in owners(c)]
    return found


def owners(change):
    """The node a change belongs to: its target, or the node of a panel change."""
    return change["target"].partition(":")[2], change["params"].get("node")


def raw_node(panel, name):
    return next(n for n in panel.nodes if n["name"] == name)


def profile_of(panel, name):
    ref = raw_node(panel, name)["configProfile"]["activeConfigProfileUuid"]
    return next(p for p in panel.profiles if p["uuid"] == ref)


def stuck(change, failure, rollback_error):
    """The shared contract of a change whose automatic rollback failed."""
    assert change["error"] == "rollback_failed"
    assert change["details"]["failure"] == failure
    assert change["details"]["rollbackError"] == rollback_error
    assert change["state"] in ROLLBACKABLE


# -- app 5, agent 9: a rollback that fails is not reported as done --------------------------
def test_recheck_failure_whose_rollback_fails_keeps_the_change():
    panel, nodes = fleet()
    node = nodes["nl-2"]
    real_facts = node.handlers["facts"]

    def facts(n, args, data):
        answer = real_facts(n, args, data)
        answer["mptcp"]["enabled"] = True  # the recheck of mptcp.guard fails
        return answer

    def rollback(n, args, data):
        raise NodeAgentError("backup_damaged", "files/0")

    node.handlers.update(facts=facts, rollback=rollback)
    app, _term, code = fix(APPLY + DONE, panel, nodes)
    assert code == EXIT_ROLLBACK_FAILED
    change = changes_of(fix_run(app), "mptcp.guard", raw_node(panel, "nl-2")["uuid"])[0]
    assert change["state"] == "applied"
    stuck(change, "recheck_failed", "backup_damaged")
    assert "inet kerberos_mptcp" in node.state["facts"]["nftTables"], "still on the node"


def test_lost_answer_whose_rollback_fails_stays_rollbackable():
    panel, nodes = fleet()
    node = nodes["nl-2"]
    real_apply = node.handlers["apply"]

    def apply(n, args, params):
        answer = real_apply(n, args, params)
        if args[0] == "mptcp.guard":
            raise TransportError("timeout", "the answer was lost")  # applied on the node
        return answer

    def rollback(n, args, data):
        raise TransportError("timeout", "no answer")

    node.handlers.update(apply=apply, rollback=rollback)
    app, _term, code = fix(APPLY + DONE, panel, nodes)
    assert code == EXIT_ROLLBACK_FAILED
    change = changes_of(fix_run(app), "mptcp.guard", raw_node(panel, "nl-2")["uuid"])[0]
    assert change["state"] == "applying"
    stuck(change, "timeout", "timeout")


def test_lost_connection_before_the_agent_changed_nothing():
    panel, nodes = fleet()
    node = nodes["nl-2"]
    real_apply = node.handlers["apply"]

    def apply(n, args, params):
        if args[0] == "mptcp.guard":
            raise TransportError("timeout", "the request never arrived")
        return real_apply(n, args, params)

    node.handlers["apply"] = apply  # the real rollback then answers no_backup
    app, _term, code = fix(APPLY + DONE, panel, nodes)
    assert code == EXIT_PARTIAL
    change = changes_of(fix_run(app), "mptcp.guard", raw_node(panel, "nl-2")["uuid"])[0]
    assert (change["state"], change["error"]) == ("failed", "timeout")


def test_profile_patch_without_an_answer_is_put_back():
    panel, nodes = fleet()
    before = json.loads(json.dumps(profile_of(panel, "nl-1")["config"]))
    panel.fail("PATCH", "/config-profiles", "lost", times=4)  # written, the answer lost
    app, _term, code = fix(domain_keys(NL1, "nl-1.example.com") + APPLY + DONE, panel, nodes)
    assert code == EXIT_PARTIAL
    assert profile_of(panel, "nl-1")["config"] == before
    change = changes_of(fix_run(app), "self_steal.profile")[0]
    assert (change["state"], change["error"]) == ("rolled_back", "timeout")


def test_self_steal_whose_undo_fails_keeps_what_stayed():
    base, nodes = fleet()
    nl1 = profile_of(base, "nl-1")["uuid"]
    state = {"patched": False}

    def hook(method, path, n, body):
        if (method, path) == ("PATCH", "/config-profiles") and body["uuid"] == nl1:
            if state["patched"]:
                return 500, b'{"message": "injected"}'  # the profile cannot go back
            state["patched"] = True
            raw_node(base, "nl-1")["isConnected"] = False  # the node drops after the profile
        return None

    app, _term, code = fix(domain_keys(NL1, "nl-1.example.com") + APPLY + DONE,
                           Hooked(base, hook), nodes)  # fmt: skip
    assert code == EXIT_ROLLBACK_FAILED
    run = fix_run(app)
    profile = changes_of(run, "self_steal.profile")[0]
    assert profile["state"] == "applied"
    stuck(profile, "node_offline", "server_error")
    assert changes_of(run, "self_steal.hosts")[0]["state"] == "rolled_back"
    assert not [h for h in base.hosts if h["sni"] == "nl-1.example.com"]
    # v19: the profile stayed on the site, so the site stays too, for `kerberos rollback`.
    stuck(changes_of(run, "self_steal.site")[0], "node_offline", "rollback_skipped")
    assert "nl-1.example.com" in nodes["nl-1"].state["sites"]


# -- app 4: a change cut short is offered by rollback; a panel bug leaves nothing half done -
def test_change_cut_short_is_offered_by_rollback():
    base, nodes = fleet()

    def hook(method, path, n, body):
        if (method, path) == ("POST", "/hosts/bulk/disable"):
            raise Died()  # between the copies and switching the old hosts off
        return None

    keys = TO_PLAN + domain_keys(NL1, "nl-1.example.com") + APPLY
    app, _term = make_app(keys, panel=Hooked(base, hook), nodes=list(nodes.values()), height=46)
    with pytest.raises(Died):
        app.run("fix")
    hosts = changes_of(fix_run(app), "self_steal.hosts")[0]
    assert hosts["state"] == "applying" and hosts["details"]["created"]
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_OK
    assert not [h for h in base.hosts if h["sni"] == "nl-1.example.com"]
    assert changes_of(fix_run(app), "self_steal.hosts")[0]["state"] == "rolled_back"


def test_panel_fix_failing_outside_the_panel_is_undone():
    from kerberos.fixes import xhttp

    base, nodes = fleet()

    def hook(method, path, n, body):
        extra = (body or {}).get("xhttpExtraParams") or {}
        if (method, path) == ("PATCH", "/hosts") and "xPaddingBytes" in extra:
            raise RuntimeError("a bug between the server and the clients")
        return None

    app, _term, code = fix(APPLY + DONE, Hooked(base, hook), nodes)
    assert code == EXIT_PARTIAL
    change = changes_of(fix_run(app), "xhttp.padding")[0]
    assert (change["state"], change["error"]) == ("rolled_back", "internal_error")
    inbound = next(i for i in profile_of(base, "fi-1")["config"]["inbounds"]
                   if i["tag"] == "XHTTP-FI1")  # fmt: skip
    assert not xhttp.padding_of(inbound["streamSettings"]["xhttpSettings"].get("extra"))


# -- agent 4: a confirmed access change rolled back after its recheck --------------------------
def fail_facts_after(app, is_trigger):
    """The first `facts` after a confirm that `is_trigger` picks gets no answer."""
    real = app.env.transport.agent
    armed = {"on": False}

    def agent(target, command, payload=None, **kw):
        if command.startswith("confirm") and is_trigger(target, command):
            answer = real(target, command, payload, **kw)
            armed["on"] = True
            return answer
        if command == "facts" and armed["on"]:
            armed["on"] = False
            raise TransportError("timeout", "facts")
        return real(target, command, payload, **kw)

    app.env.transport.agent = agent


def test_ssh_port_rolled_back_after_its_recheck_moves_kerberos_back():
    panel, nodes = fleet()
    keys = on("nl-1", "ssh.port", "space") + APPLY + DONE
    app, _term = make_app(TO_PLAN + keys, panel=panel, nodes=list(nodes.values()), height=46)
    fail_facts_after(app, lambda target, _c: target.address == "203.0.113.10" and target.port != 22)
    app.run("fix")
    change = changes_of(fix_run(app), "ssh.port")[0]
    assert (change["state"], change["error"]) == ("rolled_back", "recheck_failed")
    assert nodes["nl-1"].ssh_port == 22
    assert app.env.state.find_node("nl-1").ssh_port == 22


def test_host_keys_rolled_back_after_their_recheck_pin_the_old_key():
    panel, nodes = fleet()
    app, _term = make_app(TO_PLAN + APPLY + DONE, panel=panel, nodes=list(nodes.values()),
                          height=46)  # fmt: skip
    ids = set()
    real = app.env.transport.agent

    def note(target, command, payload=None, **kw):
        if command.startswith("apply hostkeys.regenerate") and target.address == "203.0.113.10":
            ids.add(command.split()[2])
        return real(target, command, payload, **kw)

    app.env.transport.agent = note
    fail_facts_after(app, lambda _t, command: command.split()[1] in ids)
    app.run("fix")
    change = changes_of(fix_run(app), "hostkeys.regenerate", raw_node(panel, "nl-1")["uuid"])[0]
    assert (change["state"], change["error"]) == ("rolled_back", "recheck_failed")
    assert app.env.state.pinned("203.0.113.10", 22) == nodes["nl-1"].host_key.blob


# -- agent 18: sshd that does not show the new key ---------------------------------------------
def test_host_keys_that_sshd_does_not_show_are_rolled_back():
    panel, nodes = fleet()
    node = nodes["nl-1"]
    old_pin = node.host_key.blob

    def files_only(n, params, change_id):
        # The agent rewrote the default files (facts read them), sshd serves another HostKey.
        facts = n.state["facts"]
        saved = list(facts["hostKeys"])
        new = PublicKey("ssh-ed25519", demo_blob(f"{n.name}-{change_id}"))
        facts["hostKeys"] = [{"type": "ED25519", "fingerprint": fingerprint(new.blob)}]

        def undo():
            facts["hostKeys"] = saved

        return {"hostKeys": list(facts["hostKeys"])}, undo

    fake_fixes.give_fixes(node, dict(fake_fixes.MODEL, **{"hostkeys.regenerate": files_only}))
    app, _term, code = fix(APPLY + DONE, panel, nodes)
    change = changes_of(fix_run(app), "hostkeys.regenerate", raw_node(panel, "nl-1")["uuid"])[0]
    assert (change["state"], change["error"]) == ("rolled_back", "hostkey_mismatch")
    assert app.env.state.pinned("203.0.113.10", 22) == old_pin
    confirms = [
        c for _a, c in app.env.transport.log if c.startswith(f"confirm {change['changeId']}")
    ]
    assert not confirms and code == EXIT_PARTIAL


# -- agent 5: the panel loses its node some seconds after node_api.panel_only -------------------
def test_node_api_rule_is_undone_when_the_panel_loses_the_node():
    base, nodes = fleet()
    node = nodes["nl-1"]
    real_apply = node.handlers["apply"]
    seen_after = {"rule": False, "reads": 0}

    def apply(n, args, params):
        answer = real_apply(n, args, params)
        if args[0] == "node_api.panel_only":
            seen_after["rule"] = True
        return answer

    def hook(method, path, n, body):
        if (method, path) == ("GET", "/nodes") and seen_after["rule"]:
            seen_after["reads"] += 1
            if seen_after["reads"] == 3:
                raw_node(base, "nl-1")["isConnected"] = False  # the next health check fails
        return None

    node.handlers["apply"] = apply
    app, _term, code = fix(APPLY + DONE, Hooked(base, hook), nodes)
    change = changes_of(fix_run(app), "node_api.panel_only", raw_node(base, "nl-1")["uuid"])[0]
    assert (change["state"], change["error"]) == ("rolled_back", "recheck_failed")
    assert "inet kerberos_node_api" not in node.state["facts"]["nftTables"]
    assert code == EXIT_PARTIAL


def test_node_api_recheck_watches_the_panel_for_half_a_minute():
    panel, nodes = fleet()
    app, _term = make_app(TO_PLAN + APPLY + DONE, panel=panel, nodes=list(nodes.values()),
                          height=46)  # fmt: skip
    app.env.demo = False  # a real run waits between the looks; the demo does not
    reads = []
    real = panel.__class__.__call__

    def count(self, method, url, headers, body, timeout):
        if method == "GET" and url.endswith("/api/nodes"):
            reads.append(app.env.clock.monotonic())
        return real(self, method, url, headers, body, timeout)

    panel.__class__ = type("Counting", (panel.__class__,), {"__call__": count})
    assert app.run("fix") == EXIT_OK
    assert app.env.clock.slept.count(5) >= 6
    assert max(reads) - min(reads) >= 25
