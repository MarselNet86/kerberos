"""What the review of the node side found (K13), on the KERBEROS side: the rollback of
a run, the SSH transport and S4 picking the node address."""

import pytest
from helpers import login_keys, make_app, on, seen, typed

from kerberos.copy import t
from kerberos.demo.fleet import build_nodes
from kerberos.fixes.journal import RunStore
from kerberos.flow import EXIT_OK, EXIT_ROLLBACK_FAILED
from kerberos.nodes.transport import NodeAgentError

# Same keys as tests/test_fix_flow.py and tests/test_ssh_port_flow.py.
TO_PLAN = login_keys() + ["enter", "enter"] + ["enter"] * 5 + ["esc"] + ["enter", "enter"]
TO_PLAN += ["enter", "enter", "enter"]
DEFAULT_APPLY = ["enter", "enter", "enter"]  # S7 → consent → accept, S9


def everything(*names):
    """`a` marks every row but the SSH ports (§6): the port rows are marked by hand."""
    keys = ["a"]
    for name in names:
        keys += on(name, "ssh.port", "space")
    return keys + ["enter", "enter", "enter"]  # consent, accept, S9


EVERYTHING = everything("nl-1")
ROLLBACK = ["enter", "enter", "enter"]  # run, changes, consent; the panel: the saved token
NL1 = "203.0.113.10"


def fixed(keys, nodes):
    app, term = make_app(TO_PLAN + keys, nodes=list(nodes.values()), height=44)
    app.run("fix")
    return app, term


def demo_nodes():
    return {n.name: n for n in build_nodes()}


def run_of(app, run_id):
    return RunStore(app.env.state, app.env.clock).load(run_id)


def last_run(app):
    return RunStore(app.env.state, app.env.clock).runs()[0]


def changes_of(run, uuid):
    return [c for c in run["changes"] if c["target"] == f"node:{uuid}"]


def uuid_of(app, name):
    return next(u for u, r in app.env.state.nodes().items() if r.name == name)


class Spy:
    """Agent calls with the port they went to."""

    def __init__(self, transport):
        self.calls = []
        self.inner = transport.agent

        def agent(target, command, payload=None, **kwargs):
            self.calls.append((target.address, target.port, command, kwargs.get("fresh", False)))
            return self.inner(target, command, payload, **kwargs)

        transport.agent = agent


# -- 2. a change that does not go back stops the earlier changes of its node ---------------
def test_failed_rollback_keeps_the_earlier_changes_of_the_node():
    nodes = demo_nodes()
    app, _term = fixed(DEFAULT_APPLY, nodes)
    first = last_run(app)
    nl1 = changes_of(first, uuid_of(app, "nl-1"))
    fixes = [c["fixId"] for c in nl1]
    assert fixes.index("access.admin_keys") < fixes.index("ssh.key_only")
    key_only = next(c for c in nl1 if c["fixId"] == "ssh.key_only")
    original = nodes["nl-1"].handlers["rollback"]

    def rollback(node, args, data):
        # A later run changed 10-kerberos.conf (ssh.port in sshd_config mode).
        if args[0] == key_only["changeId"]:
            raise NodeAgentError("change_conflict", "10-kerberos.conf changed after KERBEROS")
        return original(node, args, data)

    nodes["nl-1"].handlers["rollback"] = rollback
    admin_keys = list(nodes["nl-1"].authorized_keys)
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_ROLLBACK_FAILED
    after = {c["changeId"]: c for c in run_of(app, first["runId"])["changes"]}
    assert after[key_only["changeId"]]["error"] == "change_conflict"
    earlier = [after[c["changeId"]] for c in nl1 if c["fixId"] != "ssh.key_only"]
    assert earlier and all(c["error"] == "rollback_skipped" for c in earlier)
    assert all(c["state"] != "rolled_back" for c in earlier)
    assert nodes["nl-1"].authorized_keys == admin_keys, "the administrator key stays"
    assert nodes["nl-1"].state["facts"]["ssh"]["passwordAuthentication"] is False
    others = [c for c in after.values() if c["target"] == f"node:{uuid_of(app, 'nl-2')}"]
    assert others and all(c["state"] == "rolled_back" for c in others), "other nodes go back"


def test_the_fake_agent_keeps_the_admin_key_for_a_later_key_only():
    nodes = demo_nodes()
    app, _term = fixed(DEFAULT_APPLY, nodes)
    nl1 = changes_of(last_run(app), uuid_of(app, "nl-1"))
    keys = next(c for c in nl1 if c["fixId"] == "access.admin_keys")
    with pytest.raises(NodeAgentError) as refused:
        nodes["nl-1"].handlers["rollback"](nodes["nl-1"], [keys["changeId"]], None)
    assert refused.value.code == "change_conflict"


# -- 3. a confirmed ssh.port goes back in two phases ---------------------------------------
def port_change(app, name="nl-1"):
    uuid = uuid_of(app, name)
    return next(c for c in last_run(app)["changes"]
                if c["fixId"] == "ssh.port" and c["target"] == f"node:{uuid}")  # fmt: skip


def test_rollback_of_the_port_is_proved_on_the_old_port():
    nodes = demo_nodes()
    app, _term = fixed(EVERYTHING, nodes)
    change = port_change(app)
    new = change["details"]["newPort"]
    assert change["state"] == "confirmed" and nodes["nl-1"].ssh_port == new
    spy = Spy(app.env.transport)
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_OK
    mine = [(port, cmd, fresh) for addr, port, cmd, fresh in spy.calls
            if addr == NL1 and change["changeId"] in cmd]  # fmt: skip
    assert mine == [
        (new, f"rollback {change['changeId']}", False),
        (22, f"confirm {change['changeId']}", True),
    ]
    assert nodes["nl-1"].ssh_port == 22 and nodes["nl-1"].state["facts"]["ssh"]["ports"] == [22]
    assert app.env.state.find_node("nl-1").ssh_port == 22


def test_old_port_closed_at_the_hoster_keeps_the_new_port():
    """The person opened the new port at the hoster and closed 22 there."""
    nodes = demo_nodes()
    app, _term = fixed(EVERYTHING, nodes)
    change = port_change(app)
    run_id = last_run(app)["runId"]
    new = change["details"]["newPort"]
    nodes["nl-1"].state["closed_ports"] = [22]
    spy = Spy(app.env.transport)
    app.env.terminal.feed(*ROLLBACK, "x")
    assert app.run("rollback") == EXIT_ROLLBACK_FAILED
    after = {c["changeId"]: c for c in run_of(app, run_id)["changes"]}
    port = after[change["changeId"]]
    assert port["state"] == "confirmed" and port["error"] == "port_closed"
    assert nodes["nl-1"].state["facts"]["ssh"]["ports"] == [new], "back to the new port only"
    assert app.env.state.find_node("nl-1").ssh_port == new
    commands = [cmd for addr, _p, cmd, _f in spy.calls if addr == NL1]
    assert f"undo {change['changeId']}" in commands
    hostkeys = next(c for c in changes_of(run_of(app, run_id), uuid_of(app, "nl-1"))
                    if c["fixId"] == "hostkeys.regenerate")  # fmt: skip
    assert hostkeys["error"] == "rollback_skipped", "an earlier change of nl-1 waits"
    assert sum(app.env.clock.slept) >= 55, "the old port had its minute"


# 3x-ui (§7.6): KERBEROS reaches this server on 127.0.0.1 and cannot see the hoster's firewall.
XUI_LOGIN = typed("admin") + ["enter"] + typed("pw") + ["enter"]
XUI_PLAN = ["down", "enter"] + XUI_LOGIN + ["enter", "enter", "enter"]
XUI_PORT = ["home", "down"]  # the group «Новый порт SSH» of S7 (K23)


def xui_with_new_port():
    keys = XUI_PLAN + XUI_PORT + ["space", "enter", "enter", "enter", "enter"]
    app, term = make_app(keys, panel_kind=None, height=44)
    app.run("fix")
    change = next(c for c in last_run(app)["changes"] if c["fixId"] == "ssh.port")
    assert change["state"] == "confirmed"
    return app, term, change


@pytest.mark.parametrize("answer, code", [("enter", EXIT_OK), ("esc", EXIT_ROLLBACK_FAILED)])
def test_xui_rollback_of_the_port_is_tried_from_outside(answer, code):
    from kerberos.demo.xui import XUI_IP

    app, term, change = xui_with_new_port()
    run_id = last_run(app)["runId"]
    new = change["details"]["newPort"]
    app.env.terminal.feed("enter", "enter", "enter", answer, "x")
    assert app.run("rollback") == code
    assert seen(term, t("rb.outside", port=22, command=f"ssh -p 22 root@{XUI_IP}"))
    ssh = app.env.transport.nodes["127.0.0.1"].state["facts"]["ssh"]
    port = next(c for c in run_of(app, run_id)["changes"] if c["changeId"] == change["changeId"])
    if answer == "enter":
        assert port["state"] == "rolled_back" and ssh["ports"] == [22]
        assert app.env.state.node("local").ssh_port == 22
    else:
        assert port["state"] == "confirmed" and port["error"] == "port_closed"
        assert ssh["ports"] == [new] and app.env.state.node("local").ssh_port == new


@pytest.mark.parametrize("answer", ["enter", "esc"])
def test_xui_port_whose_recheck_fails_is_tried_on_the_old_port_from_outside(answer):
    """The engine takes a confirmed port back the same way as `kerberos rollback` (§9.3)."""
    from kerberos.demo.xui import XUI_IP
    from kerberos.nodes.transport import TransportError

    # Space marks the port, consent, accept, «the new port works», then the old port.
    keys = XUI_PLAN + XUI_PORT + ["space", "enter", "enter", "enter", answer]
    app, term = make_app(keys + ["enter", "enter"], panel_kind=None, height=44)
    real = app.env.transport.agent
    armed = {"on": False, "done": False}

    def agent(target, command, payload=None, **kwargs):
        if command.startswith("confirm") and target.port != 22 and not armed["done"]:
            armed["on"] = armed["done"] = True  # the confirm on the new port
        elif command == "facts" and armed["on"]:
            armed["on"] = False
            raise TransportError("timeout", "facts")  # the recheck gets no answer
        return real(target, command, payload, **kwargs)

    app.env.transport.agent = agent
    app.run("fix")
    assert seen(term, t("rb.outside", port=22, command=f"ssh -p 22 root@{XUI_IP}"))
    change = next(c for c in last_run(app)["changes"] if c["fixId"] == "ssh.port")
    ssh = app.env.transport.nodes["127.0.0.1"].state["facts"]["ssh"]
    if answer == "enter":
        assert (change["state"], change["error"]) == ("rolled_back", "recheck_failed")
        assert ssh["ports"] == [22] and app.env.state.node("local").ssh_port == 22
    else:
        new = change["details"]["newPort"]
        assert (change["state"], change["error"]) == ("confirmed", "rollback_failed")
        assert change["details"]["rollbackError"] == "port_closed"
        assert ssh["ports"] == [new] and app.env.state.node("local").ssh_port == new


# -- 5. a node given by name is reached on its IPv4 (§8.2) ----------------------------------
NL1_NAME = "nl-1.example.com"
TO_S4 = login_keys() + ["enter", "enter"]
HOST_KEYS = ["enter", "enter", "enter", "enter", "enter", "esc"]  # see tests/test_s4.py


def check_by_name(nodes, state=None, extra=HOST_KEYS):
    from kerberos.demo.fleet import build_panel

    panel = build_panel()
    next(n for n in panel.nodes if n["name"] == "nl-1")["address"] = NL1_NAME
    keys = TO_S4 + ["enter"] + extra + ["enter", "x", "q", "enter"]  # S4 intro of «Проверка»
    app, term = make_app(keys, nodes=nodes, state=state, panel=panel)
    app.env.prober.dns[NL1_NAME] = ["2001:db8::10", NL1]  # A and AAAA
    app.run("check")
    return app, term


def test_ssh_host_takes_the_ipv4_of_a_name():
    from kerberos.nodes.transport import ssh_host

    dns = {NL1_NAME: ["2001:db8::10", NL1], "v6.example.com": ["2001:db8::11"]}
    assert ssh_host(NL1_NAME, lambda name: dns.get(name, [])) == NL1
    assert ssh_host("v6.example.com", lambda name: dns.get(name, [])) == "v6.example.com"
    assert ssh_host("198.51.100.20", lambda name: []) == "198.51.100.20"
    assert ssh_host(NL1_NAME) == NL1_NAME


def test_s4_reaches_a_node_name_on_its_ipv4():
    nodes = build_nodes()
    app, _term = check_by_name(nodes)
    record = app.env.state.find_node("nl-1")
    assert record.access == "ok" and record.address == NL1_NAME
    assert record.ssh_address == NL1 and record.target(record.address).address == NL1
    assert app.env.state.pinned(NL1, 22) == nodes[0].host_key.blob
    assert ("resolve", NL1_NAME) in app.env.prober.calls


def test_node_set_up_by_name_before_moves_to_its_ipv4_without_questions():
    nodes = build_nodes()
    app, _term = check_by_name(nodes)
    state = app.env.state
    record = state.find_node("nl-1")
    record.ssh_address = ""  # as KERBEROS before K13 left it: the name, pinned by the name
    state.save_node(record)
    blob = state.pinned(NL1, 22)
    lines = state.known_hosts.read_text().splitlines()
    state.known_hosts.write_text("\n".join(x for x in lines if not x.startswith(NL1 + " ")) + "\n")
    state.pin(NL1_NAME, 22, "ssh-ed25519", blob)
    app, term = check_by_name(nodes, state, extra=["esc"])
    assert state.find_node("nl-1").ssh_address == NL1
    assert state.pinned(NL1, 22) == blob
    assert app.env.transport.interactive_logins == 0
    question = t("access.hostkey", node="nl-1", fingerprint="@").split("@")[0].strip()
    assert seen(check_by_name(build_nodes())[1], question), "the question looks like this"
    assert not seen(term, question)


# -- 8. KERBEROS waits for a change as long as the agent may work on it ----------------------
@pytest.mark.parametrize("command", ["apply mptcp.guard 0f8b6c1e-2b1c-4b5e-9a3e-1c2d3e4f5a6b",
                                     "confirm 0f8b6c1e-2b1c-4b5e-9a3e-1c2d3e4f5a6b",
                                     "rollback 0f8b6c1e-2b1c-4b5e-9a3e-1c2d3e4f5a6b",
                                     "undo 0f8b6c1e-2b1c-4b5e-9a3e-1c2d3e4f5a6b",
                                     "update " + "0" * 64])  # fmt: skip
def test_changes_get_the_long_timeout(monkeypatch, tmp_path, command):
    import subprocess

    from kerberos import agent
    from kerberos.nodes import transport
    from kerberos.nodes.transport import SshTransport, Target
    from kerberos.state import State

    seen_timeouts = []

    class Done:
        returncode, stdout, stderr = 0, b'{"protocol": 1}\n', b""

    def fake_run(argv, **kwargs):
        seen_timeouts.append(kwargs["timeout"])
        return Done()

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(SshTransport, "_run_dir", lambda self: str(tmp_path))
    ssh = SshTransport(State(tmp_path))
    ssh.agent(Target("u", "nl-1", NL1), command)
    ssh.agent(Target("u", "nl-1", NL1), "facts")
    assert seen_timeouts[0] >= transport.CHANGE_TIMEOUT > transport.APT_TIMEOUT
    assert seen_timeouts[1] < transport.CHANGE_TIMEOUT, "reading stays quick"
    # A command waiting for the agent's lock gives up before KERBEROS stops waiting.
    assert set(transport.CHANGE_COMMANDS) == agent.LOCKED
    assert agent.LOCK_WAIT < transport.CHANGE_TIMEOUT
    assert agent.APT_TIMEOUT == transport.APT_TIMEOUT


# -- 19. 3x-ui: the SSH port of this server, also when ssh.socket sets it ---------------------
def test_local_ssh_port_follows_ssh_socket():
    from kerberos.host import CommandResult, FakeHost
    from kerberos.screens.access import local_ssh_port

    host = FakeHost()
    host.on(["sshd", "-T"], CommandResult(0, "port 22\nlistenaddress 0.0.0.0:22\n"))
    assert local_ssh_port(host) == 22
    host.on(["systemctl", "is-active", "ssh.socket"], CommandResult(0, "active\n"))
    host.on(["systemctl", "show", "ssh.socket"],
            CommandResult(0, "Listen=0.0.0.0:24622 (Stream) [::]:24622 (Stream)\n"))  # fmt: skip
    assert local_ssh_port(host) == 24622, "KERBEROS's own zz-kerberos.conf moved it"


def test_local_ssh_port_from_ss_when_sshd_t_fails():
    from kerberos.host import CommandResult, FakeHost
    from kerberos.screens.access import local_ssh_port

    host = FakeHost()
    host.on(["sshd", "-T"], CommandResult(255, "", "Missing privilege separation directory"))
    host.on(["ss"], CommandResult(0, 'tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* '
                                     'users:(("sshd",pid=8,fd=3))\n'))  # fmt: skip
    assert local_ssh_port(host) == 2222


# -- 3. the protocol of nodes/ssh_port.py, for the engine too -------------------------------
class StubTransport:
    def __init__(self, rollback, confirm):
        self.answers = {"rollback": rollback, "confirm": confirm, "undo": {"state": "confirmed"}}
        self.calls = []

    def agent(self, target, command, payload=None, **kwargs):
        name = command.split()[0]
        self.calls.append((name, target.port, kwargs.get("fresh", False)))
        answer = self.answers[name]
        if isinstance(answer, Exception):
            raise answer
        return answer


def stub_env(rollback, confirm):
    from types import SimpleNamespace

    from kerberos.clock import FakeClock

    class Pins:
        def pinned(self, address, port):
            return "AAAA"

        def pin(self, *args):
            pass

    return SimpleNamespace(transport=StubTransport(rollback, confirm), state=Pins(),
                           clock=FakeClock())  # fmt: skip


PENDING = {"state": "rollback_pending", "details": {"oldPorts": [22], "newPort": 24622}}
CHANGE = {"changeId": "0f8b6c1e-2b1c-4b5e-9a3e-1c2d3e4f5a6b", "details": {"oldPorts": [22]}}


@pytest.mark.parametrize("rollback, confirm, result, calls", [
    ({"state": "rolled_back"}, None, (None, True), ["rollback"]),  # an agent before K13
    (PENDING, {"state": "rolled_back"}, (None, True), ["rollback", "confirm"]),
    (PENDING, NodeAgentError("command_failed", "x"), ("command_failed", True),
     ["rollback", "confirm"]),
    (PENDING, NodeAgentError("backup_damaged", "x"), ("backup_damaged", False),
     ["rollback", "confirm", "undo"]),
    (PENDING, {"state": "noop"}, ("port_closed", False), ["rollback", "confirm", "undo"]),
    (NodeAgentError("sshd_test_failed", "x"), None, ("sshd_test_failed", False), ["rollback"]),
])  # fmt: skip
def test_port_rollback_protocol(rollback, confirm, result, calls):
    from kerberos.nodes.ssh_port import roll_back_port
    from kerberos.nodes.transport import Target

    env = stub_env(rollback, confirm)
    assert roll_back_port(env, Target("u", "nl-1", NL1, 24622), CHANGE) == result
    assert [c[0] for c in env.transport.calls] == calls
    if "confirm" in calls:
        assert ("confirm", 22, True) in env.transport.calls, "a new connection to the old port"
