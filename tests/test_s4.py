"""S4 access to the nodes (tech.md §6, §8, K2)."""

from helpers import S4_KEYS, TOKEN, login_keys, make_app, seen

from kerberos.copy import t
from kerberos.demo.fleet import build_nodes, build_panel
from kerberos.nodes import bootstrap
from kerberos.nodes.keys import PublicKey, demo_blob

TO_S4 = login_keys() + ["enter"]  # S2 does not stop (K25), S3
AGAIN_S4 = ["enter"]  # a later run: the saved token, S2 asks nothing (§7.3); S3
# kz-1 is unreachable (Esc on its port); one table with the intro of «Проверка» confirms
# nl-1, nl-2, de-1 and fi-1; de-1 gets python3 after the question.
ALL_NODES = S4_KEYS
INTRO = ["enter"]  # «Проверка» with no new key to confirm: what S4 installs, alone
QUIT = ["q", "enter"]


def strict_panel():
    panel = build_panel()
    panel.accept_any_token = False
    panel.add_api_token(TOKEN)
    return panel


def run_check(nodes=None, state=None, extra=ALL_NODES, panel=None):
    start = AGAIN_S4 if state is not None and state.read_panel_token() else TO_S4
    keys = start + list(extra) + ["enter", "x"] + QUIT
    app, term = make_app(keys, nodes=nodes, state=state, panel=panel or strict_panel())
    app.run("check")
    return app, term


def kerberos_lines(node):
    return [line for line in node.authorized_keys if "kerberos-agent" in line]


def test_password_node_gets_the_agent_without_manual_steps():
    nodes = build_nodes()
    app, term = run_check(nodes)
    nl1 = nodes[0]
    assert nl1.agent_sha == bootstrap.agent_sha256()
    assert len(kerberos_lines(nl1)) == 1
    assert kerberos_lines(nl1)[0].startswith('from="198.51.100.5",command=')
    record = app.env.state.find_node("nl-1")
    assert record.access == "ok" and record.panel_ip == "198.51.100.5"
    assert t("access.password", node="nl-1") in term.messages
    assert app.env.transport.interactive_logins == 3  # nl-1, nl-2, de-1; fi-1 used root keys
    assert nodes[2].python is True  # de-1 got python3-minimal after the question
    summary = next(f for f in term.frames if t("access.summary", ok=4, total=5) in f)
    assert t("access.reason.unreachable") in summary


def test_no_secret_reaches_the_files():
    panel = strict_panel()
    keys = TO_S4 + ALL_NODES + ["enter", "enter"] + ["enter", "x"] + QUIT
    app, term = make_app(keys, panel=panel)
    app.run("fix")
    tokens = list(panel.sessions) + ["admin-password"]
    for path in app.env.state.root.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert not any(secret in text for secret in tokens), path
    assert all("admin-password" not in f for f in term.frames)


def test_host_key_change_stops_commands_to_the_node():
    nodes = build_nodes()
    app, _ = run_check(nodes)
    state = app.env.state
    nodes[0].host_key = PublicKey("ssh-ed25519", demo_blob("reinstalled"))
    keys = AGAIN_S4 + ["esc"] + INTRO + ["esc"] + ["enter", "x"] + QUIT  # kz-1; skip nl-1's key
    app, term = make_app(keys, nodes=nodes, state=state, panel=strict_panel())
    start = len(app.env.transport.log)
    app.run("check")
    assert seen(term, t("access.hostkey_changed", node="nl-1"))
    after = [entry for entry in app.env.transport.log[start:] if entry[0] == "203.0.113.10"]
    assert all(cmd.startswith("keyscan") for _, cmd in after), after
    assert state.pinned("203.0.113.10", 22) == demo_blob("hoster-image")


def test_new_host_key_can_be_confirmed():
    nodes = build_nodes()
    app, _ = run_check(nodes)
    state = app.env.state
    nodes[0].host_key = PublicKey("ssh-ed25519", demo_blob("reinstalled"))
    # «Пропустить ноду» is preselected for a changed key: ↑ to confirm it.
    keys = AGAIN_S4 + ["esc"] + INTRO + ["up", "enter"] + ["enter", "x"] + QUIT
    app, term = make_app(keys, nodes=nodes, state=state, panel=strict_panel())
    app.run("check")
    assert state.pinned("203.0.113.10", 22) == demo_blob("reinstalled")
    assert state.find_node("nl-1").access == "ok"


def test_known_nodes_skip_the_bootstrap():
    nodes = build_nodes()
    app, _ = run_check(nodes)
    state = app.env.state
    app, term = make_app(
        AGAIN_S4 + ["esc"] + ["enter", "x"] + QUIT,
        nodes=nodes,
        state=state,
        panel=strict_panel(),
    )
    app.run("check")
    log = [cmd for addr, cmd in app.env.transport.log if addr == "203.0.113.10"]
    assert log == ["version"]
    assert len(kerberos_lines(nodes[0])) == 1


def test_bootstrap_again_duplicates_nothing():
    nodes = build_nodes()
    app, _ = run_check(nodes)
    state = app.env.state
    state.nodes_file.unlink()
    app, _ = run_check(nodes, state, extra=["esc"] + INTRO)  # the keys are pinned already
    for node in nodes[:4]:
        assert len(kerberos_lines(node)) == 1, node.name


def test_old_agent_is_updated():
    nodes = build_nodes()
    app, _ = run_check(nodes)
    nodes[0].agent_sha = "0" * 64
    app, _ = run_check(nodes, app.env.state, extra=["esc"])  # kz-1
    assert nodes[0].agent_sha == bootstrap.agent_sha256()
    assert any(
        cmd.startswith("update ") for addr, cmd in app.env.transport.log if addr == "203.0.113.10"
    )


def test_new_panel_address_sets_access_up_again():
    nodes = build_nodes()
    app, _ = run_check(nodes)
    nodes[0].panel_ip = "198.51.100.6"
    app, _ = run_check(nodes, app.env.state, extra=["esc"] + INTRO)  # kz-1; set nl-1 up again
    lines = kerberos_lines(nodes[0])
    assert len(lines) == 1 and lines[0].startswith('from="198.51.100.6"')


def test_python_install_can_be_declined():
    nodes = build_nodes()
    extra = ["esc", "enter", "down", "enter"]  # kz-1, the table, de-1: «Пропустить ноду»
    app, term = run_check(nodes, extra=extra)
    assert nodes[2].python is False and nodes[2].agent_sha is None
    summary = next(f for f in term.frames if t("access.summary", ok=3, total=5) in f)
    assert t("access.reason.python") in summary


def test_other_ssh_port_is_asked_for():
    nodes = build_nodes()
    nodes[5].reachable = True
    nodes[5].ssh_port = 2222
    extra = ["backspace", "backspace"] + list("2222") + ["enter", "enter", "enter"]
    app, term = run_check(nodes, extra=extra)
    record = app.env.state.find_node("kz-1")
    assert record.access == "ok" and record.ssh_port == 2222
    assert app.env.state.pinned("192.0.2.60", 2222) is not None


def test_admin_key_question_only_in_fix_mode():
    app, term = run_check()
    assert all(t("access.admin.title") not in f for f in term.frames)
    keys = TO_S4 + ALL_NODES + ["enter", "enter"] + ["enter", "x"] + QUIT
    app, term = make_app(keys)
    app.run("fix")
    assert any(t("access.admin.title") in f for f in term.frames)
    assert seen(term, t("access.answer.admin.mine", n=1))
