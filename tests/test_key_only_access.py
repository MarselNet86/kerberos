"""Nodes that let root in only with a key (tech.md §6 S4, §8.2, K21).

Found on the owner's fleet: every node took only keys, the person's key lived on their
own computer, and S4 asked for passwords that could never work. Each node ended as
«нет доступа: не удалось войти», and nothing said why.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest
from helpers import S4_KEYS, TOKEN, flat, login_keys, make_app, seen

from kerberos.copy import t
from kerberos.demo.fleet import build_nodes, build_panel
from kerberos.nodes.transport import SshTransport, Target
from kerberos.state import State

ROOT = Path(__file__).resolve().parent.parent
TO_S4 = login_keys() + ["enter"]  # S2 does not stop (K25), S3
# kz-1 is unreachable and its port question is skipped; one table confirms the host keys
# (nl-1 is turned away at once after it), de-1 gets python3.
ALL_NODES = S4_KEYS
WHOIS = ["enter"]  # S5: yes; then S6
QUIT = ["q", "enter"]
KEY_ONLY = t("access.reason.key_only")


def strict_panel():
    panel = build_panel()
    panel.accept_any_token = False
    panel.add_api_token(TOKEN)
    return panel


def run_check(nodes, *, forwarded=False):
    keys = TO_S4 + ALL_NODES + ["enter"] + WHOIS + QUIT
    app, term = make_app(keys, nodes=nodes, panel=strict_panel())
    app.env.transport.agent_forwarded = forwarded
    app.run("check")
    return app, term


def key_only_fleet(root_keys=False):
    nodes = build_nodes()
    nodes[0].password_offered = False  # nl-1
    nodes[0].root_keys = root_keys
    return nodes


def last_run(app):
    runs = sorted((app.env.state.root / "runs").iterdir())
    return runs[-1]


def test_a_key_only_node_is_not_asked_for_a_password():
    app, term = run_check(key_only_fleet())
    assert not seen(term, t("access.password", node="nl-1"))
    assert app.env.transport.interactive_logins == 2  # nl-2 and de-1 only
    assert seen(term, f"✗ {t('access.status.none')}: {KEY_ONLY}")
    summary = next(f for f in term.frames if t("access.summary", ok=3, total=5) in f)
    assert t("access.key_only.hint") in flat(summary)
    assert t("access.key_only.hint.agent") not in flat(summary)


def test_the_reason_reaches_the_run_the_report_and_the_log():
    app, term = run_check(key_only_fleet())
    directory = last_run(app)
    run = json.loads((directory / "run.json").read_text(encoding="utf-8"))
    nl1 = next(n for n in run["nodes"] if n["name"] == "nl-1")
    assert (nl1["access"], nl1["accessReason"]) == ("none", KEY_ONLY)
    fi1 = next(n for n in run["nodes"] if n["name"] == "fi-1")
    assert fi1["access"] == "ok" and "accessReason" not in fi1
    report = (directory / "report.md").read_text(encoding="utf-8")
    assert f"| {t('access.status.none')}: {KEY_ONLY} |" in report
    log = (directory / "kerberos.log").read_text(encoding="utf-8")
    assert f"access nl-1: none ({KEY_ONLY})" in log
    unreachable = t("access.reason.unreachable")
    nodes = f"nl-1 ({KEY_ONLY}); kz-1 ({unreachable})"
    s6 = next(f for f in term.frames if "Без доступа" in f)
    # The line wraps in the column right of the score badge.
    column = " ".join(line.split("│")[-1].strip() for line in s6.splitlines()[2:10])
    assert t("s6.no_access", nodes=nodes) in " ".join(column.split())


def test_a_forwarded_key_opens_a_key_only_node():
    """`ssh -A`: the key login of S4 offers the person's own key (§8.2)."""
    nodes = key_only_fleet(root_keys=True)
    app, term = run_check(nodes, forwarded=True)
    assert app.env.state.find_node("nl-1").access == "ok"
    assert len([k for k in nodes[0].authorized_keys if "kerberos-agent" in k]) == 1
    assert not any(t("access.key_only.hint.agent") in flat(f) for f in term.frames)


def test_a_forwarded_key_that_does_not_fit_gets_its_own_hint():
    app, term = run_check(key_only_fleet(), forwarded=True)
    summary = next(f for f in term.frames if t("access.summary", ok=3, total=5) in f)
    assert t("access.key_only.hint.agent") in flat(summary)
    assert t("access.key_only.hint") not in flat(summary)


class Done:
    def __init__(self, code, stderr):
        self.returncode, self.stdout, self.stderr = code, "", stderr


def test_ssh_transport_keeps_what_the_node_offers(monkeypatch, tmp_path):
    seen_argv = []

    def fake_run(argv, **kwargs):
        seen_argv.append(argv)
        return Done(255, "root@192.0.2.10: Permission denied (publickey).\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("kerberos.nodes.transport.SshTransport._run_dir", lambda self: "/tmp/k")
    transport = SshTransport(State(tmp_path))
    target = Target("u1", "nl-1", "192.0.2.10", 22)
    assert transport.offered_methods(target) is None
    assert transport.open_root(target, interactive=False) is False
    assert transport.offered_methods(target) == ["publickey"]
    # No IdentitiesOnly: the agent of `ssh -A` may offer the person's key.
    assert "IdentitiesOnly=yes" not in seen_argv[0]
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
    assert transport.agent_forwarded is True
    monkeypatch.delenv("SSH_AUTH_SOCK")
    assert transport.agent_forwarded is False


@pytest.mark.skipif(os.geteuid() == 0, reason="the launcher calls sudo only without root")
@pytest.mark.parametrize("sock", ["/tmp/ssh-test/agent.1", ""])
def test_launcher_hands_the_forwarded_key_to_sudo(tmp_path, sock):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    out = tmp_path / "argv"
    sudo = bin_dir / "sudo"
    sudo.write_text(f'#!/bin/sh\nfor a in "$@"; do echo "$a"; done > {out}\n')
    sudo.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k != "SSH_AUTH_SOCK"}
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    if sock:
        env["SSH_AUTH_SOCK"] = sock
    launcher = str(ROOT / "kerberos")
    subprocess.run([launcher, "check"], env=env, capture_output=True, timeout=30, check=True)
    argv = out.read_text().splitlines()
    if sock:
        assert argv == ["--", "env", f"SSH_AUTH_SOCK={sock}", launcher, "check"]
    else:
        assert argv == ["--", launcher, "check"]
