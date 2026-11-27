"""Agent changes (tech.md §9.3, §10.3): backup, apply, rollback, timer, idempotency."""

import json
import os
import stat
import uuid

import pytest
from agent_helpers import APT_INSTALL, Recorder, call

from kerberos import agent

ADMIN = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBkLQ1Bbnn3QgWxB8dkF5rQ7m+9Cqg admin@laptop"
KERBEROS = (
    'from="198.51.100.5",command="/usr/local/sbin/kerberos-agent",restrict '
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKerberosKerberosKerberosKerb k@panel"
)


def new_id() -> str:
    return str(uuid.uuid4())


def write(system, path, text, mode=0o644):
    full = system.path(path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fh:
        fh.write(text)
    os.chmod(full, mode)


def read(system, path):
    full = system.path(path)
    return open(full).read() if os.path.exists(full) else None


def ok(recorder, *prefixes):
    for prefix in prefixes:
        recorder.on(prefix, agent.Result(0))


@pytest.fixture
def node(system, recorder):
    """A node with the usual commands succeeding."""
    ok(recorder, ["systemctl"], ["sysctl"], ["sshd", "-t"], ["systemd-run"], ["apt-get"])
    recorder.on(["docker", "ps"], agent.Result(0, ""))
    recorder.on(["docker", "inspect"], agent.Result(0, json.dumps([{"HostConfig": {
        "NetworkMode": "host"}, "Config": {"Env": ["NODE_PORT=2222"]}}])))  # fmt: skip
    recorder.on(["ss"], agent.Result(0, ""))
    system.environ["SSH_CONNECTION"] = "198.51.100.5 41022 203.0.113.10 22"
    write(system, "/proc/sys/net/mptcp/enabled", "1\n")
    write(system, "/root/.ssh/authorized_keys", ADMIN + "\n" + KERBEROS + "\n", 0o600)
    return system


def apply(system, fix_id, params, change_id=None):
    change_id = change_id or new_id()
    code, answer = call(system, ["apply", fix_id, change_id], json.dumps(params).encode())
    return change_id, code, answer


def test_mptcp_guard_apply_rollback_apply(node, recorder):
    change, code, answer = apply(node, "mptcp.guard", {})
    assert code == 0 and answer["state"] == "applied"
    assert read(node, "/etc/sysctl.d/98-kerberos-mptcp.conf") == "net.mptcp.enabled = 0\n"
    nft = read(node, "/etc/kerberos/mptcp.nft")
    assert "ip protocol tcp ip hdrlength > 5 counter drop" in nft
    assert nft.startswith("table inet kerberos_mptcp\nflush table inet kerberos_mptcp\n")
    assert "ExecStart=/usr/sbin/nft -f /etc/kerberos/mptcp.nft" in read(
        node, "/etc/systemd/system/kerberos-mptcp.service"
    )
    assert ["sysctl", "-w", "net.mptcp.enabled=0"] in recorder.calls
    assert ["systemctl", "restart", "kerberos-mptcp.service"] in recorder.calls
    code, answer = call(node, ["rollback", change])
    assert code == 0 and answer["state"] == "rolled_back"
    assert read(node, "/etc/sysctl.d/98-kerberos-mptcp.conf") is None
    assert read(node, "/etc/kerberos/mptcp.nft") is None
    assert ["systemctl", "disable", "--now", "kerberos-mptcp.service"] in recorder.calls
    assert recorder.calls[-1] == ["sysctl", "-w", "net.mptcp.enabled=1"]
    _change, code, answer = apply(node, "mptcp.guard", {})
    assert code == 0 and answer["state"] == "applied"


def test_same_change_id_is_noop(node, recorder):
    change, _code, first = apply(node, "mptcp.guard", {})
    calls = len(recorder.calls)
    _change, code, again = apply(node, "mptcp.guard", {}, change)
    assert code == 0 and again["state"] == "noop" and len(recorder.calls) == calls
    assert again["files"] == first["files"]


def test_rollback_restores_bytes_and_modes(node):
    write(node, "/etc/fail2ban/jail.d/zz-kerberos.local", "[sshd]\nenabled = false\n", 0o640)
    write(node, "/usr/bin/fail2ban-client", "#!/bin/sh\n")
    change, code, _answer = apply(node, "fail2ban.sshd", {"sshPorts": [22, 24622]})
    assert code == 0
    jail = read(node, "/etc/fail2ban/jail.d/zz-kerberos.local")
    assert "port = 22,24622" in jail and "backend = systemd" in jail
    assert "ignoreip = 127.0.0.1/8 ::1 198.51.100.5" in jail
    call(node, ["rollback", change])
    path = node.path("/etc/fail2ban/jail.d/zz-kerberos.local")
    assert open(path).read() == "[sshd]\nenabled = false\n"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o640


def test_fail2ban_installs_packages_and_removes_on_rollback(node, recorder):
    change, code, _answer = apply(node, "fail2ban.sshd", {"sshPorts": [22]})
    assert code == 0
    assert [*APT_INSTALL, "fail2ban", "python3-systemd"] in recorder.calls
    call(node, ["rollback", change])
    assert ["apt-get", "remove", "-y", "-q", "fail2ban"] in recorder.calls


def test_apt_failure(node, recorder):
    recorder.on(["apt-get", "install"], agent.Result(100, "", "E: Unable to locate package"))
    _change, code, answer = apply(node, "fail2ban.sshd", {"sshPorts": [22]})
    assert code == 1 and answer["error"]["code"] == "apt_failed"
    assert read(node, "/etc/fail2ban/jail.d/zz-kerberos.local") is None


def test_node_api_rules_and_bridge_refusal(node, recorder):
    recorder.on(["ss", "-Htn"], agent.Result(0, "0 0 203.0.113.10:2222 198.51.100.5:41022\n"))
    _change, code, answer = apply(
        node, "node_api.panel_only", {"port": 2222, "panelIp": "198.51.100.5"}
    )
    assert code == 0, answer
    nft = read(node, "/etc/kerberos/node-api.nft")
    assert "tcp dport 2222 ip saddr 198.51.100.5 counter accept" in nft
    assert nft.index("accept") < nft.index("tcp dport 2222 counter drop")
    recorder.on(["docker", "inspect"], agent.Result(0, json.dumps([{"HostConfig": {
        "NetworkMode": "remnanode_default"}, "Config": {"Env": []}}])))  # fmt: skip
    _change, code, answer = apply(node, "node_api.panel_only", {"port": 2222})
    assert code == 1 and answer["error"]["code"] == "bridge_network"


def test_ports_drop_keeps_earlier_ports_and_refuses_docker(node, recorder):
    _c, code, _a = apply(node, "ports.drop", {"ports": ["8080/tcp"]})
    assert code == 0
    _c, code, _a = apply(node, "ports.drop", {"ports": ["9090/tcp"]})
    nft = read(node, "/etc/kerberos/ports.nft")
    assert 'iifname != "lo" tcp dport 8080 drop' in nft and "tcp dport 9090 drop" in nft
    recorder.on(["docker", "ps"], agent.Result(0, json.dumps({"Ports": "0.0.0.0:3000->3000/tcp"})))
    _c, code, answer = apply(node, "ports.drop", {"ports": ["3000/tcp"]})
    assert code == 1 and answer["error"]["code"] == "docker_published"


def test_key_only_needs_an_admin_key(node):
    write(node, "/root/.ssh/authorized_keys", KERBEROS + "\n", 0o600)
    _change, code, answer = apply(node, "ssh.key_only", {})
    assert code == 1 and answer["error"]["code"] == "no_admin_key"
    assert read(node, agent.SSHD_CONF) is None


def test_key_only_waits_for_confirmation_with_a_timer(node, recorder):
    change, code, answer = apply(node, "ssh.key_only", {})
    assert code == 0 and answer["state"] == "pending_confirm"
    assert read(node, agent.SSHD_CONF) == (
        "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
        "PermitRootLogin prohibit-password\n"
    )
    assert ["systemd-run", "--on-active=180", "--unit", f"kerberos-undo-{change}",
            "/usr/local/sbin/kerberos-agent", "undo", change] in recorder.calls  # fmt: skip
    assert read(node, agent.PENDING_FILE).strip() == change
    _c, code, answer = apply(node, "mptcp.guard", {})
    assert code == 1 and answer["error"]["code"] == "change_conflict"
    code, answer = call(node, ["confirm", change])
    assert code == 0 and answer["state"] == "confirmed"
    assert ["systemctl", "stop", f"kerberos-undo-{change}.timer"] in recorder.calls
    assert read(node, agent.PENDING_FILE) == ""


def test_timer_rolls_back_when_confirm_never_comes(node):
    change, _code, _answer = apply(node, "ssh.key_only", {})
    # systemd calls the agent with arguments after 180 seconds
    code, answer = call(node, ["rollback", change])
    assert code == 0 and answer["state"] == "rolled_back"
    assert read(node, agent.SSHD_CONF) is None
    code, answer = call(node, ["confirm", change])
    assert code == 1 and answer["error"]["code"] == "change_conflict"


def test_sshd_test_failure_restores_the_file(node, recorder):
    recorder.on(["sshd", "-t"], agent.Result(255, "", "line 1: Bad configuration option"))
    _change, code, answer = apply(node, "ssh.key_only", {})
    assert code == 1 and answer["error"]["code"] == "sshd_test_failed"
    assert read(node, agent.SSHD_CONF) is None


def test_key_only_keeps_port_lines(node):
    write(node, agent.SSHD_CONF, "Port 22\nPort 24622\n")
    apply(node, "ssh.key_only", {})
    assert read(node, agent.SSHD_CONF).endswith("Port 22\nPort 24622\n")


def test_hostkeys_regenerate_and_roll_back(node, recorder):
    write(node, "/etc/ssh/ssh_host_ed25519_key", "old private\n", 0o600)
    write(
        node,
        "/etc/ssh/ssh_host_ed25519_key.pub",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOldOldOldOldOldOldOldOldOldOldOld root@old\n",
    )

    def keygen(argv, _input):
        import base64

        name, path = argv[argv.index("-t") + 1], argv[argv.index("-f") + 1]
        blob = base64.b64encode(f"new {name} key material".encode()).decode()
        write(node, path, f"new {name}\n", 0o600)
        write(node, path + ".pub", f"ssh-{name} {blob} root@new\n")
        return agent.Result(0)

    recorder.on(["ssh-keygen"], keygen)
    change, code, answer = apply(node, "hostkeys.regenerate", {})
    assert code == 0 and answer["state"] == "pending_confirm"
    assert any(k["type"] == "ED25519" for k in answer["details"]["hostKeys"])
    assert read(node, "/etc/ssh/ssh_host_ed25519_key") == "new ed25519\n"
    call(node, ["rollback", change])
    assert read(node, "/etc/ssh/ssh_host_ed25519_key") == "old private\n"
    assert read(node, "/etc/ssh/ssh_host_rsa_key") is None
    mode = stat.S_IMODE(os.stat(node.path("/etc/ssh/ssh_host_ed25519_key")).st_mode)
    assert mode == 0o600


def test_admin_keys_are_added_once(node):
    other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherOtherOtherOtherOther other@pc"
    change, code, answer = apply(node, "access.admin_keys", {"keys": [ADMIN, other]})
    assert code == 0 and answer["details"]["added"] == 1
    assert read(node, "/root/.ssh/authorized_keys").count("other@pc") == 1
    _c, code, answer = apply(node, "access.admin_keys", {"keys": ["ssh-ed25519 x\nrm -rf"]})
    assert code == 1 and answer["error"]["code"] == "bad_params"
    call(node, ["rollback", change])
    assert "other@pc" not in read(node, "/root/.ssh/authorized_keys")


def test_rollback_refuses_when_a_file_changed_later(node):
    change, _code, _answer = apply(node, "ports.drop", {"ports": ["8080/tcp"]})
    write(node, "/etc/kerberos/ports.nft", "edited by hand\n")
    code, answer = call(node, ["rollback", change])
    assert code == 1 and answer["error"]["code"] == "change_conflict"


def test_damaged_or_missing_backup(node):
    write(node, "/etc/kerberos/ports.nft", "old\n")
    change, _code, _answer = apply(node, "ports.drop", {"ports": ["8080/tcp"]})
    write(node, f"{agent.change_dir(change)}/files/0", "tampered\n")
    code, answer = call(node, ["rollback", change])
    assert code == 1 and answer["error"]["code"] == "backup_damaged"
    code, answer = call(node, ["rollback", new_id()])
    assert code == 1 and answer["error"]["code"] == "no_backup"


def test_mptcp_absent(node):
    os.remove(node.path("/proc/sys/net/mptcp/enabled"))
    _change, code, answer = apply(node, "mptcp.guard", {})
    assert code == 1 and answer["error"]["code"] == "mptcp_absent"


def test_plan_previews_without_changing(node, recorder):
    code, answer = call(node, ["plan", "ssh.key_only"], b"{}")
    assert code == 0 and answer["files"][0]["path"] == agent.SSHD_CONF
    assert "sshd -t" in answer["commands"]
    assert read(node, agent.SSHD_CONF) is None


def test_unknown_fix(node):
    _change, code, answer = apply(node, "made.up", {})
    assert code == 1 and answer["error"]["code"] == "not_implemented"


def test_backup_directory_is_private(node):
    write(node, "/etc/kerberos/ports.nft", "old\n")
    change, _code, _answer = apply(node, "ports.drop", {"ports": ["8080/tcp"]})
    record = node.path(f"{agent.change_dir(change)}/rollback.json")
    assert stat.S_IMODE(os.stat(record).st_mode) == 0o600
    assert json.loads(open(record).read())["files"][0]["existed"] is True


def test_recorder_is_reused_for_command_order(node, recorder):
    assert isinstance(recorder, Recorder)


# -- SSH only from the panel server (tech.md §9.2, §10.3, K28) ----------------------------
# The rule lets SSH in only from the address this very session of KERBEROS comes from; open
# sessions stay. It is an access change: a timer puts it back unless a new connection of
# KERBEROS confirms it.

PANEL = "198.51.100.5"
SSHD_22 = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=7,fd=3))\n'
SSHD_BOTH = SSHD_22 + 'tcp LISTEN 0 128 0.0.0.0:24622 0.0.0.0:* users:(("sshd",pid=7,fd=4))\n'
IP_ADDR = json.dumps([{"ifname": "eth0", "addr_info": [
    {"family": "inet", "local": "203.0.113.10", "scope": "global", "prefixlen": 24}]}])  # fmt: skip


def listening(recorder, text=SSHD_22):
    recorder.on(["ss", "-Hlntup"], agent.Result(0, text))
    recorder.on(["ip", "-j", "addr", "show"], agent.Result(0, IP_ADDR))


def test_ssh_answers_only_the_panel_and_open_sessions_stay(node, recorder):
    listening(recorder, SSHD_BOTH)
    change, code, answer = apply(node, "ssh.panel_only", {"panelIp": PANEL})
    assert code == 0, answer
    assert answer["state"] == "pending_confirm", "an access change waits for a new login"
    nft = read(node, "/etc/kerberos/ssh.nft")
    assert nft.startswith("table inet kerberos_ssh\nflush table inet kerberos_ssh\n")
    rules = [line.strip() for line in nft.splitlines()]
    assert rules.index("tcp dport { 22, 24622 } ct state established,related accept") < rules.index(
        "tcp dport { 22, 24622 } counter drop"
    )
    assert 'iifname "lo" tcp dport { 22, 24622 } accept' in rules
    assert f"tcp dport {{ 22, 24622 }} ip saddr {PANEL} counter accept" in rules
    assert answer["details"] == {"ports": [22, 24622], "panelIp": PANEL}
    assert any(c[:1] == ["systemd-run"] and "kerberos-undo-" + change in " ".join(c)
               for c in recorder.calls), "the timer puts it back without a confirm"  # fmt: skip
    code, answer = call(node, ["confirm", change])
    assert code == 0 and answer["state"] == "confirmed"
    code, answer = call(node, ["rollback", change])
    assert code == 0 and answer["state"] == "rolled_back"
    assert read(node, "/etc/kerberos/ssh.nft") is None
    assert ["systemctl", "disable", "--now", "kerberos-ssh.service"] in recorder.calls


def test_a_session_from_another_address_is_refused(node, recorder):
    listening(recorder)
    node.environ["SSH_CONNECTION"] = "192.0.2.77 41022 203.0.113.10 22"
    _change, code, answer = apply(node, "ssh.panel_only", {"panelIp": PANEL})
    assert code == 1 and answer["error"]["code"] == "panel_not_peer"
    assert read(node, "/etc/kerberos/ssh.nft") is None


def test_the_panel_server_on_this_very_node_is_refused(node, recorder):
    listening(recorder)
    node.environ["SSH_CONNECTION"] = "203.0.113.10 41022 203.0.113.10 22"
    _change, code, answer = apply(node, "ssh.panel_only", {"panelIp": "203.0.113.10"})
    assert code == 1 and answer["error"]["code"] == "panel_local"
    node.environ["SSH_CONNECTION"] = "127.0.0.1 41022 127.0.0.1 22"
    _change, code, answer = apply(node, "ssh.panel_only", {"panelIp": "127.0.0.1"})
    assert code == 1 and answer["error"]["code"] == "panel_local", "3x-ui: SSH only from itself"


def test_no_key_of_the_person_no_rule(node, recorder):
    listening(recorder)
    write(node, "/root/.ssh/authorized_keys", KERBEROS + "\n", 0o600)
    _change, code, answer = apply(node, "ssh.panel_only", {"panelIp": PANEL})
    assert code == 1 and answer["error"]["code"] == "no_admin_key"


def test_applied_twice_with_one_change_id_is_a_noop(node, recorder):
    listening(recorder)
    change, code, _answer = apply(node, "ssh.panel_only", {"panelIp": PANEL})
    assert code == 0
    _change, code, answer = apply(node, "ssh.panel_only", {"panelIp": PANEL}, change)
    assert code == 0 and answer["state"] == "noop"


def nft_rule(port: int, verdict: str, saddr: str = "") -> dict:
    expr = [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                       "right": port}}]  # fmt: skip
    if saddr:
        expr.insert(0, {"match": {"op": "==", "left": {"payload": {"protocol": "ip",
                                                                   "field": "saddr"}},
                                  "right": saddr}})  # fmt: skip
    expr.append({verdict: None})
    return {"rule": {"family": "inet", "table": "kerberos_ssh", "chain": "input", "expr": expr}}


def test_facts_say_which_ports_of_ssh_are_guarded():
    ruleset = agent.Ruleset(json.dumps({"nftables": [
        {"table": {"family": "inet", "name": "kerberos_ssh"}},
        {"chain": {"family": "inet", "table": "kerberos_ssh", "name": "input", "hook": "input"}},
        nft_rule(22, "accept", PANEL),
        nft_rule(22, "drop"),
    ]}))  # fmt: skip
    assert 22 in ruleset.dropped("tcp") and 24622 not in ruleset.dropped("tcp")
