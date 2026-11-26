"""Package installs of the agent (tech.md §10.3): no dpkg prompt can fail them.

Found on the K24 stand: the person's /etc/letsencrypt/cli.ini made dpkg ask what to do
with it while self-steal installed certbot; the question read EOF, certbot stayed
half-configured and the agent answered apt_failed.
"""

import json
import os
import sys
import uuid

import pytest
from agent_helpers import APT_INSTALL, call

from kerberos import agent

DOMAIN = "de-1.example.com"
FAIL2BAN = {"sshPorts": [22], "panelIp": "198.51.100.5"}
ANSWERED = ("nginx", "systemctl", "certbot", "apt-get", "dpkg", "docker", "sysctl")
CONFIGURE = ["dpkg", "--force-confdef", "--force-confold", "--configure", "-a"]


def write(system, path, text, mode=0o644):
    full = system.path(path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fh:
        fh.write(text)
    os.chmod(full, mode)


def status(**packages):
    """/var/lib/dpkg/status with one stanza per package: name=state."""
    return "\n".join(
        f"Package: {name.replace('_', '-')}\nStatus: install ok {state}\nPriority: optional\n"
        "Architecture: arm64\nDescription: a package\n of the stand\n"
        for name, state in packages.items()
    )


@pytest.fixture
def node(system, recorder):
    for prefix in ANSWERED:
        recorder.on([prefix], agent.Result(0))
    recorder.on(
        ["ss"], agent.Result(0, 'tcp LISTEN 0 4096 *:443 *:* users:(("xray",pid=1,fd=7))\n')
    )
    return system


def apply(system, fix_id, params):
    change = str(uuid.uuid4())
    code, answer = call(system, ["apply", fix_id, change], json.dumps(params).encode())
    return change, code, answer


def installs(recorder):
    starts = (["apt-get", "install"], ["dpkg", "--force-confdef"])
    return [c for c in recorder.calls if c[:2] in starts]


def test_install_keeps_the_persons_config_files(node, recorder):
    write(node, "/etc/letsencrypt/cli.ini", "# mine\nrsa-key-size = 4096\n")
    _change, code, answer = apply(node, "self_steal.site", {"domain": DOMAIN, "siteSeed": 2})
    assert code == 0, answer
    assert installs(recorder) == [APT_INSTALL + ["nginx", "certbot"]]
    assert open(node.path("/etc/letsencrypt/cli.ini")).read() == "# mine\nrsa-key-size = 4096\n"


def test_retry_after_update_keeps_them_too(node, recorder):
    answers = iter([agent.Result(100, "", "E: Unable to locate package"), agent.Result(0)])
    recorder.on(["apt-get", "install"], lambda _argv, _input: next(answers))
    _change, code, answer = apply(node, "watch.install", {})
    assert code == 0, answer
    apt = [c for c in recorder.calls if c[:1] == ["apt-get"]]
    assert apt == [APT_INSTALL + ["cron", "logrotate"], ["apt-get", "update", "-q"],
                   APT_INSTALL + ["cron", "logrotate"]]  # fmt: skip


def test_half_configured_certbot_is_configured_before_the_install(node, recorder):
    """An earlier run left certbot iF and its library iU: its binary is there, and the
    agent used to take that for an installed certbot."""
    write(node, "/usr/sbin/nginx", "")
    write(node, "/usr/bin/certbot", "")
    dpkg = status(nginx="installed", certbot="half-configured", python3_certbot="unpacked")
    write(node, agent.DPKG_STATUS, dpkg)
    _change, code, answer = apply(node, "self_steal.site", {"domain": DOMAIN, "siteSeed": 2})
    assert code == 0, answer
    assert installs(recorder) == [CONFIGURE, APT_INSTALL + ["certbot"]]
    assert recorder.calls.index(CONFIGURE) < next(
        i for i, c in enumerate(recorder.calls) if c[0] == "certbot"
    )


def test_interrupted_dpkg_is_configured_before_the_install(node, recorder):
    """A killed dpkg leaves its journal: apt-get refuses anything until it is replayed."""
    write(node, f"{agent.DPKG_UPDATES}/0001", "")
    write(node, agent.DPKG_STATUS, status(cron="installed"))
    _change, code, answer = apply(node, "watch.install", {})
    assert code == 0, answer
    assert installs(recorder) == [CONFIGURE, APT_INSTALL + ["cron", "logrotate"]]


def test_failed_configure_still_tries_the_install(node, recorder):
    write(node, agent.DPKG_STATUS, status(fail2ban="half-configured"))
    write(node, "/usr/bin/fail2ban-client", "")
    recorder.on(["dpkg"], agent.Result(1, "", "dpkg: error processing package fail2ban"))
    recorder.on(["apt-get", "install"], agent.Result(100, "", "E: Sub-process dpkg returned 1"))
    _change, code, answer = apply(node, "fail2ban.sshd", FAIL2BAN)
    assert code == 1 and answer["error"]["code"] == "apt_failed"
    assert installs(recorder)[0] == CONFIGURE
    assert installs(recorder)[1:] == [APT_INSTALL + ["fail2ban", "python3-systemd"]] * 2
    assert not node.exists("/etc/fail2ban/jail.d/zz-kerberos.local")


def test_healthy_dpkg_is_left_alone(node, recorder):
    write(node, agent.DPKG_STATUS, status(nginx="installed", cron="installed"))
    os.makedirs(node.path(agent.DPKG_UPDATES))
    _change, code, answer = apply(node, "watch.install", {})
    assert code == 0, answer
    assert CONFIGURE not in recorder.calls


def test_nothing_to_install_touches_no_package(node, recorder):
    """A fix that installs nothing does not configure a package someone else left."""
    write(node, "/usr/sbin/cron", "")
    write(node, "/usr/sbin/logrotate", "")
    write(node, agent.DPKG_STATUS, status(cron="installed", logrotate="installed",
                                          grub_pc="half-configured"))  # fmt: skip
    _change, code, answer = apply(node, "watch.install", {})
    assert code == 0, answer
    assert installs(recorder) == []


@pytest.mark.parametrize("fix_id, params, package, binary", [
    ("watch.install", {}, "logrotate", "/usr/sbin/logrotate"),
    ("fail2ban.sshd", FAIL2BAN, "fail2ban", "/usr/bin/fail2ban-client"),
    ("mptcp.guard", {}, "nftables", "/usr/sbin/nft"),
])  # fmt: skip
def test_every_fix_installs_a_half_configured_package_again(node, recorder, fix_id, params,
                                                           package, binary):  # fmt: skip
    there = ("/usr/sbin/cron", "/usr/sbin/logrotate", "/usr/bin/fail2ban-client",
             "/usr/lib/python3/dist-packages/systemd/__init__.py", "/usr/sbin/nft")  # fmt: skip
    for path in there:
        write(node, path, "")
    write(node, "/proc/sys/net/mptcp/enabled", "1\n")
    write(node, agent.DPKG_STATUS, status(**{package.replace("-", "_"): "unpacked"}))
    _change, code, answer = apply(node, fix_id, params)
    assert code == 0, answer
    assert installs(recorder) == [CONFIGURE, APT_INSTALL + [package]]
    assert node.exists(binary)


def test_commands_never_read_the_ssh_channel():
    """A question gets EOF at once (here and on the stand VMs, whatever stdin pytest has)."""
    probe = ("import os, sys; print(len(sys.stdin.read()), os.environ['DEBIAN_FRONTEND'],"
             " os.environ['UCF_FORCE_CONFFOLD'])")  # fmt: skip
    result = agent.run_command([sys.executable, "-c", probe], timeout=20)
    assert (result.code, result.stdout.split()) == (0, ["0", "noninteractive", "1"])
    echo = agent.run_command([sys.executable, "-c", "import sys; print(sys.stdin.read())"],
                             input="given", timeout=20)  # fmt: skip
    assert echo.stdout == "given\n"
