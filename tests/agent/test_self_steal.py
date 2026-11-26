"""Self-steal on the node (tech.md §10.4 step 1, §10.9 node.letsencrypt_mount)."""

import json
import os
import stat
import uuid

import pytest
from agent_helpers import APT_INSTALL, call

from kerberos import agent

DOMAIN = "de-1.example.com"


def write(system, path, text, mode=0o644):
    full = system.path(path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fh:
        fh.write(text)
    os.chmod(full, mode)


def read(system, path):
    full = system.path(path)
    return open(full).read() if os.path.exists(full) else None


@pytest.fixture
def node(system, recorder):
    for prefix in (["nginx"], ["systemctl"], ["certbot"], ["apt-get"], ["docker"]):
        recorder.on(prefix, agent.Result(0))
    recorder.on(
        ["ss"], agent.Result(0, 'tcp LISTEN 0 4096 *:443 *:* users:(("xray",pid=1,fd=7))\n')
    )
    return system


def apply(system, fix_id, params):
    change = str(uuid.uuid4())
    code, answer = call(system, ["apply", fix_id, change], json.dumps(params).encode())
    return change, code, answer


def test_site_steps_in_order(node, recorder):
    change, code, answer = apply(node, "self_steal.site", {"domain": DOMAIN, "siteSeed": 2})
    assert code == 0, answer
    assert [*APT_INSTALL, "nginx", "certbot"] in recorder.calls
    queries = (["is-enabled"], ["is-active"])  # the state of nginx, read before anything
    calls = [c for c in recorder.calls
             if c[0] in ("nginx", "certbot", "systemctl") and c[1:2] not in queries]  # fmt: skip
    certbot = next(i for i, c in enumerate(calls) if c[0] == "certbot")
    assert calls[:certbot] == [
        ["nginx", "-t"],
        ["systemctl", "enable", "nginx"],
        ["systemctl", "reload-or-restart", "nginx"],
    ]
    assert calls[certbot] == [
        "certbot",
        "certonly",
        "--webroot",
        "-w",
        agent.ACME_ROOT,
        "-d",
        DOMAIN,
        "--register-unsafely-without-email",
        "--agree-tos",
        "--non-interactive",
        "--keep-until-expiring",
    ]
    assert calls[certbot + 1 :] == [["nginx", "-t"], ["systemctl", "reload", "nginx"]]
    conf = read(node, agent.SITE_CONF)
    assert "listen 127.0.0.1:8445 ssl http2;" in conf
    assert f"/etc/letsencrypt/live/{DOMAIN}/fullchain.pem" in conf
    assert "location /.well-known/acme-challenge/" in conf and "return 301 https" in conf
    hook = node.path(agent.RENEW_HOOK)
    assert open(hook).read() == "#!/bin/sh\nsystemctl reload nginx\n"
    assert stat.S_IMODE(os.stat(hook).st_mode) == 0o755
    html = agent.site_html(2, DOMAIN)
    assert read(node, f"{agent.SITE_ROOT}/index.html") == html
    assert answer["details"]["template"] == agent.template_hash(html)
    code, answer = call(node, ["rollback", change])
    assert answer["state"] == "rolled_back"
    assert read(node, agent.SITE_CONF) is None and read(node, agent.RENEW_HOOK) is None
    assert ["systemctl", "disable", "--now", "nginx"] in recorder.calls


def test_port_80_taken_by_something_else(node, recorder):
    recorder.on(
        ["ss"],
        agent.Result(0, 'tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("apache2",pid=5,fd=4))\n'),
    )
    _c, code, answer = apply(node, "self_steal.site", {"domain": DOMAIN})
    assert code == 1 and answer["error"]["code"] == "port80_busy"


def test_certbot_failure_leaves_nothing(node, recorder):
    write(node, "/usr/sbin/nginx", "")
    recorder.on(["certbot"], agent.Result(1, "", "Challenge failed"))
    _c, code, answer = apply(node, "self_steal.site", {"domain": DOMAIN})
    assert code == 1 and answer["error"]["code"] == "certbot_failed"
    assert read(node, agent.SITE_CONF) is None
    assert read(node, f"{agent.ACME_ROOT}/.kerberos") is None


def test_nginx_test_failure(node, recorder):
    recorder.on(["nginx", "-t"], agent.Result(1, "", "emerg"))
    _c, code, answer = apply(node, "self_steal.site", {"domain": DOMAIN})
    assert code == 1 and answer["error"]["code"] == "nginx_test_failed"


@pytest.mark.parametrize(
    "params",
    [
        {"domain": "bad domain"},
        {"domain": DOMAIN, "siteSeed": -1},
        {"domain": DOMAIN, "siteSeed": True},
    ],
)
def test_bad_params(node, params):
    _c, code, answer = apply(node, "self_steal.site", params)
    assert code == 1 and answer["error"]["code"] == "bad_params"


def test_layouts_differ_by_seed_not_by_domain():
    hashes = [agent.template_hash(agent.site_html(seed, DOMAIN)) for seed in range(4)]
    assert len(set(hashes)) == 4
    other = [agent.template_hash(agent.site_html(seed, "fi-1.example.net")) for seed in range(4)]
    assert hashes == other
    assert agent.site_html(1, DOMAIN) != agent.site_html(1, "fi-1.example.net")


COMPOSE = """services:
  remnanode:
    container_name: remnanode
    image: remnawave/node:latest
    network_mode: host
    volumes:
      - /var/log/remnanode:/var/log/remnanode
    env_file:
      - .env
"""


def test_letsencrypt_mount(node, recorder):
    write(node, agent.COMPOSE_FILE, COMPOSE)
    change, code, _answer = apply(node, "node.letsencrypt_mount", {})
    assert code == 0
    text = read(node, agent.COMPOSE_FILE)
    log = "      - /var/log/remnanode:/var/log/remnanode\n"
    assert log + "      - /etc/letsencrypt:/etc/letsencrypt:ro\n" in text
    assert ["docker", "compose", "-f", agent.COMPOSE_FILE, "up", "-d"] in recorder.calls
    call(node, ["rollback", change])
    assert read(node, agent.COMPOSE_FILE) == COMPOSE


def test_letsencrypt_mount_twice_changes_nothing(node, recorder):
    write(node, agent.COMPOSE_FILE, COMPOSE)
    apply(node, "node.letsencrypt_mount", {})
    before = read(node, agent.COMPOSE_FILE)
    _c, code, answer = apply(node, "node.letsencrypt_mount", {})
    assert code == 0 and answer["files"] == [] and read(node, agent.COMPOSE_FILE) == before


def test_letsencrypt_mount_needs_the_compose_file(node):
    _c, code, answer = apply(node, "node.letsencrypt_mount", {})
    assert code == 1 and answer["error"]["code"] == "bad_params"
