"""CDN origin filter and the watch on the node (tech.md §10.6 cdn.edge_only, §10.3)."""

import json
import os
import stat
import subprocess
import sys
import uuid

import pytest
from agent_helpers import APT_INSTALL, ROOT, call

from kerberos import agent

SITE = "/etc/nginx/sites-enabled/cdn"
SITE_TEXT = """server {
    listen 8443 ssl;
    server_name cdn.example.com;
    location /api/stream {
        proxy_pass http://127.0.0.1:2053;
    }
    location = /cdn-check {
        return 204;
    }
    location / {
        root /var/www/html;
    }
}
"""
IP_ADDR = json.dumps([{"ifname": "eth0", "addr_info": [
    {"family": "inet", "local": "198.51.100.77", "scope": "global"},
    {"family": "inet6", "local": "2001:db8::77", "scope": "global"},
]}])  # fmt: skip
PARAMS = {"paths": ["/api/stream"], "nets": ["192.0.2.0/24", "198.51.100.0/24"]}


def write(system, path, text, mode=0o644):
    full = system.path(path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fh:
        fh.write(text)
    os.chmod(full, mode)


def read(system, path):
    full = system.path(path)
    return open(full).read() if os.path.exists(full) else None


def apply(system, fix_id, params):
    change = str(uuid.uuid4())
    code, answer = call(system, ["apply", fix_id, change], json.dumps(params).encode())
    return change, code, answer


@pytest.fixture
def origin(system, recorder):
    for prefix in (["nginx"], ["systemctl"], ["apt-get"]):
        recorder.on(prefix, agent.Result(0))
    recorder.on(["ip", "-j", "addr", "show"], agent.Result(0, IP_ADDR))
    write(system, SITE, SITE_TEXT)
    write(system, "/etc/nginx/nginx.conf", "http { include /etc/nginx/conf.d/*.conf; }\n")
    return system


def test_edge_only_guards_the_tunnel_and_rolls_back(origin, recorder):
    change, code, answer = apply(origin, "cdn.edge_only", PARAMS)
    assert code == 0, answer
    geo = read(origin, agent.EDGES_CONF)
    assert "geo $from_cdn_edge {" in geo and "default 0;" in geo
    for address in ("127.0.0.1", "::1", "198.51.100.77", "2001:db8::77", "192.0.2.0/24",
                    "198.51.100.0/24"):  # fmt: skip
        assert f"    {address} 1;\n" in geo
    lines = read(origin, SITE).splitlines()
    tunnel = lines.index("    location /api/stream {")
    check = lines.index("    location = /cdn-check {")
    assert lines[tunnel + 1].strip() == agent.EDGE_SNIPPET, "first line of the location"
    assert lines[check + 1].strip() == agent.EDGE_SNIPPET
    assert "    location @kerberos_not_edge { return 404; }" in lines
    root = lines.index("    location / {")
    assert agent.EDGE_SNIPPET not in lines[root + 1], "the site itself stays open"
    calls = [c for c in recorder.calls if c[0] in ("nginx", "systemctl")]
    assert calls == [["nginx", "-t"], ["systemctl", "reload", "nginx"]]
    assert answer["details"] == {"site": SITE, "paths": ["/api/stream"],
                                 "nets": ["192.0.2.0/24", "198.51.100.0/24"]}  # fmt: skip
    code, answer = call(origin, ["rollback", change])
    assert code == 0 and answer["state"] == "rolled_back"
    assert read(origin, SITE) == SITE_TEXT and read(origin, agent.EDGES_CONF) is None
    assert recorder.calls[-1] == ["systemctl", "reload", "nginx"]
    _change, code, answer = apply(origin, "cdn.edge_only", PARAMS)
    assert code == 0 and read(origin, SITE).count(agent.EDGE_SNIPPET) == 2


def test_guard_is_idempotent():
    once = agent.edge_guarded(SITE_TEXT, ["/api/stream"])
    assert agent.edge_guarded(once, ["/api/stream"]) == once
    assert once.count(agent.EDGE_SNIPPET) == 2 and once.count("@kerberos_not_edge {") == 1


def test_linked_site_keeps_its_link(origin):
    os.remove(origin.path(SITE))
    write(origin, "/etc/nginx/sites-available/cdn", SITE_TEXT)
    os.symlink("../sites-available/cdn", origin.path(SITE))
    change, code, answer = apply(origin, "cdn.edge_only", PARAMS)
    assert code == 0, answer
    assert os.path.islink(origin.path(SITE))
    assert agent.EDGE_SNIPPET in read(origin, "/etc/nginx/sites-available/cdn")
    code, _answer = call(origin, ["rollback", change])
    assert code == 0 and os.path.islink(origin.path(SITE))
    assert read(origin, "/etc/nginx/sites-available/cdn") == SITE_TEXT


def test_realip_refuses(origin):
    write(origin, "/etc/nginx/nginx.conf",
          "http { set_real_ip_from 192.0.2.0/24; real_ip_header X-Forwarded-For; }\n")  # fmt: skip
    _change, code, answer = apply(origin, "cdn.edge_only", PARAMS)
    assert code == 1 and answer["error"]["code"] == "realip_enabled"
    assert read(origin, SITE) == SITE_TEXT and read(origin, agent.EDGES_CONF) is None


@pytest.mark.parametrize("params", [
    {"paths": ["/api/stream"], "nets": []},
    {"paths": ["/"], "nets": ["192.0.2.0/24"]},
    {"paths": ["/api/stream"], "nets": ["not-a-net"]},
    {"paths": ["/elsewhere"], "nets": ["192.0.2.0/24"]},
    {"paths": ["/api/stream; return 200"], "nets": ["192.0.2.0/24"]},
])  # fmt: skip
def test_bad_params(origin, params):
    _change, code, answer = apply(origin, "cdn.edge_only", params)
    assert code == 1 and answer["error"]["code"] == "bad_params"
    assert read(origin, SITE) == SITE_TEXT


def test_nginx_test_failure_restores(origin, recorder):
    recorder.on(["nginx", "-t"], agent.Result(1, "", "emerg"))
    _change, code, answer = apply(origin, "cdn.edge_only", PARAMS)
    assert code == 1 and answer["error"]["code"] == "nginx_test_failed"
    assert read(origin, SITE) == SITE_TEXT and read(origin, agent.EDGES_CONF) is None


# -- watch.install -------------------------------------------------------------
@pytest.fixture
def plain(system, recorder):
    for prefix in (["systemctl"], ["apt-get"]):
        recorder.on(prefix, agent.Result(0))
    return system


def test_watch_installs_and_rolls_back(plain, recorder):
    change, code, answer = apply(plain, "watch.install", {})
    assert code == 0, answer
    script = plain.path(agent.WATCH_BIN)
    assert stat.S_IMODE(os.stat(script).st_mode) == 0o755
    assert read(plain, agent.WATCH_CRON) == f"*/5 * * * * root {agent.WATCH_BIN} >/dev/null 2>&1\n"
    rotate = read(plain, agent.WATCH_ROTATE)
    assert rotate.startswith(agent.WATCH_LOG) and "monthly" in rotate
    assert [*APT_INSTALL, "cron", "logrotate"] in recorder.calls
    assert agent.collect_facts(plain)["watch"]["installed"] is True
    code, _answer = call(plain, ["rollback", change])
    assert code == 0
    assert not plain.exists(agent.WATCH_BIN) and not plain.exists(agent.WATCH_CRON)
    assert agent.collect_facts(plain)["watch"]["installed"] is False


def test_watch_skips_installed_packages(plain, recorder):
    write(plain, "/usr/sbin/cron", "")
    write(plain, "/usr/sbin/logrotate", "")
    _change, code, _answer = apply(plain, "watch.install", {})
    assert code == 0 and not any(c[0] == "apt-get" for c in recorder.calls)


def test_watch_script_writes_one_line_of_counts(tmp_path):
    log = tmp_path / "watch.log"
    script = agent.WATCH_SCRIPT.replace(agent.AGENT_PATH, str(ROOT / "src/kerberos/agent.py"))
    script = script.replace(agent.WATCH_LOG, str(log))
    path = tmp_path / "kerberos-watch"
    path.write_text(script)
    env = {"PATH": str(tmp_path / "no-commands")}  # no ss, no xray: counts are zero
    subprocess.run([sys.executable, "-I", "-S", str(path)], check=True, env=env, timeout=60)
    line = log.read_text()
    assert line.count("\n") == 1
    # no ss: no port of Xray is known, and the line says so (K18)
    assert " port=- conn=0 ips=0 cut=0 nets=- stall=0 users5m=None req5m=None" in line
