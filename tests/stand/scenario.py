#!/usr/bin/env python3
"""Stand scenario (tech.md §17, §18): apply, roll back, apply again, on a real node.

Runs as root on a disposable stand VM only (tools/stand.sh copies it there).
It installs the agent from this checkout and drives it the way KERBEROS does,
then checks the effect through the agent's own facts and, for SSH, through new
connections to the ports. Never run it on a production server: it changes SSH,
nftables, fail2ban and, on Ubuntu 22.04, switches ufw on for a moment.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import socket
import subprocess
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.join(HERE, "..", "..", "src", "kerberos", "agent.py")
AGENT = "/usr/local/sbin/kerberos-agent"
PANEL = "198.51.100.5"  # documentation address standing in for the panel server
results: list = []


def agent(*args: str, payload: dict | None = None) -> tuple[int, dict]:
    env = dict(os.environ, SSH_CONNECTION=f"{PANEL} 50000 127.0.0.1 22")
    proc = subprocess.run(
        [sys.executable, AGENT, *args],
        input=json.dumps(payload or {}).encode(),
        capture_output=True,
        env=env,
        check=False,
    )
    lines = proc.stdout.decode().strip().splitlines()
    return proc.returncode, json.loads(lines[-1]) if lines else {}


def facts() -> dict:
    return agent("facts")[1]


def report(name: str, ok: bool, detail: str = "") -> None:
    results.append(ok)
    print(f"{'ok  ' if ok else 'FAIL'}  {name}" + (f": {detail}" if detail and not ok else ""))


def cycle(fix_id: str, params: dict, applied, restored, confirm: bool = False,
          describe=None) -> None:  # fmt: skip
    """Apply, check, roll back, check, apply again, roll back.

    `describe` turns facts into the detail printed when a check fails.
    """
    for round_no in (1, 2):
        change = str(uuid.uuid4())
        code, answer = agent("apply", fix_id, change, payload=params)
        report(f"{fix_id} apply #{round_no}", code == 0, json.dumps(answer))
        if code != 0:
            return
        if confirm:
            code, answer = agent("confirm", change)
            report(f"{fix_id} confirm #{round_no}", answer.get("state") == "confirmed")
        now = facts()
        report(f"{fix_id} effect #{round_no}", applied(now), describe(now) if describe else "")
        code, again = agent("apply", fix_id, change, payload=params)
        report(f"{fix_id} same changeId is noop", again.get("state") == "noop")
        code, answer = agent("rollback", change)
        report(f"{fix_id} rollback #{round_no}", answer.get("state") == "rolled_back",
               json.dumps(answer))  # fmt: skip
        now = facts()
        report(f"{fix_id} restored #{round_no}", restored(now), describe(now) if describe else "")


def ssh_answers(port: int) -> bool:
    """A new TCP connection to the port gets the banner of sshd: SSH really listens there."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
            conn.settimeout(10)
            return conn.recv(64).startswith(b"SSH-")
    except OSError:
        return False


def ufw_rules() -> str:
    return subprocess.run(["ufw", "status"], capture_output=True, text=True).stdout


def ssh_port_cycle(before: dict, ufw: bool = False) -> None:
    """ssh.port the way KERBEROS drives it (§10.3, §9.3): the new port must answer a new
    connection before confirm; a confirmed port goes back in two phases, the first time
    through `undo` (the old port did not answer), the second time to the end."""
    old = before["ssh"]["ports"]
    port = next(p for p in range(24622, 32767)
                if all(s["port"] != p for s in before["listening"]))  # fmt: skip
    name = "ssh.port with ufw" if ufw else "ssh.port"
    for round_no in (1, 2):
        change = str(uuid.uuid4())
        code, answer = agent("apply", "ssh.port", change, payload={"port": port})
        report(f"{name} apply #{round_no}", answer.get("state") == "pending_confirm",
               json.dumps(answer))  # fmt: skip
        if code != 0:
            return
        report(f"{name} new port answers before confirm", ssh_answers(port))
        report(f"{name} old port still answers", all(ssh_answers(p) for p in old))
        if ufw:
            report(f"{name} ufw lets the new port in", f"{port}/tcp" in ufw_rules())
        code, answer = agent("confirm", change)
        report(f"{name} confirm #{round_no}", answer.get("state") == "confirmed")
        report(f"{name} only the new port", ssh_answers(port)
               and not any(ssh_answers(p) for p in old))  # fmt: skip
        report(f"{name} facts", facts()["ssh"]["ports"] == [port])
        code, again = agent("apply", "ssh.port", change, payload={"port": port})
        report(f"{name} same changeId is noop", again.get("state") == "noop")
        code, answer = agent("rollback", change)
        report(f"{name} rollback waits for the old port", answer.get("state")
               == "rollback_pending", json.dumps(answer))  # fmt: skip
        report(f"{name} both ports again", ssh_answers(port) and all(ssh_answers(p) for p in old))
        timers = subprocess.run(["systemctl", "list-timers", "--all", "--no-pager"],
                                capture_output=True, text=True).stdout  # fmt: skip
        report(f"{name} undo timer of the rollback", f"kerberos-undo-{change}" in timers)
        if round_no == 1:
            code, answer = agent("undo", change)
            report(f"{name} undo keeps the confirmed port", answer.get("state") == "confirmed"
                   and ssh_answers(port) and not any(ssh_answers(p) for p in old))  # fmt: skip
            code, answer = agent("rollback", change)
            report(f"{name} rollback again", answer.get("state") == "rollback_pending")
        report(f"{name} old port answers a new connection", all(ssh_answers(p) for p in old))
        code, answer = agent("confirm", change)
        report(f"{name} rollback #{round_no}", answer.get("state") == "rolled_back",
               json.dumps(answer))  # fmt: skip
        report(f"{name} restored #{round_no}", facts()["ssh"]["ports"] == old
               and all(ssh_answers(p) for p in old) and not ssh_answers(port))  # fmt: skip
        if ufw:
            report(f"{name} ufw rule gone", f"{port}/tcp" not in ufw_rules())


def ufw_variant(before: dict) -> None:
    """Ubuntu 22.04 only: ssh.port with ufw active. The SSH ports are let in first and ufw
    is switched off again at the end, so the VM stays reachable."""
    if shutil.which("ufw") is None or before["firewall"]["ufw"] == "active":
        print("skip  ssh.port with ufw: no ufw, or it is in use already")
        return
    for port in before["ssh"]["ports"]:
        subprocess.run(["ufw", "allow", f"{port}/tcp"], capture_output=True, check=False)
    try:
        enabled = subprocess.run(["ufw", "--force", "enable"], capture_output=True, check=False)
        report("ufw switched on for the test", enabled.returncode == 0)
        if enabled.returncode == 0:
            ssh_port_cycle(facts(), ufw=True)
    finally:
        subprocess.run(["ufw", "--force", "disable"], capture_output=True, check=False)
        for port in before["ssh"]["ports"]:
            subprocess.run(["ufw", "--force", "delete", "allow", f"{port}/tcp"],
                           capture_output=True, check=False)  # fmt: skip


def listen(port: int) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    return server


WATCH_LOG = "/var/log/kerberos-watch.log"
STAND_KEY = "/tmp/kerberos-stand-key"
EDGE_SITE = "/etc/nginx/sites-enabled/kerberos-stand-cdn"
EDGE_CONF = "/etc/nginx/conf.d/kerberos-edges.conf"
EDGE_TEXT = """server {
    listen 127.0.0.1:8098;
    location /stand-tunnel {
        return 200;
    }
    location = /cdn-check {
        return 204;
    }
}
"""


def edge_filter() -> None:
    """cdn.edge_only on a plain nginx site of the stand: nginx must take the filter."""
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    if shutil.which("nginx") is None:
        subprocess.run(["apt-get", "install", "-y", "-qq", "nginx"], env=env, check=False,
                       capture_output=True)  # fmt: skip
    if shutil.which("nginx") is None:
        report("cdn.edge_only: nginx installed", False)
        return
    with open(EDGE_SITE, "w") as fh:
        fh.write(EDGE_TEXT)
    subprocess.run(["systemctl", "reload-or-restart", "nginx"], check=False)

    def guarded(_facts: dict) -> bool:
        return os.path.exists(EDGE_CONF) and "@kerberos_not_edge" in open(EDGE_SITE).read()

    def clean(_facts: dict) -> bool:
        return not os.path.exists(EDGE_CONF) and open(EDGE_SITE).read() == EDGE_TEXT

    try:
        cycle("cdn.edge_only", {"paths": ["/stand-tunnel"], "nets": ["192.0.2.0/24"]},
              guarded, clean)  # fmt: skip
    finally:
        os.remove(EDGE_SITE)
        subprocess.run(["systemctl", "reload", "nginx"], check=False)


CLI_INI = "/etc/letsencrypt/cli.ini"
# The person's own file. Its ACME server is a closed local port: certbot fails at once,
# no request leaves the VM, and that it went there shows the file was in use.
CLI_TEXT = "# the person's own settings\nserver = https://127.0.0.1:9/directory\n"
STAND_DOMAIN = "stand.example.com"


def dpkg_state(package: str) -> str:
    """`dpkg -l` letters: ii installed, iU unpacked, iF half-configured; '' not known."""
    out = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}", package],
                         capture_output=True, text=True, check=False)  # fmt: skip
    return out.stdout.strip() if out.returncode == 0 else ""


def certbot_conffile() -> None:
    """K24 stand: /etc/letsencrypt/cli.ini is there before self-steal installs certbot
    (tech.md §10.3). dpkg asks about it, and an install that cannot answer leaves certbot
    half-configured. The agent must keep the file, and configure such a certbot."""
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")

    def fresh() -> None:
        subprocess.run(["apt-get", "purge", "-y", "-q", "certbot"], env=env,
                       capture_output=True, check=False)  # fmt: skip
        os.makedirs(os.path.dirname(CLI_INI), exist_ok=True)
        with open(CLI_INI, "w") as fh:
            fh.write(CLI_TEXT)

    def site(name: str) -> None:
        code, answer = agent("apply", "self_steal.site", str(uuid.uuid4()),
                             payload={"domain": STAND_DOMAIN, "siteSeed": 1})  # fmt: skip
        # certbot_failed: the install went through and the site step reached certbot.
        report(f"{name}: certbot installs", code != 0
               and answer.get("error", {}).get("code") == "certbot_failed"
               and dpkg_state("certbot") == "ii",
               f"{dpkg_state('certbot')} {json.dumps(answer)}")  # fmt: skip
        report(f"{name}: the person's cli.ini stays", open(CLI_INI).read() == CLI_TEXT)
        report(f"{name}: the site went back", not any(
            STAND_DOMAIN in s["serverNames"] for s in facts()["nginx"]["sites"]))  # fmt: skip

    try:
        fresh()
        site("cli.ini before certbot")
        fresh()
        # What the agent did before: nobody answers dpkg, stdin at EOF.
        old = subprocess.run(["apt-get", "install", "-y", "-q", "certbot"], env=env,
                             stdin=subprocess.DEVNULL, capture_output=True, text=True,
                             check=False)  # fmt: skip
        if "conffile prompt" not in old.stdout + old.stderr:
            # certbot of this OS ships no cli.ini: leave it unpacked another way.
            print("note  certbot here has no cli.ini conffile: unpacking it instead")
            fresh()
            subprocess.run(["apt-get", "install", "-y", "-q", "--download-only", "certbot"],
                           env=env, capture_output=True, check=False)  # fmt: skip
            debs = sorted(glob.glob("/var/cache/apt/archives/certbot_*.deb"))
            if debs:
                subprocess.run(["dpkg", "--unpack", debs[-1]], capture_output=True, check=False)
        state = dpkg_state("certbot")
        report("certbot left half-configured", state in ("iU", "iF"), state)
        site("half-configured certbot")
    finally:
        for path in (CLI_INI, CLI_INI + ".dpkg-dist"):  # the domain cycle takes the default
            if os.path.exists(path):
                os.remove(path)


def main() -> int:
    if os.geteuid() != 0:
        print("run as root on a stand VM")
        return 2
    shutil.copyfile(SOURCE, AGENT)
    os.chmod(AGENT, 0o755)
    before = facts()
    print(f"{before['os']['id']} {before['os']['version']}, OpenSSH ports {before['ssh']['ports']}")

    if before["mptcp"]["enabled"] or os.path.exists("/proc/sys/net/mptcp/enabled"):
        cycle("mptcp.guard", {},
              lambda f: not f["mptcp"]["enabled"] and f["mptcp"]["ipOptionsDrop"],
              lambda f: f["mptcp"]["enabled"] == before["mptcp"]["enabled"]
              and "inet kerberos_mptcp" not in f["nftTables"])  # fmt: skip

    cycle("fail2ban.sshd", {"sshPorts": before["ssh"]["ports"], "panelIp": PANEL},
          lambda f: f["fail2ban"]["sshdJail"],
          lambda f: f["fail2ban"]["sshdJail"] == before["fail2ban"]["sshdJail"])  # fmt: skip

    server = listen(8099)
    try:

        def firewalled(f: dict) -> bool:
            return any(s["port"] == 8099 and s["firewalled"] for s in f["listening"])

        cycle("ports.drop", {"ports": ["8099/tcp"]}, firewalled, lambda f: not firewalled(f))
    finally:
        server.close()

    # K8: the watch, and the CDN filter on a stand site of its own.
    cycle("watch.install", {},
          lambda f: f["watch"]["installed"],
          lambda f: f["watch"]["installed"] == before["watch"]["installed"])  # fmt: skip
    change = str(uuid.uuid4())
    agent("apply", "watch.install", change)
    watch = subprocess.run(["/usr/local/sbin/kerberos-watch"], capture_output=True, check=False)
    lines = (open(WATCH_LOG).read().splitlines() if os.path.exists(WATCH_LOG) else []) or [""]
    report("watch writes one line of counts", watch.returncode == 0 and " conn=" in lines[-1],
           watch.stderr.decode()[-300:])  # fmt: skip
    agent("rollback", change)
    edge_filter()
    certbot_conffile()

    if before["nodeApi"]["port"] and before["remnanode"].get("network") == "host":
        cycle("node_api.panel_only", {"port": before["nodeApi"]["port"], "panelIp": PANEL},
              lambda f: f["nodeApi"]["panelOnly"],
              lambda f: f["nodeApi"]["panelOnly"] == before["nodeApi"]["panelOnly"])  # fmt: skip

    # Self-steal needs a real domain of the stand with its A record on this VM (§22).
    domain_file = os.path.join(HERE, "..", "..", "domain")
    domain = open(domain_file).read().strip() if os.path.exists(domain_file) else ""
    if domain:

        def has_site(f: dict) -> bool:
            return any(domain in s["serverNames"] for s in f["nginx"]["sites"])

        cycle("self_steal.site", {"domain": domain, "siteSeed": 1},
              lambda f: has_site(f) and any(c["domain"] == domain for c in f["certbot"]["certs"]),
              lambda f: not has_site(f))  # fmt: skip
    else:
        print("skip  self_steal.site: no stand domain for this VM")
    if os.path.exists("/opt/remnanode/docker-compose.yml"):
        cycle("node.letsencrypt_mount", {},
              lambda f: f["remnanode"]["letsencryptMounted"],
              lambda f: f["remnanode"]["letsencryptMounted"]
              == before["remnanode"]["letsencryptMounted"])  # fmt: skip

    # §8.5: the person's own key reaches the node: a throwaway key of this stand VM.
    for leftover in (STAND_KEY, STAND_KEY + ".pub"):  # a run before left its key
        if os.path.exists(leftover):
            os.remove(leftover)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "stand@kerberos",
                    "-f", STAND_KEY], check=True)  # fmt: skip
    key = open(STAND_KEY + ".pub").read().strip()
    cycle("access.admin_keys", {"keys": [key]},
          lambda f: f["ssh"]["adminKeys"] == before["ssh"]["adminKeys"] + 1,
          lambda f: f["ssh"]["adminKeys"] == before["ssh"]["adminKeys"])  # fmt: skip

    # Taken right before the cycle: the keys of a fresh cloud VM may change at first boot.
    old = {k["fingerprint"] for k in facts()["hostKeys"]}

    def renewed(f: dict) -> set:
        """A DSA key of the image stays as it is (tech.md §10.3); every other key is new."""
        return {k["fingerprint"] for k in f["hostKeys"] if k["type"] not in ("ssh-dss", "DSA")}

    cycle("hostkeys.regenerate", {},
          lambda f: bool(renewed(f)) and not (renewed(f) & old),
          lambda f: {k["fingerprint"] for k in f["hostKeys"]} == old, confirm=True,
          describe=lambda f: json.dumps(sorted(k["fingerprint"][-8:] for k in f["hostKeys"])
                                        + ["was"] + sorted(o[-8:] for o in old)))  # fmt: skip

    ssh_port_cycle(before)
    if (before["os"]["id"], before["os"]["version"]) == ("ubuntu", "22.04"):
        ufw_variant(before)

    if before["ssh"]["adminKeys"]:
        # K28: SSH only from the panel. The scenario itself runs over SSH from elsewhere:
        # that it goes on proves the open session survives the rule.
        cycle("ssh.panel_only", {"panelIp": PANEL},
              lambda f: f["ssh"]["guarded"] == f["ssh"]["ports"]
              and "inet kerberos_ssh" in f["nftTables"],
              lambda f: f["ssh"]["guarded"] == before["ssh"]["guarded"]
              and "inet kerberos_ssh" not in f["nftTables"], confirm=True,
              describe=lambda f: json.dumps([f["ssh"]["ports"], f["ssh"]["guarded"]]))  # fmt: skip
        report("sshd answers on loopback after ssh.panel_only", all(
            ssh_answers(p) for p in facts()["ssh"]["ports"]))  # fmt: skip
        cycle("ssh.key_only", {},
              lambda f: not f["ssh"]["passwordAuthentication"],
              lambda f: f["ssh"]["passwordAuthentication"]
              == before["ssh"]["passwordAuthentication"], confirm=True)  # fmt: skip
        # The confirmation never comes: the undo timer must exist and roll back.
        change = str(uuid.uuid4())
        agent("apply", "ssh.key_only", change)
        timers = subprocess.run(["systemctl", "list-timers", "--all", "--no-pager"],
                                capture_output=True, text=True).stdout  # fmt: skip
        report("undo timer is armed", f"kerberos-undo-{change}" in timers)
        # --wait: the undo must finish before the late confirm, or the confirm may win.
        subprocess.run(["systemctl", "--wait", "start", f"kerberos-undo-{change}.service"],
                       check=False)  # fmt: skip
        code, answer = agent("confirm", change)
        report("timer rolled the change back", answer.get("error", {}).get("code")
               == "change_conflict")  # fmt: skip
        report("password login is back as it was", facts()["ssh"]["passwordAuthentication"]
               == before["ssh"]["passwordAuthentication"])  # fmt: skip
    else:
        code, answer = agent("apply", "ssh.key_only", str(uuid.uuid4()))
        report("ssh.key_only refuses without an admin key",
               answer.get("error", {}).get("code") == "no_admin_key")  # fmt: skip

    failed = results.count(False)
    print(f"\n{len(results) - failed} ok, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
