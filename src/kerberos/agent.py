#!/usr/bin/env python3
"""KERBEROS agent (tech.md §9): one file, Python 3.9+, standard library only.

Installed on a node as /usr/local/sbin/kerberos-agent and reached only
through the restricted KERBEROS key (`command=` in authorized_keys), so the
requested command arrives in SSH_ORIGINAL_COMMAND. The rollback timer of
systemd calls it with arguments instead. Only the commands of §9.1 are
accepted; parameters are checked with regular expressions and data comes as
JSON on stdin. The answer is one JSON object on stdout; on an error the exit
code is not 0 and the body is {"error": {"code", "message"}}.

Every function works on a `System`: the root of the file system and the
command runner, so tests run the same code against a temporary directory
and recorded command outputs.
"""

from __future__ import annotations

import base64
import calendar
import colorsys
import contextlib
import fcntl
import hashlib
import html
import ipaddress
import json
import os
import platform
import re
import shlex
import socket
import ssl
import subprocess
import sys
import time
from typing import Any, Callable, Optional

PROTOCOL = 1
AGENT_VERSION = "0.12.0"
AGENT_PATH = "/usr/local/sbin/kerberos-agent"
STATE_DIR = "/var/lib/kerberos"

ERROR_CODES = frozenset(
    """bad_params unknown_command sha_mismatch no_admin_key sshd_test_failed ssh_port
    port_busy bridge_network docker_published mptcp_absent port80_busy certbot_failed
    nginx_test_failed realip_enabled apt_failed change_conflict no_backup backup_damaged
    not_implemented command_failed panel_not_peer acme_check_failed acme_standalone
    certbot_hook panel_local""".split()
)

FIX_ID = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
CHANGE_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AgentError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        if code not in ERROR_CODES:
            raise ValueError(f"unknown agent error code {code}")
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class Result:
    def __init__(self, code: int, stdout: str = "", stderr: str = "") -> None:
        self.code = code
        self.stdout = stdout
        self.stderr = stderr

    @property
    def ok(self) -> bool:
        return self.code == 0


def run_command(argv: list[str], input: Optional[str] = None, timeout: float = 120) -> Result:
    # No command reads the SSH channel: a prompt gets EOF at once instead of waiting.
    stdin = {"input": input} if input is not None else {"stdin": subprocess.DEVNULL}
    env = dict(os.environ, LC_ALL="C", LANG="C", DEBIAN_FRONTEND="noninteractive")
    env["UCF_FORCE_CONFFOLD"] = "1"  # ucf keeps the person's file too, like dpkg (§10.3)
    try:
        proc = subprocess.run(
            argv,
            **stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except FileNotFoundError:
        return Result(127, "", f"{argv[0]}: not found")
    except subprocess.TimeoutExpired:
        return Result(124, "", f"{argv[0]}: timeout")
    return Result(proc.returncode, proc.stdout, proc.stderr)


class System:
    """File system root, command runner and environment of one agent call."""

    def __init__(
        self,
        root: str = "/",
        run: Callable[..., Result] = run_command,
        environ: Optional[dict] = None,
        fetch: Optional[Callable[..., tuple]] = None,
        now: Optional[Callable[[], float]] = None,
        http: Optional[Callable[[str, str, str], tuple]] = None,
    ) -> None:
        self.root = root
        self._run = run
        self.environ = dict(os.environ if environ is None else environ)
        self.fetch = fetch or https_get
        self.now = now or time.time
        self.http = http or http_local

    def path(self, path: str) -> str:
        return os.path.join(self.root, path.lstrip("/"))

    def exists(self, path: str) -> bool:
        return os.path.lexists(self.path(path))

    def read(self, path: str) -> Optional[str]:
        try:
            with open(self.path(path), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def read_bytes(self, path: str) -> Optional[bytes]:
        try:
            with open(self.path(path), "rb") as fh:
                return fh.read()
        except OSError:
            return None

    def write_bytes(self, path: str, data: bytes, mode: int) -> None:
        """Atomic write: a temporary file in the same directory, then rename."""
        full = self.path(path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        tmp = f"{full}.kerberos-tmp-{os.getpid()}"
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, full)

    def write(self, path: str, text: str, mode: int = 0o644) -> None:
        self.write_bytes(path, text.encode("utf-8"), mode)

    def run(self, argv: list[str], input: Optional[str] = None, timeout: float = 120) -> Result:
        return self._run(argv, input=input, timeout=timeout)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def own_source(system: System) -> bytes:
    data = system.read_bytes(AGENT_PATH)
    if data is None:
        with open(os.path.abspath(__file__), "rb") as fh:
            data = fh.read()
    return data


# -- reading the node (tech.md §9.2): pure parsers ---------------------------
PRIVATE_V4 = tuple(
    ipaddress.ip_network(n)
    for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
              "127.0.0.0/8")
)  # fmt: skip
PRIVATE_V6 = tuple(ipaddress.ip_network(n) for n in ("fc00::/7", "fe80::/10", "::1/128"))
KEY_TYPE_NAMES = {
    "ssh-ed25519": "ED25519",
    "ssh-rsa": "RSA",
    "ecdsa-sha2-nistp256": "ECDSA",
    "ecdsa-sha2-nistp384": "ECDSA",
    "ecdsa-sha2-nistp521": "ECDSA",
}
UFW_APPS = {"openssh": [(22, "tcp")], "nginx full": [(80, "tcp"), (443, "tcp")],
            "nginx http": [(80, "tcp")], "nginx https": [(443, "tcp")]}  # fmt: skip
XRAY_LOGS = ("/var/log/remnanode/access.log", "/var/log/xray/access.log")
RU_TLDS = (".ru", ".su", ".xn--p1ai", ".xn--p1acf", ".xn--p1ag")


def parse_os_release(text: str) -> dict:
    values = {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip().strip('"')
    return {"id": values.get("ID", ""), "version": values.get("VERSION_ID", "")}


def is_public(address: str) -> bool:
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return False
    nets = PRIVATE_V4 if addr.version == 4 else PRIVATE_V6
    return not any(addr in net for net in nets) and not addr.is_multicast


def parse_ip_addr(text: str) -> tuple[list, list]:
    """Global addresses from `ip -j addr show`, private ranges left out."""
    v4: list = []
    v6: list = []
    try:
        links = json.loads(text or "[]")
    except ValueError:
        return v4, v6
    for link in links if isinstance(links, list) else []:
        for info in link.get("addr_info") or []:
            if info.get("scope") != "global" or not is_public(str(info.get("local", ""))):
                continue
            target = v4 if info.get("family") == "inet" else v6
            if info["local"] not in target:
                target.append(info["local"])
    return v4, v6


def split_host_port(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    # «[::1]%lo:62789», «127.0.0.53%lo:53»: the interface goes first, then the brackets
    host = host.split("%", 1)[0].strip("[]")
    try:
        return host, int(port)
    except ValueError:
        return host, 0


def parse_ss_listen(text: str) -> list:
    """`ss -Hlntup`: proto, local address and port, process."""
    sockets = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] not in ("tcp", "udp"):
            continue
        address, port = split_host_port(parts[4])
        match = re.search(r'users:\(\("([^"]+)"', line)
        sockets.append(
            {
                "proto": parts[0],
                "address": "0.0.0.0" if address == "*" else address,
                "port": port,
                "process": match.group(1) if match else "",
            }
        )
    return sockets


def ss_number(line: str, name: str) -> int:
    match = re.search(rf"\b{name}:(\d+)", line)
    return int(match.group(1)) if match else 0


def parse_ss_connections(text: str) -> list:
    """`ss -Htin state established`: peer, bytes received, ms since the last receive; and
    for the sign of K27 bytes the client acknowledged, segments still in flight and ms
    since its last ACK."""
    connections = []
    current: Optional[dict] = None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if line[0] in " \t":
            if current is not None:
                current["received"] = ss_number(line, "bytes_received")
                current["lastrcv"] = ss_number(line, "lastrcv")
                current["acked"] = ss_number(line, "bytes_acked")
                current["unacked"] = ss_number(line, "unacked")
                current["lastack"] = ss_number(line, "lastack")
            continue
        parts = line.split()
        if len(parts) >= 4:
            peer, _ = split_host_port(parts[3])
            local, port = split_host_port(parts[2])
            # A dual-stack socket (Xray's «*:443») shows IPv4 clients as ::ffff:198.51.100.7.
            peer, local = plain_ip(peer), plain_ip(local)
            current = {
                "peer": peer,
                "local": local,
                "port": port,
                "received": 0,
                "lastrcv": 0,
                "acked": 0,
                "unacked": 0,
                "lastack": 0,
            }
            connections.append(current)
    return connections


def parse_sshd_t(text: str) -> dict:
    """`sshd -T`: the first value of every key, and every port and host key.

    `port` holds the ports of the `listenaddress` lines when there are any: those are
    what sshd binds, and `ListenAddress 0.0.0.0:2222` puts 2222 only there."""
    values: dict = {"port": [], "hostkey": []}
    ports: list = []
    listen: list = []
    for line in (text or "").splitlines():
        key, _, value = line.strip().partition(" ")
        key, value = key.lower(), value.strip()
        if key == "port":
            if value.isdigit() and int(value) not in ports:
                ports.append(int(value))
        elif key == "listenaddress":
            _host, port = split_host_port(value.split()[0] if value else "")
            if port and port not in listen:
                listen.append(port)
        elif key == "hostkey":
            if value and value not in values["hostkey"]:
                values["hostkey"].append(value)
        elif key:
            values.setdefault(key, value)
    values["port"] = listen or ports
    return values


def sshd_listen_ports(text: str) -> list:
    """TCP ports that sshd itself holds in `ss -Hlntup` (any owner of the socket)."""
    ports: list = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "tcp":
            continue
        if any(name.startswith("sshd") for name in re.findall(r'\("([^"]+)",pid=', line)):
            _host, port = split_host_port(parts[4])
            if port and port not in ports:
                ports.append(port)
    return ports


def ssh_ports(sshd_ports: list, by_socket: bool, socket_listen: str, ss_text: str) -> tuple:
    """Ports SSH listens on: ssh.socket's when it is active and has any, else sshd's own
    (from `sshd -T`, else the listeners of sshd in `ss`). Second value: by the socket."""
    if by_socket:
        listen = parse_socket_ports(socket_listen)
        if listen:
            return listen, True
    if sshd_ports:
        return list(sshd_ports), False
    return sshd_listen_ports(ss_text) or [22], False


def parse_socket_ports(text: str) -> list:
    """`systemctl show ssh.socket -p Listen`: Listen=[::]:22 (Stream) ..."""
    ports = []
    for match in re.finditer(r":(\d+) \(Stream\)", text or ""):
        port = int(match.group(1))
        if port not in ports:
            ports.append(port)
    return ports


def key_options(text: str) -> list:
    """Names of the options before the key type, commas inside quotes kept together."""
    names, current, quoted = [], "", False
    for char in text:
        if char == '"':
            quoted = not quoted
        if char == "," and not quoted:
            names.append(current)
            current = ""
        else:
            current += char
    names.append(current)
    return [name.split("=", 1)[0].strip().lower() for name in names if name.strip()]


def count_admin_keys(text: str) -> int:
    """Keys that let a person log in: not KERBEROS's own, and none with `command=` or
    `restrict` (cloud-init's "Please login as ubuntu", backup keys): `from=` still counts."""
    count = 0
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key = re.search(r"(^|\s)(ssh-|ecdsa-|sk-)\S+\s+\S+", line)
        if not key or AGENT_PATH in line:
            continue
        if not {"command", "restrict"} & set(key_options(line[: key.start()])):
            count += 1
    return count


def host_key_facts(files: dict) -> list:
    keys = []
    for name in sorted(files):
        parts = (files[name] or "").split()
        if len(parts) < 2:
            continue
        try:
            raw = base64.b64decode(parts[1])
        except (ValueError, TypeError):
            continue
        digest = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        keys.append(
            {"type": KEY_TYPE_NAMES.get(parts[0], parts[0]), "fingerprint": f"SHA256:{digest}"}
        )
    return keys


def _port_values(right: Any) -> list:
    """Ports in the right side of an nft match: a number, a set or a range."""
    if isinstance(right, int):
        return [right]
    if isinstance(right, dict):
        if "set" in right:
            values = []
            for item in right["set"]:
                values += _port_values(item)
            return values
        if "range" in right and len(right["range"]) == 2:
            low, high = right["range"]
            if isinstance(low, int) and isinstance(high, int) and high - low < 70000:
                return list(range(low, high + 1))
    return []


class Ruleset:
    """The effective nft rules that matter here (from `nft -j list ruleset`)."""

    def __init__(self, text: str) -> None:
        try:
            items = json.loads(text or "{}").get("nftables", [])
        except (ValueError, AttributeError):
            items = []
        self.tables: list = []
        self.input_chains: set = set()
        self.rules: list = []
        for item in items:
            if "table" in item:
                table = item["table"]
                self.tables.append(f"{table.get('family')} {table.get('name')}")
            elif "chain" in item and item["chain"].get("hook") == "input":
                chain = item["chain"]
                self.input_chains.add((chain.get("family"), chain.get("table"), chain.get("name")))
            elif "rule" in item:
                self.rules.append(item["rule"])

    def _input_rules(self):
        for rule in self.rules:
            if (rule.get("family"), rule.get("table"), rule.get("chain")) in self.input_chains:
                yield rule

    @staticmethod
    def _parse(rule: dict) -> dict:
        info: dict = {"ports": [], "proto": None, "saddr": None, "verdict": None, "hdrlen": False}
        for expr in rule.get("expr") or []:
            match = expr.get("match")
            if match:
                left = match.get("left") or {}
                payload = left.get("payload") if isinstance(left, dict) else None
                if payload and payload.get("field") == "dport":
                    info["proto"] = payload.get("protocol")
                    info["ports"] += _port_values(match.get("right"))
                elif payload and payload.get("field") == "saddr":
                    info["saddr"] = match.get("right")
                elif (
                    payload
                    and payload.get("field") == "hdrlength"
                    and match.get("op") in (">", "!=")
                ):
                    info["hdrlen"] = True
            for verdict in ("accept", "drop", "reject"):
                if verdict in expr:
                    info["verdict"] = verdict
        return info

    def dropped(self, proto: str) -> set:
        """Ports dropped for every source on input."""
        ports: set = set()
        for rule in self._input_rules():
            info = self._parse(rule)
            if info["verdict"] in ("drop", "reject") and info["saddr"] is None:
                if info["proto"] in (proto, "th", None) and info["ports"]:
                    ports.update(info["ports"])
        return ports

    def accepted_from(self, port: int) -> list:
        sources = []
        for rule in self._input_rules():
            info = self._parse(rule)
            if info["verdict"] == "accept" and port in info["ports"] and info["saddr"]:
                sources.append(str(info["saddr"]))
        return sources

    def drops_ip_options(self) -> bool:
        return any(
            self._parse(rule)["hdrlen"] and self._parse(rule)["verdict"] == "drop"
            for rule in self._input_rules()
        )


def parse_ufw(text: str) -> dict:
    """`ufw status verbose`: state, default policy and allowed ports from anywhere."""
    if not text:
        return {"state": "absent", "deny": False, "allowed": set()}
    state = "active" if re.search(r"^Status: active", text, re.M) else "inactive"
    deny = bool(re.search(r"^Default: (deny|reject) \(incoming\)", text, re.M))
    allowed: set = set()
    rules = False
    for line in text.splitlines():
        if line.startswith("--"):
            rules = True
            continue
        if not rules or not line.strip():
            continue
        cols = re.split(r"\s{2,}", line.strip())
        if len(cols) < 3 or not cols[1].startswith(("ALLOW", "LIMIT")):
            continue
        if not cols[2].startswith("Anywhere"):
            continue
        target = cols[0].replace(" (v6)", "").strip()
        for port, proto in _ufw_target(target):
            allowed.add((port, proto))
    return {"state": state, "deny": deny, "allowed": allowed}


def _ufw_target(target: str) -> list:
    if target.lower() in UFW_APPS:
        return UFW_APPS[target.lower()]
    port, _, proto = target.partition("/")
    result = []
    for part in port.split(","):
        low, _, high = part.partition(":")
        if low.isdigit():
            for value in range(int(low), int(high or low) + 1):
                for kind in [proto] if proto else ["tcp", "udp"]:
                    result.append((value, kind))
    return result


def parse_fail2ban(configs: list, ssh_ports: list) -> dict:
    """The sshd jail from fail2ban's files in their own order of precedence."""
    if not configs:
        return {"enabled": False, "jailPorts": []}
    enabled = False
    port_value = "ssh"
    defaults_enabled = False
    for _name, text in configs:
        section = None
        for raw in (text or "").splitlines():
            line = raw.split("#", 1)[0].split(";", 1)[0].strip()
            if not line:
                continue
            header = re.match(r"^\[(.+)\]$", line)
            if header:
                section = header.group(1).strip()
                continue
            key, sep, value = line.partition("=")
            if not sep:
                continue
            key, value = key.strip().lower(), value.strip()
            if section == "DEFAULT" and key == "enabled":
                defaults_enabled = value.lower() in ("true", "yes", "1")
            if section == "sshd":
                if key == "enabled":
                    enabled = value.lower() in ("true", "yes", "1")
                elif key == "port":
                    port_value = value
    jail_ports: list = []
    for part in re.split(r"[,\s]+", port_value):
        part = part.strip()
        if part in ("ssh", "%(ssh_port)s"):
            part = "22"
        low, _, high = part.partition(":")
        if low.isdigit() and high.isdigit():
            jail_ports += [p for p in ssh_ports if int(low) <= p <= int(high)]
        elif low.isdigit():
            jail_ports.append(int(low))
    return {"enabled": enabled or defaults_enabled, "jailPorts": sorted(set(jail_ports))}


def docker_published(text: str) -> set:
    ports: set = set()
    for line in (text or "").splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        for match in re.finditer(r":(\d+)->\d+/(tcp|udp)", str(item.get("Ports", ""))):
            ports.add((int(match.group(1)), match.group(2)))
    return ports


def parse_remnanode(text: str) -> dict:
    """`docker inspect remnanode`: only network, node port and mounts. The
    environment holds SECRET_KEY: only NODE_PORT or APP_PORT is taken from it."""
    try:
        data = json.loads(text or "[]")[0]
    except (ValueError, IndexError, KeyError, TypeError):
        return {"present": False, "network": None, "nodePort": None, "letsencryptMounted": False}
    port = None
    for item in (data.get("Config") or {}).get("Env") or []:
        name, _, value = str(item).partition("=")
        if name in ("NODE_PORT", "APP_PORT") and value.isdigit():
            port = int(value)
    mode = (data.get("HostConfig") or {}).get("NetworkMode") or ""
    mounts = [m.get("Destination") for m in data.get("Mounts") or []]
    return {
        "present": True,
        "network": "host" if mode == "host" else "bridge",
        "nodePort": port,
        "letsencryptMounted": any(str(d).rstrip("/") == "/etc/letsencrypt" for d in mounts),
    }


def parse_nginx(files: dict) -> dict:
    realip = False
    sites = []
    for name in sorted(files):
        text = re.sub(r"#[^\n]*", "", files[name] or "")
        if re.search(r"\b(real_ip_header|set_real_ip_from)\b", text):
            realip = True
        for block in _server_blocks(text):
            names = []
            for match in re.finditer(r"\bserver_name\s+([^;]+);", block):
                names += [n for n in match.group(1).split() if n != "_"]
            listen = []
            for match in re.finditer(r"\blisten\s+([^;]+);", block):
                listen.append(" ".join(match.group(1).split()))
            sites.append({"file": name, "serverNames": names, "listen": listen})
    return {"realip": realip, "sites": sites}


def _server_blocks(text: str) -> list:
    blocks = []
    for match in re.finditer(r"\bserver\s*\{", text):
        depth, i = 1, match.end()
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        blocks.append(text[match.end() : i - 1])
    return blocks


def cert_not_after(path: str) -> Optional[str]:
    try:
        import _ssl

        decoded = _ssl._test_decode_cert(path)  # noqa: SLF001 - stdlib has no public decoder
    except Exception:  # noqa: BLE001 - any failure means "unknown"
        return None
    value = decoded.get("notAfter")
    if not value:
        return None
    try:
        stamp = ssl.cert_time_to_seconds(value)
    except ValueError:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp))


def parse_xray_log(text: str, now: float) -> dict:
    """Counts of the last five minutes of the Xray access log; never addresses."""
    accepted = 0
    users: set = set()
    russian = 0
    since = now - 300
    for line in (text or "").splitlines():
        match = re.match(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
        if not match or " accepted " not in line:
            continue
        try:
            stamp = time.mktime(time.strptime(match.group(1), "%Y/%m/%d %H:%M:%S"))
        except ValueError:
            continue
        if stamp < since:
            continue
        accepted += 1
        dest = re.search(r" accepted (?:tcp|udp):([^:\s]+):\d+", line)
        if dest and dest.group(1).lower().endswith(RU_TLDS):
            russian += 1
        email = re.search(r"email: (\S+)", line)
        if email:
            users.add(email.group(1))
    share = round(russian / accepted, 4) if accepted else 0.0
    return {"accepted5m": accepted, "users5m": len(users), "ruShare": share}


def net_of(address: str, v4_prefix: int, v6_prefix: int) -> str:
    addr = ipaddress.ip_address(address)
    prefix = v4_prefix if addr.version == 4 else v6_prefix
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


# K27: TSPU lets a connection through for its first ~16 KB and then drops what the server
# sends: the client acknowledged about that much and nothing since, while data is still in
# flight. An idle connection has nothing unacknowledged; a client that went away mid-download
# usually got far more than this.
STALL_ACKED = (10_240, 24_576)
STALL_MS = 3000


def stalled(item: dict) -> bool:
    low, high = STALL_ACKED
    acked = item.get("acked", 0)
    return low <= acked <= high and item.get("unacked", 0) > 0 and item.get("lastack", 0) > STALL_MS


def nets_of(connections: list) -> list:
    nets: dict = {}
    for item in connections:
        net = net_of(item["peer"], 16, 32)
        nets[net] = nets.get(net, 0) + 1
    return [{"net": n, "count": c} for n, c in sorted(nets.items(), key=lambda x: -x[1])]


def watch_family(connections: list) -> dict:
    cut = [c for c in connections if c["received"] <= 1500 and c["lastrcv"] > 3000]
    stuck = [c for c in connections if stalled(c)]
    return {
        "connections": len(connections),
        "clientIps": len({c["peer"] for c in connections}),
        "cut": len(cut),
        "cutNets": nets_of(cut),
        "stalled": len(stuck),
        "stalledNets": nets_of(stuck),
    }


def template_hash(html: str) -> str:
    """Structure of a page: the sequence of its tags, not the text."""
    tags = re.findall(r"<\s*([a-zA-Z][a-zA-Z0-9-]*)", html or "")
    return hashlib.sha256(" ".join(t.lower() for t in tags).encode()).hexdigest()[:16]


def parse_access_log(text: str, path: str) -> dict:
    nets: dict = {}
    for line in (text or "").splitlines():
        match = re.match(r'^(\S+) \S+ \S+ \[[^\]]*\] "(?:GET|POST|PUT|HEAD|OPTIONS) (\S+)', line)
        if not match or not match.group(2).startswith(path):
            continue
        try:
            net = net_of(match.group(1), 24, 48)
        except ValueError:
            continue
        nets[net] = nets.get(net, 0) + 1
    return nets


# -- reading the node: collectors ------------------------------------------
def panel_address(system: System) -> str:
    parts = system.environ.get("SSH_CONNECTION", "").split()
    return parts[0] if parts else ""


def plain_ip(value: str) -> str:
    """An IPv4 address mapped into IPv6 (::ffff:198.51.100.5) as plain IPv4."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    mapped = getattr(address, "ipv4_mapped", None)
    return str(mapped or address)


def node_api_peers(system: System, port: int) -> set:
    """Addresses with an established connection to the node API right now."""
    out = system.run(["ss", "-Htn", "state", "established", f"( sport = :{port} )"])
    return {plain_ip(c["peer"]) for c in parse_ss_connections(out.stdout)}


PRIVSEP_DIR = "/run/sshd"


def ensure_privsep(system: System) -> None:
    """sshd -t and -T stop on a missing /run/sshd. With ssh.socket it exists only while
    ssh.service runs, so a test right after a socket restart fails without it."""
    os.makedirs(system.path(PRIVSEP_DIR), mode=0o755, exist_ok=True)


def sshd_values(system: System) -> dict:
    result = system.run(["sshd", "-T"])
    if not result.ok:
        ensure_privsep(system)
        result = system.run(["sshd", "-T"])
    return parse_sshd_t(result.stdout)


def socket_active(system: System) -> bool:
    return system.run(["systemctl", "is-active", "ssh.socket"]).stdout.strip() == "active"


def socket_listen_text(system: System) -> str:
    return system.run(["systemctl", "show", "ssh.socket", "-p", "Listen"]).stdout


def collect_ssh(system: System, values: Optional[dict] = None) -> dict:
    values = dict(sshd_values(system) if values is None else values)
    if "passwordauthentication" not in values:
        # No word from sshd: never report password login as off when it may be on.
        values.update(passwordauthentication="yes", kbdinteractiveauthentication="yes")
    active = socket_active(system)
    listen = socket_listen_text(system) if active else ""
    # sshd -T did not answer: the ports come from what sshd holds, not a guess of 22.
    sshd_ports = values.get("port") or []
    ss_text = "" if sshd_ports else system.run(["ss", "-Hlntup"]).stdout
    ports, active = ssh_ports(sshd_ports, active, listen, ss_text)
    admin = count_admin_keys(
        (system.read("/root/.ssh/authorized_keys") or "")
        + "\n"
        + (system.read("/root/.ssh/authorized_keys2") or "")
    )
    kbd = values.get("kbdinteractiveauthentication", values.get("challengeresponseauthentication"))
    return {
        "ports": ports,
        "socketActivated": active,
        "passwordAuthentication": values.get("passwordauthentication") == "yes",
        "kbdInteractive": kbd == "yes",
        "permitRootLogin": values.get("permitrootlogin", ""),
        "adminKeys": admin,
    }


def fail2ban_files(system: System) -> list:
    order = ["/etc/fail2ban/jail.conf"]
    jail_d = system.path("/etc/fail2ban/jail.d")
    names = sorted(os.listdir(jail_d)) if os.path.isdir(jail_d) else []
    order += [f"/etc/fail2ban/jail.d/{n}" for n in names if n.endswith(".conf")]
    order.append("/etc/fail2ban/jail.local")
    order += [f"/etc/fail2ban/jail.d/{n}" for n in names if n.endswith(".local")]
    return [(name, system.read(name)) for name in order if system.read(name) is not None]


def collect_files(system: System, directory: str, suffix: str = "") -> dict:
    full = system.path(directory)
    if not os.path.isdir(full):
        return {}
    files = {}
    for name in sorted(os.listdir(full)):
        if suffix and not name.endswith(suffix):
            continue
        path = f"{directory.rstrip('/')}/{name}"
        text = system.read(path)
        if text is not None:
            files[path] = text
    return files


DEFAULT_HOST_KEYS = tuple(f"/etc/ssh/ssh_host_{name}_key" for name in ("rsa", "ecdsa", "ed25519"))


def host_key_files(values: dict) -> list:
    """The HostKey files of `sshd -T`; the usual ones when sshd did not answer."""
    listed = [p for p in values.get("hostkey") or [] if p.startswith("/")]
    return listed or list(DEFAULT_HOST_KEYS)


def public_keys(system: System, paths: list) -> dict:
    """The .pub files of these host keys; with the usual paths, every ssh_host_*.pub."""
    if list(paths) == list(DEFAULT_HOST_KEYS):
        return {p: t for p, t in collect_files(system, "/etc/ssh", ".pub").items()
                if os.path.basename(p).startswith("ssh_host_")}  # fmt: skip
    found = {f"{p}.pub": system.read(f"{p}.pub") for p in sorted(set(paths))}
    return {p: t for p, t in found.items() if t is not None}


def collect_facts(system: System) -> dict:
    os_release = parse_os_release(system.read("/etc/os-release") or "")
    kernel = (system.read("/proc/sys/kernel/osrelease") or "").strip()
    v4, v6 = parse_ip_addr(system.run(["ip", "-j", "addr", "show"]).stdout)
    values = sshd_values(system)
    ssh = collect_ssh(system, values)
    ruleset = Ruleset(system.run(["nft", "-j", "list", "ruleset"]).stdout)
    # K28: ports of SSH dropped for everybody but a few (ssh.panel_only or a rule of the
    # person's own): there SSH is not open to the whole internet.
    ssh["guarded"] = sorted(p for p in ssh["ports"] if p in ruleset.dropped("tcp"))
    ufw_out = system.run(["ufw", "status", "verbose"])
    ufw = parse_ufw(ufw_out.stdout if ufw_out.code != 127 else "")
    published = docker_published(system.run(["docker", "ps", "--format", "{{json .}}"]).stdout)
    remnanode = parse_remnanode(system.run(["docker", "inspect", "remnanode"]).stdout)
    if remnanode["present"]:
        version = system.run(["docker", "exec", "remnanode", "xray", "version"]).stdout
        match = re.search(r"Xray (\d+\.\d+\.\d+)", version)
        remnanode["xrayVersion"] = match.group(1) if match else None
    else:
        remnanode["xrayVersion"] = None
    listening = []
    for item in parse_ss_listen(system.run(["ss", "-Hlntup"]).stdout):
        key = (item["port"], item["proto"])
        firewalled = item["port"] in ruleset.dropped(item["proto"]) or (
            ufw["state"] == "active" and ufw["deny"] and key not in ufw["allowed"]
        )
        item["docker"] = item["process"] == "docker-proxy" or key in published
        item["firewalled"] = firewalled
        listening.append(item)
    node_port = remnanode.get("nodePort")
    panel_ip = plain_ip(panel_address(system))
    peers = node_api_peers(system, node_port) if node_port else set()
    other_peers = len([p for p in peers if p != panel_ip])
    jail = parse_fail2ban(fail2ban_files(system), ssh["ports"])
    f2b_installed = system.exists("/usr/bin/fail2ban-client")
    f2b_active = system.run(["systemctl", "is-active", "fail2ban"]).stdout.strip() == "active"
    mptcp_sockets = 0
    for line in (system.read("/proc/net/protocols") or "").splitlines():
        parts = line.split()
        if parts and parts[0] in ("MPTCP", "MPTCPv6") and len(parts) > 2 and parts[2].isdigit():
            mptcp_sockets += int(parts[2])
    host_keys = host_key_facts(public_keys(system, host_key_files(values)))
    nginx_files = collect_files(system, "/etc/nginx/sites-enabled")
    nginx_files.update(collect_files(system, "/etc/nginx/conf.d", ".conf"))
    nginx = parse_nginx(nginx_files)
    certs = []
    live = system.path("/etc/letsencrypt/live")
    if os.path.isdir(live):
        for name in sorted(os.listdir(live)):
            cert = os.path.join(live, name, "cert.pem")
            if os.path.exists(cert):
                certs.append({"domain": name, "notAfter": cert_not_after(cert)})
    return {
        "protocol": PROTOCOL,
        "agent": AGENT_VERSION,
        "os": {**os_release, "kernel": kernel},
        "ipv4": v4,
        "ipv6": v6,
        "python": platform.python_version(),
        "listening": listening,
        "ssh": ssh,
        "fail2ban": {
            "installed": f2b_installed,
            "sshdJail": f2b_installed and f2b_active and jail["enabled"],
            "jailPorts": jail["jailPorts"],
        },
        "mptcp": {
            "enabled": (system.read("/proc/sys/net/mptcp/enabled") or "0").strip() == "1",
            "ipOptionsDrop": ruleset.drops_ip_options(),
            "sockets": mptcp_sockets,
        },
        "nodeApi": {
            "port": node_port,
            "panelOnly": bool(node_port) and node_port in ruleset.dropped("tcp"),
            "otherPeers": other_peers,
            # The panel talks to the node API from the address KERBEROS comes from: the
            # rule of node_api.panel_only keeps it (§10.3).
            "panelPeer": bool(panel_ip) and panel_ip in peers,
        },
        "nftTables": ruleset.tables,
        "hostKeys": host_keys,
        "firewall": {"ufw": ufw["state"]},
        "remnanode": remnanode,
        "nginx": {
            "installed": system.exists("/usr/sbin/nginx"),
            "realip": nginx["realip"],
            "sites": nginx["sites"],
        },
        "certbot": {
            "installed": system.exists("/usr/bin/certbot"),
            "certs": certs,
            # A pre-hook of every renewal stops nginx: renewals through nginx fail (§10.4, K17).
            "stopsNginx": stops_nginx(certbot_global(system)[0]),
        },
        # Renewals that would stop working once nginx holds :80 (self_steal.site, §10.4).
        "acme": [
            {
                "tool": r["tool"],
                "name": r["name"],
                "names": r["names"],
                "notAfter": cert_not_after(system.path(r["cert"])),
                # A hook stops or kills something first: port 80 is looked after (K17).
                "freesPort": r.get("freesPort", False),
                **({"blocked": r["reason"]} if r["state"] == "blocked" else {}),
            }
            for r in renewals(system)
            if r["state"] != "moved"
        ],
        "watch": {
            "installed": system.exists("/usr/local/sbin/kerberos-watch")
            and system.exists("/etc/cron.d/kerberos-watch")
        },
    }


def vpn_ports(system: System) -> list:
    """TCP ports Xray answers on from outside, 443 first; empty when Xray listens only on
    loopback. The cut share means something for VPN connections only: on a panel server 443
    is a web server, on a CDN origin nginx holds it and Xray sits on loopback (K18, found on
    a live server). All of them together: one quiet inbound must not read as 1 cut of 1."""
    ports = set()
    for item in parse_ss_listen(system.run(["ss", "-Hlntup"]).stdout):
        name = str(item.get("process") or "")
        if item["proto"] != "tcp" or not (name == "rw-core" or name.startswith("xray")):
            continue
        try:
            if ipaddress.ip_address(plain_ip(str(item.get("address") or ""))).is_loopback:
                continue
        except ValueError:
            continue  # an address the agent cannot read is not counted as public
        ports.add(item["port"])
    return sorted(ports, key=lambda p: (p != 443, p))


def collect_watch(system: System, port: Optional[int] = None) -> dict:
    ports = vpn_ports(system) if port is None else [port]
    connections = []
    if ports:
        expr = " or ".join(f"sport = :{p}" for p in ports)
        out = system.run(["ss", "-Htin", "state", "established", f"( {expr} )"])
        connections = parse_ss_connections(out.stdout)
    v4 = [c for c in connections if ":" not in c["peer"]]
    v6 = [c for c in connections if ":" in c["peer"]]
    log = ""
    for path in XRAY_LOGS:
        data = system.read_bytes(path)
        if data is not None:
            log = data[-2_000_000:].decode("utf-8", "replace")
            break
    xray = parse_xray_log(log, system.now()) if log else {
        "accepted5m": None, "users5m": None, "ruShare": None,
    }  # fmt: skip
    return {
        "protocol": PROTOCOL,
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(system.now())),
        "port": ports[0] if ports else None,
        "ports": ports,
        "v4": watch_family(v4),
        "v6": watch_family(v6),
        "xray": xray,
    }


def https_get(host: str, port: int, sni: str, path: str, timeout: float = 10.0) -> tuple:
    """GET over TLS with a chosen SNI; the certificate is not checked (local stub)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: Mozilla/5.0\r\n"
        "Accept: text/html\r\nConnection: close\r\n\r\n"
    )
    data = b""
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=sni) as tls:
            tls.sendall(request.encode())
            while len(data) < 1_000_000:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = _unchunk(body)
    return status, headers, body


def http_local(address: str, host: str, path: str, timeout: float = 10.0) -> tuple:
    """(status, body) of a GET to nginx on this server, port 80 of `address`, with the
    Host a certificate authority would send for `host` (§10.4, K16)."""
    name = f"[{host}]" if ":" in host else host
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {name}\r\nUser-Agent: kerberos-agent\r\n"
        "Connection: close\r\n\r\n"
    )
    data = b""
    with socket.create_connection((address, 80), timeout=timeout) as conn:
        conn.sendall(request.encode())
        while len(data) < 65536:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    try:
        status = int(head.split(b" ", 2)[1])
    except (IndexError, ValueError):
        status = 0
    return status, body.decode("utf-8", "replace")


def _unchunk(body: bytes) -> bytes:
    out = b""
    while body:
        size_line, _, rest = body.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        body = rest[size + 2 :]
    return out


DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
URL_PATH = re.compile(r"^/[A-Za-z0-9._~/-]{0,200}$")


def cmd_facts(system: System, args: list, data: Any) -> dict:
    return collect_facts(system)


def cmd_watch(system: System, args: list, data: Any) -> dict:
    return collect_watch(system)


def cmd_site_check(system: System, args: list, data: dict) -> dict:
    domain = str(data.get("domain", "")).lower()
    if not DOMAIN.match(domain):
        raise AgentError("bad_params", "domain")
    try:
        status, headers, body = system.fetch("127.0.0.1", 8445, domain, "/")
    except (OSError, ValueError, IndexError):
        return {"template": None, "altSvc": None, "status": None}
    return {
        "template": template_hash(body.decode("utf-8", "replace")),
        "altSvc": headers.get("alt-svc"),
        "status": status,
    }


def cmd_edge_sources(system: System, args: list, data: dict) -> dict:
    path = str(data.get("path", ""))
    if not URL_PATH.match(path):
        raise AgentError("bad_params", "path")
    nets: dict = {}
    for name in ("/var/log/nginx/access.log.1", "/var/log/nginx/access.log"):
        for net, count in parse_access_log(system.read(name) or "", path).items():
            nets[net] = nets.get(net, 0) + count
    ordered = sorted(nets.items(), key=lambda item: (-item[1], item[0]))
    return {"nets": [{"net": n, "count": c} for n, c in ordered]}


# -- changes (tech.md §9.3) ---------------------------------------------------
CHANGES_DIR = STATE_DIR + "/changes"
PENDING_FILE = STATE_DIR + "/pending"
UNDO_DELAY = 180
APT_TIMEOUT = 600
SSHD_CONF = "/etc/ssh/sshd_config.d/10-kerberos.conf"
AUTHORIZED_KEYS = "/root/.ssh/authorized_keys"
HOST_KEY_NAMES = ("rsa", "ecdsa", "ed25519")


class Plan:
    """What one fix changes: files, packages, commands, how to undo."""

    def __init__(self, fix_id: str) -> None:
        self.fix_id = fix_id
        self.files: dict = {}  # path -> (text or None to delete, mode)
        self.created: list = []  # paths commands create; absent before
        self.packages: list = []
        self.commands: list = []  # (argv, error code), after the files
        self.undo_before: list = []  # argv, before files are restored
        self.undo_after: list = []  # argv, after files are restored
        self.access = False  # timer and confirmation by a new connection
        self.details: dict = {}
        self.after: Optional[Callable[[System], dict]] = None
        self.keep: list = []  # backed up now, changed only by `confirm`
        self.confirm_files: dict = {}  # path -> (text, mode), written by `confirm`
        self.confirm_commands: list = []  # (argv, error code), run by `confirm`
        self.steps: list = []  # ordered writes and runs after files and commands
        self.stage = False  # a confirmed change goes back through the first phase
        self.private: set = set()  # files whose text `plan` does not show
        # Renewals that move to KERBEROS's webroot after the steps (self_steal.site, §10.4):
        # only their method is kept for the undo, other tools rewrite these files.
        self.moves: list = []

    def write(self, path: str, text: Optional[str], mode: int = 0o644,
              private: bool = False) -> None:  # fmt: skip
        """`private`: the text comes from a file of the person (docker-compose.yml with
        SECRET_KEY, nginx sites, sshd configs): `plan` does not show it (§9.4)."""
        self.files[path] = (text, mode)
        if private:
            self.private.add(path)

    def run(self, argv: list, code: str = "command_failed") -> None:
        self.commands.append((argv, code))

    def on_confirm(self, path: Optional[str] = None, text: Optional[str] = None,
                   argv: Optional[list] = None, code: str = "command_failed") -> None:  # fmt: skip
        """Second phase (§10.3, ssh.port): after the new connection has worked."""
        if path is not None:
            self.confirm_files[path] = (text, 0o644)
            if path not in self.files and path not in self.keep:
                self.keep.append(path)
        if argv is not None:
            self.confirm_commands.append((argv, code))

    def step_write(self, path: str, text: str, mode: int = 0o644) -> None:
        """An ordered step: for fixes that must interleave files and commands."""
        self.steps.append(("write", path, text, mode))
        if path not in self.keep and path not in self.files:
            self.keep.append(path)

    def step_run(self, argv: list, code: str = "command_failed", timeout: float = 120) -> None:
        self.steps.append(("run", argv, code, timeout))


FIXES: dict = {}


def fix(name: str):
    def register(builder):
        FIXES[name] = builder
        return builder

    return register


def change_dir(change_id: str) -> str:
    return f"{CHANGES_DIR}/{change_id}"


def load_record(system: System, change_id: str) -> Optional[dict]:
    text = system.read(f"{change_dir(change_id)}/rollback.json")
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError as exc:
        raise AgentError("backup_damaged", "rollback.json is not JSON") from exc


def save_record(system: System, record: dict) -> None:
    system.write(f"{change_dir(record['changeId'])}/rollback.json",
                 json.dumps(record, indent=2, sort_keys=True), 0o600)  # fmt: skip


def answer_of(record: dict, state: Optional[str] = None) -> dict:
    return {
        "protocol": PROTOCOL,
        "changeId": record["changeId"],
        "fixId": record["fixId"],
        "state": state or record["state"],
        "files": [item["path"] for item in record["files"]],
        "details": record.get("details", {}),
    }


def file_sha(system: System, path: str) -> Optional[str]:
    data = system.read_bytes(path)
    return None if data is None else sha256_bytes(data)


def mode_of(system: System, path: str) -> Optional[int]:
    try:
        return os.stat(system.path(path)).st_mode & 0o7777
    except OSError:
        return None


def save_files(system: System, change_id: str, paths: list, folder: str) -> list:
    """Copies of `paths` as they are now, in the change's folder: how to put them back."""
    entries = []
    for index, path in enumerate(paths):
        data = system.read_bytes(path)
        entry = {"path": path, "existed": data is not None, "mode": mode_of(system, path),
                 "backup": None, "sha256": None}  # fmt: skip
        if data is not None:
            name = f"{folder}/{index}"
            system.write_bytes(f"{change_dir(change_id)}/{name}", data, 0o600)
            entry["backup"] = name
            entry["sha256"] = sha256_bytes(data)
        entries.append(entry)
    return entries


def put_back(system: System, change_id: str, entries: list) -> None:
    for entry in entries:
        path = entry["path"]
        if entry["existed"]:
            data = system.read_bytes(f"{change_dir(change_id)}/{entry['backup']}")
            if data is None or sha256_bytes(data) != entry["sha256"]:
                raise AgentError("backup_damaged", path)
            system.write_bytes(path, data, entry["mode"] if entry["mode"] is not None else 0o644)
        elif system.exists(path):
            os.remove(system.path(path))


def write_files(system: System, files: dict) -> None:
    for path, (text, mode) in files.items():
        if text is None:
            if system.exists(path):
                os.remove(system.path(path))
        else:
            system.write(path, text, mode)


def run_step(system: System, argv: list) -> Result:
    return system.run(argv, timeout=APT_TIMEOUT if argv[:1] == ["apt-get"] else 120)


def backup(system: System, change_id: str, plan: Plan) -> dict:
    """Copy every file the change touches before anything happens (§9.3)."""
    paths = list(plan.files) + [p for p in plan.created + plan.keep if p not in plan.files]
    record = {
        "changeId": change_id,
        "fixId": plan.fix_id,
        "state": "applying",
        "files": save_files(system, change_id, list(dict.fromkeys(paths)), "files"),
        "undoBefore": plan.undo_before,
        "undoAfter": plan.undo_after,
        "access": plan.access,
        "details": dict(plan.details),
        "confirm": {
            "files": {p: [text, mode] for p, (text, mode) in plan.confirm_files.items()},
            "commands": [[argv, code] for argv, code in plan.confirm_commands],
        },
        "written": {},
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(system.now())),
        # Which change came later: `at` has one-second steps, changes of a run share them.
        "order": system.now(),
    }
    if plan.stage:
        # The layout of the first phase: a confirmed change goes back through it.
        record["stage"] = {
            "files": {p: [text, mode] for p, (text, mode) in plan.files.items()},
            "commands": [[argv, code] for argv, code in plan.commands],
        }
    return record


def restore(system: System, record: dict) -> list:
    """Files back to their bytes and modes; undo commands around it. Returns the undo
    commands that failed: the files are back then, but a service may not be."""
    problems = []
    for argv in record.get("undoBefore", []):
        if not run_step(system, argv).ok:
            problems.append(" ".join(argv))
    put_back(system, record["changeId"], record["files"])
    revert_renewals(system, record)
    for argv in record.get("undoAfter", []):
        if not run_step(system, argv).ok:
            problems.append(" ".join(argv))
    return problems


def undo_error(error: AgentError, problems: list) -> AgentError:
    """The change did not happen and its undo left a command failed: the node needs a look."""
    if not problems:
        return error
    return AgentError("command_failed", f"{error.code}; undo failed: {'; '.join(problems)}")


DPKG_STATUS = "/var/lib/dpkg/status"
DPKG_UPDATES = "/var/lib/dpkg/updates"
# dpkg asks what to do with a config file the person already has (certbot's
# /etc/letsencrypt/cli.ini, nginx.conf): DEBIAN_FRONTEND does not cover that prompt, it
# reads EOF and fails the install. Default answer, else keep the person's file.
DPKG_KEEP_CONFIG = ["--force-confdef", "--force-confold"]
APT_KEEP_CONFIG = ["-o", "Dpkg::Options::=--force-confdef",
                   "-o", "Dpkg::Options::=--force-confold"]  # fmt: skip
# Unpacked, not configured: `dpkg -l` iU, iF, iW, iT.
UNFINISHED = ("unpacked", "half-configured", "triggers-awaited", "triggers-pending")


def unfinished_packages(status: str) -> list:
    """Packages of /var/lib/dpkg/status that dpkg unpacked but did not configure."""
    names = []
    for stanza in re.split(r"\n\s*\n", status):
        fields = dict(re.findall(r"^([A-Za-z-]+):[ \t]*(.*)$", stanza, re.M))
        words = fields.get("Status", "").split()
        if fields.get("Package") and len(words) == 3 and words[2] in UNFINISHED:
            names.append(fields["Package"])
    return names


def needs_package(system: System, package: str, binary: str) -> bool:
    """Not there, or left half-configured (an install that failed earlier)."""
    return not system.exists(binary) or package in unfinished_packages(
        system.read(DPKG_STATUS) or ""
    )


def dpkg_unfinished(system: System) -> bool:
    """Something to configure first: a killed dpkg leaves its journal in updates/, and
    apt-get then refuses to install anything until `dpkg --configure -a`."""
    try:
        journal = os.listdir(system.path(DPKG_UPDATES))
    except OSError:
        journal = []
    return bool(journal) or bool(unfinished_packages(system.read(DPKG_STATUS) or ""))


def install_packages(system: System, packages: list) -> None:
    """At most APT_TIMEOUT for the whole install, so KERBEROS knows how long to wait.

    The person's config files stay as they are, and packages an earlier install left
    half-configured are configured first, with the same answer."""
    if not packages:
        return
    argv = ["apt-get", "install", "-y", "-q", *APT_KEEP_CONFIG, *packages]
    deadline = time.monotonic() + APT_TIMEOUT

    def left() -> float:
        return max(1.0, deadline - time.monotonic())

    if dpkg_unfinished(system):
        # Its own result does not matter: apt-get configures what is left and fails if not.
        system.run(["dpkg", *DPKG_KEEP_CONFIG, "--configure", "-a"], timeout=left())
    if system.run(argv, timeout=left()).ok:
        return
    system.run(["apt-get", "update", "-q"], timeout=left())
    if not system.run(argv, timeout=left()).ok:
        raise AgentError("apt_failed", " ".join(packages))


def pending_change(system: System) -> Optional[str]:
    value = (system.read(PENDING_FILE) or "").strip()
    return value or None


def clear_pending(system: System, change_id: str) -> None:
    if pending_change(system) == change_id:
        system.write(PENDING_FILE, "", 0o600)


def set_pending(system: System, record: dict, state: str) -> None:
    record["state"] = state
    record["pendingSince"] = system.now()
    system.write(PENDING_FILE, record["changeId"] + "\n", 0o600)


WAITING = ("pending_confirm", "rollback_pending")
UNDO_MARGIN = 60


def parse_at(value: Any) -> Optional[float]:
    try:
        return float(calendar.timegm(time.strptime(str(value), "%Y-%m-%dT%H:%M:%SZ")))
    except ValueError:
        return None


def timer_lost(system: System, record: dict) -> bool:
    """The change waits longer than its timer could: a reboot took the transient timer
    or its undo failed. Then nobody will ever settle it but the next apply."""
    since = record.get("pendingSince")
    since = parse_at(record.get("at")) if since is None else since
    if since is None or system.now() - since < UNDO_DELAY + UNDO_MARGIN:
        return False
    unit = f"kerberos-undo-{record['changeId']}.timer"
    state = system.run(["systemctl", "show", "-p", "SubState", "--value", unit]).stdout.strip()
    return state not in ("waiting", "running")


def start_timer(system: System, change_id: str, again: bool = False) -> bool:
    unit = f"kerberos-undo-{change_id}"
    if again:
        # The unit name of the apply: an undo that failed earlier leaves it loaded.
        system.run(["systemctl", "reset-failed", f"{unit}.timer", f"{unit}.service"])
    # `undo`, not `rollback`: a change confirmed meanwhile must stay.
    return system.run(["systemd-run", f"--on-active={UNDO_DELAY}", "--unit", unit,
                       AGENT_PATH, "undo", change_id]).ok  # fmt: skip


def cmd_apply(system: System, args: list, data: dict) -> dict:
    fix_id, change_id = args
    record = load_record(system, change_id)
    if record is not None:
        if record["fixId"] != fix_id:
            raise AgentError("change_conflict", "the changeId belongs to another fix")
        return answer_of(record, "noop")
    builder = FIXES.get(fix_id)
    if builder is None:
        raise AgentError("not_implemented", fix_id)
    waiting = pending_change(system)
    if waiting:
        other = load_record(system, waiting)
        if other is not None and other["state"] in WAITING:
            if not timer_lost(system, other):
                raise AgentError("change_conflict", f"change {waiting} waits for confirmation")
            cmd_undo(system, [waiting], None)  # what its timer would have done
    plan = builder(system, data)
    install_packages(system, plan.packages)
    record = backup(system, change_id, plan)
    save_record(system, record)
    try:
        write_files(system, plan.files)
        for argv, code in plan.commands:
            if not run_step(system, argv).ok:
                raise AgentError(code, " ".join(argv))
        for step in plan.steps:
            if step[0] == "write":
                system.write(step[1], step[2], step[3])
            elif not system.run(step[1], timeout=step[3]).ok:
                raise AgentError(step[2], " ".join(step[1]))
        if plan.moves:
            move_renewals(system, record, plan.moves)
        if plan.after is not None:
            record["details"].update(plan.after(system))
    except AgentError as exc:
        problems = restore(system, record)
        record["state"] = "failed"
        save_record(system, record)
        raise undo_error(exc, problems) from exc
    record["written"] = {e["path"]: file_sha(system, e["path"]) for e in record["files"]}
    if plan.access:
        if not start_timer(system, change_id):
            problems = restore(system, record)
            record["state"] = "failed"
            save_record(system, record)
            raise undo_error(AgentError("command_failed", "systemd-run"), problems)
        set_pending(system, record, "pending_confirm")
    else:
        record["state"] = "applied"
    save_record(system, record)
    return answer_of(record)


def stop_timer(system: System, change_id: str) -> None:
    system.run(["systemctl", "stop", f"kerberos-undo-{change_id}.timer"])


def cmd_confirm(system: System, args: list, data: Any) -> dict:
    change_id = args[0]
    record = load_record(system, change_id)
    if record is None:
        raise AgentError("no_backup", change_id)
    if record["state"] == "rollback_pending":
        return finish_rollback(system, record)
    if record["state"] == "rolled_back" and record.get("rolledBackBy") == "confirm":
        return answer_of(record)  # the answer of a confirm got lost: it is done
    if record["state"] in ("confirmed", "applied"):
        return answer_of(record, "noop")
    if record["state"] != "pending_confirm":
        raise AgentError("change_conflict", f"change is {record['state']}")
    second = record.get("confirm") or {}
    try:
        write_files(system, second.get("files") or {})
        for argv, code in second.get("commands") or []:
            if not system.run(argv).ok:
                raise AgentError(code, " ".join(argv))
    except AgentError as exc:
        # backup_damaged here leaves the timer armed: it tries the rollback once more.
        problems = restore(system, record)
        stop_timer(system, change_id)
        record["state"] = "failed"
        clear_pending(system, change_id)
        save_record(system, record)
        raise undo_error(exc, problems) from exc
    stop_timer(system, change_id)
    record["written"] = {e["path"]: file_sha(system, e["path"]) for e in record["files"]}
    record["state"] = "confirmed"
    clear_pending(system, change_id)
    save_record(system, record)
    return answer_of(record)


def cmd_undo(system: System, args: list, data: Any) -> dict:
    """The undo timer: roll back only a change that still waits for its confirmation;
    a rollback that waits for its own goes back to the confirmed change."""
    record = load_record(system, args[0])
    if record is None:
        raise AgentError("no_backup", args[0])
    if record["state"] == "rollback_pending":
        return back_to_confirmed(system, record)
    if record["state"] != "pending_confirm":
        return answer_of(record, "noop")
    return cmd_rollback(system, args, data)


def other_records(system: System, change_id: str):
    base = system.path(CHANGES_DIR)
    for name in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        if name != change_id and CHANGE_ID.match(name):
            try:
                other = load_record(system, name)
            except AgentError:
                continue
            if other is not None:
                yield other


def came_later(other: dict, record: dict) -> bool:
    """Same second, or records without `order`: the other one counts as later."""
    if "order" in other and "order" in record:
        return other["order"] >= record["order"]
    return str(other.get("at", "")) >= str(record.get("at", ""))


IN_FORCE = ("applied", "confirmed", "pending_confirm", "rollback_pending")


def key_only_after(system: System, record: dict) -> Optional[str]:
    """A later ssh.key_only in force: without the administrator key the person is locked out."""
    for other in other_records(system, record["changeId"]):
        if other["fixId"] == "ssh.key_only" and other["state"] in IN_FORCE:
            if came_later(other, record):
                return other["changeId"]
    return None


def cmd_rollback(system: System, args: list, data: Any) -> dict:
    change_id = args[0]
    record = load_record(system, change_id)
    if record is None:
        raise AgentError("no_backup", change_id)
    if record["state"] == "rolled_back":
        return answer_of(record, "noop")
    if record["state"] == "rollback_pending":
        return answer_of(record)  # waits for `confirm` over the old port, or for `undo`
    if record["state"] in ("applied", "confirmed"):
        for path, sha in record.get("written", {}).items():
            if file_sha(system, path) != sha:
                raise AgentError("change_conflict", f"{path} changed after KERBEROS")
    if record["fixId"] == "access.admin_keys" and record["state"] in IN_FORCE:
        later = key_only_after(system, record)
        if later:
            raise AgentError("change_conflict", f"ssh.key_only {later} needs this key")
    if record["state"] == "confirmed" and record.get("stage"):
        return stage_rollback(system, record)
    was = record["state"]
    # backup_damaged here leaves a timer armed: it tries the rollback once more.
    problems = restore(system, record)
    if was == "pending_confirm":
        stop_timer(system, change_id)
    record["state"] = "rolled_back"
    record["details"]["undoProblems"] = problems
    clear_pending(system, change_id)
    save_record(system, record)
    if problems:
        raise AgentError("command_failed", "undo failed: " + "; ".join(problems))
    return answer_of(record)


# -- a confirmed SSH port goes back the way it came (§9.3, K13) ------------------
def stage_rollback(system: System, record: dict) -> dict:
    """First phase: SSH listens on the old and the new port again, the undo timer runs.
    KERBEROS proves the old port with a new connection and calls `confirm`, which puts
    the old layout back; without it `undo` returns to the confirmed one, new port only."""
    change_id = record["changeId"]
    record["confirmedFiles"] = save_files(
        system, change_id, [e["path"] for e in record["files"]], "confirmed"
    )
    save_record(system, record)
    stage = record["stage"]
    try:
        write_files(system, stage["files"])
        ensure_privsep(system)
        for argv, code in stage["commands"]:
            if not run_step(system, argv).ok:
                raise AgentError(code, " ".join(argv))
        if not start_timer(system, change_id, again=True):
            raise AgentError("command_failed", "systemd-run")
    except AgentError as exc:
        problems = layout_of_confirm(system, record)
        save_record(system, record)
        raise undo_error(exc, problems) from exc
    set_pending(system, record, "rollback_pending")
    save_record(system, record)
    return answer_of(record)


def layout_of_confirm(system: System, record: dict) -> list:
    """The files of the confirmed change and the commands that made them work."""
    put_back(system, record["changeId"], record.get("confirmedFiles") or [])
    ensure_privsep(system)
    return [" ".join(argv) for argv, _code in (record.get("confirm") or {}).get("commands") or []
            if not run_step(system, argv).ok]  # fmt: skip


def back_to_confirmed(system: System, record: dict) -> dict:
    problems = layout_of_confirm(system, record)
    stop_timer(system, record["changeId"])
    record["state"] = "confirmed"
    clear_pending(system, record["changeId"])
    save_record(system, record)
    if problems:
        raise AgentError("command_failed", "undo failed: " + "; ".join(problems))
    return answer_of(record)


def finish_rollback(system: System, record: dict) -> dict:
    """Second phase: the old port answered a new connection; only the old layout stays."""
    # backup_damaged leaves the timer armed: it brings back the confirmed layout.
    problems = restore(system, record)
    stop_timer(system, record["changeId"])
    record["state"] = "rolled_back"
    record["rolledBackBy"] = "confirm"
    record["details"]["undoProblems"] = problems
    clear_pending(system, record["changeId"])
    save_record(system, record)
    if problems:
        raise AgentError("command_failed", "undo failed: " + "; ".join(problems))
    return answer_of(record)


def cmd_plan(system: System, args: list, data: dict) -> dict:
    builder = FIXES.get(args[0])
    if builder is None:
        raise AgentError("not_implemented", args[0])
    plan = builder(system, data)
    return {
        "files": [
            {"path": p, "content": None if p in plan.private else text}
            for p, (text, _mode) in plan.files.items()
        ]  # fmt: skip
        # Renewal configs of acme.sh and certbot: files of the person, shown by path only.
        + [{"path": move["path"], "content": None} for move in plan.moves],
        "commands": [" ".join(argv) for argv, _code in plan.commands],
        "packages": plan.packages,
    }


# -- the fixes of §10.3 -------------------------------------------------------
def nft_unit(name: str, table: str, conf: str, about: str) -> str:
    return (
        "[Unit]\n"
        f"Description=KERBEROS: {about}\n"
        "After=network-pre.target\n"
        "Wants=network-pre.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        f"ExecStart=/usr/sbin/nft -f {conf}\n"
        f"ExecStop=/usr/sbin/nft delete table {table}\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def nft_table(table: str, rules: list) -> str:
    """Loading is idempotent: the table is created, flushed and filled again."""
    body = "\n".join(f"    {rule}" for rule in rules)
    return (
        f"table {table}\nflush table {table}\n"
        f"table {table} {{\n  chain input {{\n"
        "    type filter hook input priority -10; policy accept;\n"
        f"{body}\n  }}\n}}\n"
    )


def service_state(system: System, unit: str) -> tuple:
    """Enabled and running, by the exit codes of `systemctl is-enabled` and `is-active`."""
    enabled = system.run(["systemctl", "is-enabled", unit]).ok
    return enabled, system.run(["systemctl", "is-active", unit]).ok


def service_back(unit: str, enabled: bool, active: bool, start: str = "restart") -> list:
    """Undo commands that leave a service as it was: enabled or not, running or not."""
    return [["systemctl", "enable" if enabled else "disable", unit],
            ["systemctl", start if active else "stop", unit]]  # fmt: skip


def nft_service(plan: Plan, name: str, table: str, rules: list, about: str,
                system: Optional[System] = None) -> None:  # fmt: skip
    # Debian cloud images come without nft; the package stays after a rollback.
    missing = system is not None and needs_package(system, "nftables", "/usr/sbin/nft")
    if missing and "nftables" not in plan.packages:
        plan.packages.append("nftables")
    conf = f"/etc/kerberos/{name}.nft"
    unit = f"kerberos-{name}.service"
    existed = system is not None and system.exists(f"/etc/systemd/system/{unit}")
    plan.write(conf, nft_table(table, rules))
    plan.write(f"/etc/systemd/system/{unit}", nft_unit(name, table, conf, about))
    plan.run(["systemctl", "daemon-reload"])
    plan.run(["systemctl", "enable", unit])
    plan.run(["systemctl", "restart", unit])
    if existed and system is not None:
        # An earlier change of this fix is in force: the restored files hold its rules,
        # so the unit loads them again instead of going away with them.
        enabled, active = service_state(system, unit)
        plan.undo_after += [["systemctl", "daemon-reload"], *service_back(unit, enabled, active)]
    else:
        plan.undo_before.append(["systemctl", "disable", "--now", unit])
        plan.undo_after.append(["systemctl", "daemon-reload"])


@fix("mptcp.guard")
def fix_mptcp(system: System, params: dict) -> Plan:
    current = system.read("/proc/sys/net/mptcp/enabled")
    if current is None:
        raise AgentError("mptcp_absent", "no net.mptcp in this kernel")
    plan = Plan("mptcp.guard")
    plan.write("/etc/sysctl.d/98-kerberos-mptcp.conf", "net.mptcp.enabled = 0\n")
    plan.run(["sysctl", "-w", "net.mptcp.enabled=0"])
    nft_service(plan, "mptcp", "inet kerberos_mptcp",
                ["ip protocol tcp ip hdrlength > 5 counter drop"],
                "drop TCP packets with IP options (MPTCP guard)", system)  # fmt: skip
    plan.undo_after.append(["sysctl", "-w", f"net.mptcp.enabled={current.strip() or '0'}"])
    return plan


def int_list(value: Any, what: str) -> list:
    if not isinstance(value, list) or not value:
        raise AgentError("bad_params", what)
    result = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or not 0 < item < 65536:
            raise AgentError("bad_params", what)
        result.append(item)
    return result


def address_param(system: System, params: dict) -> str:
    value = str(params.get("panelIp") or panel_address(system))
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise AgentError("bad_params", "panelIp") from exc


def fail2ban_value(configs: list, section: str, key: str) -> Optional[str]:
    """The value of `key` in `section` that wins over fail2ban's files in their order;
    a value goes on over the indented lines after it."""
    value = None
    for _name, text in configs:
        current, going_on = None, False
        for raw in (text or "").splitlines():
            line = raw.split("#", 1)[0].split(";", 1)[0]
            if not line.strip():
                going_on = going_on and bool(raw.strip())
                continue
            if raw[:1] in (" ", "\t") and going_on and value is not None:
                value += " " + line.strip()
                continue
            going_on = False
            header = re.match(r"^\[(.+)\]$", line.strip())
            if header:
                current = header.group(1).strip()
                continue
            name, sep, rest = line.partition("=")
            if sep and current == section and name.strip().lower() == key:
                value, going_on = rest.strip(), True
    return value


def ignore_list(*values: Optional[str]) -> str:
    tokens: list = []
    for value in values:
        for token in re.split(r"[,\s]+", value or ""):
            if token and token not in tokens:
                tokens.append(token)
    return " ".join(tokens)


@fix("fail2ban.sshd")
def fix_fail2ban(system: System, params: dict) -> Plan:
    ports = int_list(params.get("sshPorts"), "sshPorts")
    panel = address_param(system, params)
    installed = system.exists("/usr/bin/fail2ban-client")
    plan = Plan("fail2ban.sshd")
    if needs_package(system, "fail2ban", "/usr/bin/fail2ban-client"):
        plan.packages.append("fail2ban")
    if needs_package(system, "python3-systemd", "/usr/lib/python3/dist-packages/systemd"):
        plan.packages.append("python3-systemd")
    # Our file is read last and its ignoreip replaces the person's whitelist: keep it.
    configs = [(name, text) for name, text in fail2ban_files(system) if name != JAIL_FILE]
    ours = f"127.0.0.1/8 ::1 {panel}"
    sshd = fail2ban_value(configs, "sshd", "ignoreip")
    plan.write(
        JAIL_FILE,
        "[DEFAULT]\n"
        f"ignoreip = {ignore_list(fail2ban_value(configs, 'DEFAULT', 'ignoreip'), ours)}\n"
        "[sshd]\n"
        "enabled = true\n"
        f"port = {','.join(str(p) for p in ports)}\n"
        + (f"ignoreip = {ignore_list(sshd, ours)}\n" if sshd is not None else "")
        + "backend = systemd\n"
        "maxretry = 5\n"
        "findtime = 10m\n"
        "bantime = 1h\n",
    )
    plan.run(["systemctl", "enable", "fail2ban"])
    plan.run(["systemctl", "restart", "fail2ban"])
    if installed:
        # A fail2ban the person stopped stays stopped after the rollback.
        plan.undo_after += service_back("fail2ban", *service_state(system, "fail2ban"))
    else:
        plan.undo_after += [["systemctl", "disable", "--now", "fail2ban"],
                            ["apt-get", "remove", "-y", "-q", "fail2ban"]]  # fmt: skip
    return plan


@fix("node_api.panel_only")
def fix_node_api(system: System, params: dict) -> Plan:
    port = int_list([params.get("port")], "port")[0]
    panel = address_param(system, params)
    remnanode = parse_remnanode(system.run(["docker", "inspect", "remnanode"]).stdout)
    if remnanode.get("network") == "bridge":
        raise AgentError("bridge_network", "remnanode publishes its port through Docker")
    if plain_ip(panel) not in node_api_peers(system, port):
        # The panel reaches the node from another address (IPv6 SSH, IPv4 backend):
        # the rule would cut the panel off its node.
        raise AgentError("panel_not_peer", f"no connection to port {port} from {panel}")
    family = "ip6" if ":" in panel else "ip"
    plan = Plan("node_api.panel_only")
    nft_service(plan, "node-api", "inet kerberos_node_api", [
        f"tcp dport {port} {family} saddr {panel} counter accept",
        f"tcp dport {port} counter drop",
    ], "the node API only for the panel", system)  # fmt: skip
    plan.details = {"port": port, "panelIp": panel}
    return plan


SSH_GUARD = "inet kerberos_ssh"


@fix("ssh.panel_only")
def fix_ssh_panel_only(system: System, params: dict) -> Plan:
    """K28: SSH of the node answers only the panel server; the person comes in through it
    (`kerberos ssh`, `ssh -J`) or the console of the hoster. Sessions open now stay."""
    panel = address_param(system, params)
    came = plain_ip(panel_address(system))
    if came and came != plain_ip(panel):
        # The rule would let in an address KERBEROS does not come from: it cuts itself off.
        raise AgentError("panel_not_peer", "this session comes from another address")
    v4, v6 = parse_ip_addr(system.run(["ip", "-j", "addr", "show"]).stdout)
    if ipaddress.ip_address(panel).is_loopback or plain_ip(panel) in v4 + v6:
        raise AgentError("panel_local", "the panel server is this node: SSH only from itself")
    keys = (system.read(AUTHORIZED_KEYS) or "") + "\n" + (system.read(AUTHORIZED_KEYS + "2") or "")
    if count_admin_keys(keys) == 0:
        raise AgentError("no_admin_key", "no key of the administrator to come in with")
    ports = sorted(ssh_ports_in_use(system, system.run(["ss", "-Hlntup"]).stdout))
    if not ports:
        raise AgentError("bad_params", "no port of SSH")
    listed = ", ".join(str(p) for p in ports)
    family = "ip6" if ":" in panel else "ip"
    plan = Plan("ssh.panel_only")
    nft_service(plan, "ssh", SSH_GUARD, [
        f"tcp dport {{ {listed} }} ct state established,related accept",
        f'iifname "lo" tcp dport {{ {listed} }} accept',
        f"tcp dport {{ {listed} }} {family} saddr {panel} counter accept",
        f"tcp dport {{ {listed} }} counter drop",
    ], "SSH only from the panel server", system)  # fmt: skip
    plan.access = True
    plan.details = {"ports": ports, "panelIp": panel}
    return plan


PORT_RE = re.compile(r"^(\d{1,5})/(tcp|udp)$")


def ssh_ports_in_use(system: System, ss_text: str) -> set:
    """Ports of SSH right now: the one this session came in on, every port sshd holds
    and the ports of ssh.socket when it is active."""
    ports = set(sshd_listen_ports(ss_text))
    parts = system.environ.get("SSH_CONNECTION", "").split()
    if len(parts) >= 4 and parts[3].isdigit():
        ports.add(int(parts[3]))
    if socket_active(system):
        ports.update(parse_socket_ports(socket_listen_text(system)))
    return ports


@fix("ports.drop")
def fix_ports(system: System, params: dict) -> Plan:
    wanted = []
    for item in params.get("ports") or []:
        match = PORT_RE.match(str(item))
        if not match or not 0 < int(match.group(1)) < 65536:
            raise AgentError("bad_params", "ports")
        wanted.append((int(match.group(1)), match.group(2)))
    if not wanted:
        raise AgentError("bad_params", "ports")
    ss_text = system.run(["ss", "-Hlntup"]).stdout
    # The rule drops established packets too: on an SSH port it would cut this very
    # session and every way back to the node. No undo timer guards ports.drop.
    ssh = ssh_ports_in_use(system, ss_text)
    refused = [f"{p}/{proto}" for p, proto in wanted if proto == "tcp" and p in ssh]
    if refused:
        raise AgentError("ssh_port", ", ".join(refused))
    published = docker_published(system.run(["docker", "ps", "--format", "{{json .}}"]).stdout)
    for sock in parse_ss_listen(ss_text):
        if sock["process"] == "docker-proxy":
            published.add((sock["port"], sock["proto"]))
    blocked = [f"{p}/{proto}" for p, proto in wanted if (p, proto) in published]
    if blocked:
        raise AgentError("docker_published", ", ".join(blocked))
    existing = re.findall(
        r"(tcp|udp) dport (\d+) drop", system.read("/etc/kerberos/ports.nft") or ""
    )
    ports = sorted({(int(p), proto) for proto, p in existing} | set(wanted))
    rules = [f'iifname != "lo" {proto} dport {port} drop' for port, proto in ports]
    plan = Plan("ports.drop")
    nft_service(plan, "ports", "inet kerberos_ports", rules, "drop ports nobody should reach",
                system)  # fmt: skip
    plan.details = {"ports": [f"{p}/{proto}" for p, proto in wanted]}
    return plan


def ssh_reload(plan: Plan, system: System) -> None:
    ensure_privsep(system)
    plan.run(["sshd", "-t"], "sshd_test_failed")
    plan.run(["systemctl", "try-reload-or-restart", "ssh.service"])
    plan.undo_after.append(["systemctl", "try-reload-or-restart", "ssh.service"])


def host_key_type(system: System, path: str) -> tuple:
    """(ssh-keygen type, bits or None) of a host key, from its .pub, else from its name."""
    first = ((system.read(path + ".pub") or "").split() or [""])[0]
    if first.startswith("ecdsa-sha2-nistp"):
        return "ecdsa", first[len("ecdsa-sha2-nistp") :]
    named = {"ssh-ed25519": "ed25519", "ssh-rsa": "rsa", "ssh-dss": "dsa"}.get(first)
    if named:
        return named, None
    name = os.path.basename(path)
    for kind in ("ed25519", "ecdsa", "rsa", "dsa"):
        if kind in name:
            return kind, None
    return "", None


@fix("hostkeys.regenerate")
def fix_hostkeys(system: System, params: dict) -> Plan:
    """New keys of the same types, made one by one, in the files sshd really uses (the
    HostKey lines of `sshd -T`). Not `ssh-keygen -A`: up to OpenSSH 9 it also makes a DSA
    key, so a server without one would get a deprecated key that the rollback does not
    take away. A DSA key the server already has stays as it is."""
    plan = Plan("hostkeys.regenerate")
    paths = host_key_files(sshd_values(system))
    for path in paths:
        kind, bits = host_key_type(system, path)
        if kind not in HOST_KEY_NAMES:
            continue
        if not system.exists(path) and kind != "ed25519":
            continue  # no new key types; ED25519 is the one the fleet is compared by
        for file in (path, path + ".pub"):
            if system.exists(file):
                plan.write(file, None)
            else:
                plan.created.append(file)
        plan.run(["ssh-keygen", "-q", "-t", kind, *(["-b", bits] if bits else []), "-N", "",
                  "-f", path])  # fmt: skip
    ssh_reload(plan, system)
    plan.access = True
    plan.after = lambda system_: {"hostKeys": host_key_facts(public_keys(system_, paths))}
    return plan


@fix("ssh.key_only")
def fix_key_only(system: System, params: dict) -> Plan:
    if count_admin_keys(system.read(AUTHORIZED_KEYS) or "") == 0:
        raise AgentError("no_admin_key", "no key of the administrator besides KERBEROS")
    kept = [line for line in (system.read(SSHD_CONF) or "").splitlines()
            if line.split(" ", 1)[0].lower() == "port"]  # fmt: skip
    lines = ["PasswordAuthentication no", "KbdInteractiveAuthentication no",
             "PermitRootLogin prohibit-password", *kept]  # fmt: skip
    plan = Plan("ssh.key_only")
    plan.write(SSHD_CONF, "\n".join(lines) + "\n", private=True)
    ssh_reload(plan, system)
    plan.access = True
    return plan


SOCKET_DROPIN = "/etc/systemd/system/ssh.socket.d/zz-kerberos.conf"
# systemd gives up on a socket restarted more than five times in ten seconds
# (start-limit-hit) and new SSH logins stop: the counter goes to zero first.
SOCKET_RESTART = (
    ["systemctl", "reset-failed", "ssh.socket", "ssh.service"],
    ["systemctl", "restart", "ssh.socket"],
)
SSHD_MAIN = "/etc/ssh/sshd_config"
JAIL_FILE = "/etc/fail2ban/jail.d/zz-kerberos.local"


def socket_listen(text: str) -> list:
    """Addresses of `systemctl show ssh.socket -p Listen`: [("0.0.0.0", 22), ("[::]", 22)]."""
    found = []
    for match in re.finditer(r"(\[[^\]]*\]|[0-9.]+|\*)?:(\d+) \(Stream\)", text or ""):
        host = match.group(1) or ""
        item = (host, int(match.group(2)))
        if item not in found:
            found.append(item)
    return found


def socket_dropin(hosts: list, ports: list) -> str:
    lines = ["[Socket]", "ListenStream="]
    for port in ports:
        for host in hosts:
            lines.append(f"ListenStream={host}:{port}" if host else f"ListenStream={port}")
    return "\n".join(lines) + "\n"


def with_ports(text: str, ports: list) -> str:
    """Our sshd file: other lines as they are, Port lines for `ports`."""
    kept = [line for line in (text or "").splitlines() if line.split(" ", 1)[0].lower() != "port"]
    return "\n".join(kept + [f"Port {p}" for p in ports]) + "\n"


def comment_ports(text: str) -> str:
    lines = []
    for line in (text or "").splitlines():
        if re.match(r"^\s*Port\s+\d+", line, re.I):
            line = f"# {line.strip()}  # KERBEROS: the port lives in sshd_config.d"
        lines.append(line)
    return "\n".join(lines) + "\n"


def jail_ports(text: str, ports: list) -> str:
    joined = ",".join(str(p) for p in ports)
    return re.sub(r"(?m)^port\s*=.*$", f"port = {joined}", text)


@fix("ssh.port")
def fix_ssh_port(system: System, params: dict) -> Plan:
    port = int_list([params.get("port")], "port")[0]
    if port < 1024:
        raise AgentError("bad_params", "port")
    if any(s["port"] == port for s in parse_ss_listen(system.run(["ss", "-Hlntup"]).stdout)):
        raise AgentError("port_busy", str(port))
    plan = Plan("ssh.port")
    plan.access = True
    plan.stage = True
    if parse_ufw(system.run(["ufw", "status", "verbose"]).stdout)["state"] == "active":
        plan.run(["ufw", "allow", f"{port}/tcp"])
        plan.undo_after.append(["ufw", "delete", "allow", f"{port}/tcp"])
    socket = system.run(["systemctl", "is-active", "ssh.socket"]).stdout.strip() == "active"
    listen = socket_listen(system.run(["systemctl", "show", "ssh.socket", "-p", "Listen"]).stdout)
    if socket and listen:
        old = sorted({p for _host, p in listen})
        hosts = list(dict.fromkeys(host for host, _p in listen)) or ["0.0.0.0", "[::]"]
        plan.write(SOCKET_DROPIN, socket_dropin(hosts, old + [port]))
        plan.run(["systemctl", "daemon-reload"])
        for argv in SOCKET_RESTART:
            plan.run(argv)
        plan.on_confirm(SOCKET_DROPIN, socket_dropin(hosts, [port]))
        plan.on_confirm(argv=["systemctl", "daemon-reload"])
        for argv in SOCKET_RESTART:
            plan.on_confirm(argv=argv)
        plan.undo_after += [["systemctl", "daemon-reload"], *SOCKET_RESTART]
    else:
        old = parse_sshd_t(system.run(["sshd", "-T"]).stdout).get("port") or [22]
        current = system.read(SSHD_CONF) or ""
        plan.write(SSHD_CONF, with_ports(current, old + [port]), private=True)
        ssh_reload(plan, system)
        plan.on_confirm(SSHD_CONF, with_ports(current, [port]))
        main = system.read(SSHD_MAIN)
        if main is not None and re.search(r"(?m)^\s*Port\s+\d+", main, re.I):
            plan.on_confirm(SSHD_MAIN, comment_ports(main))
        plan.on_confirm(argv=["sshd", "-t"], code="sshd_test_failed")
        plan.on_confirm(argv=["systemctl", "try-reload-or-restart", "ssh.service"])
    jail = system.read(JAIL_FILE)
    if jail is not None:
        plan.write(JAIL_FILE, jail_ports(jail, old + [port]))
        plan.run(["systemctl", "restart", "fail2ban"])
        plan.on_confirm(JAIL_FILE, jail_ports(jail, [port]))
        plan.on_confirm(argv=["systemctl", "restart", "fail2ban"])
        plan.undo_after.append(["systemctl", "restart", "fail2ban"])
    plan.details = {"newPort": port, "oldPorts": old, "socket": bool(socket and listen)}
    return plan


# -- self-steal on the node (§10.4 step 1, §10.9) ------------------------------
SITE_CONF = "/etc/nginx/sites-enabled/kerberos-site"
ACME_ROOT = "/var/www/kerberos-acme"
SITE_ROOT = "/var/www/kerberos-site"
RENEW_HOOK = "/etc/letsencrypt/renewal-hooks/deploy/kerberos-nginx-reload"
COMPOSE_FILE = "/opt/remnanode/docker-compose.yml"
LETSENCRYPT_VOLUME = "/etc/letsencrypt:/etc/letsencrypt:ro"

# -- the stub site (tech.md §10.4 step 1): a site of its own on every node -----
# A small business with its own name, texts, colours, fonts and markup, all
# from one seed. Nothing is loaded from elsewhere: styles, icon and pictures
# are inline, so the page asks no other server for anything.
SITE_SEEDS = 1 << 32


class SiteRandom:
    """The random stream of a site: sha256 of the seed in counter mode.

    It is the same on every Python version, so KERBEROS on the panel server
    and the agent on the node build the same site from the same seed.
    """

    def __init__(self, seed: int, part: str) -> None:
        self.key = f"kerberos-site:{seed}:{part}:".encode()
        self.counter = 0

    def random(self) -> float:
        block = hashlib.sha256(self.key + str(self.counter).encode()).digest()
        self.counter += 1
        return int.from_bytes(block[:6], "big") / float(1 << 48)

    def below(self, n: int) -> int:
        return int(self.random() * n)

    def choice(self, items: Any) -> Any:
        return items[self.below(len(items))]

    def uniform(self, low: float, high: float) -> float:
        return low + (high - low) * self.random()

    def chance(self, p: float) -> bool:
        return self.random() < p

    def shuffled(self, items: Any) -> list:
        result = list(items)
        for i in range(len(result) - 1, 0, -1):
            j = self.below(i + 1)
            result[i], result[j] = result[j], result[i]
        return result

    def sample(self, items: Any, k: int) -> list:
        return self.shuffled(items)[:k]

    def word(self, text: str) -> str:
        return self.choice(text.split("|"))

    def words(self, text: str, k: int) -> list:
        return self.sample(text.split("|"), k)


def hsl_hex(hue: float, saturation: float, lightness: float) -> str:
    red, green, blue = colorsys.hls_to_rgb((hue % 360) / 360, lightness, saturation)
    return "#" + "".join(f"{round(c * 255):02x}" for c in (red, green, blue))


def mix(a: str, b: str, share: float) -> str:
    """`share` of colour b in colour a."""
    pairs = [(int(a[i : i + 2], 16), int(b[i : i + 2], 16)) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * share):02x}" for x, y in pairs)


def luminance(color: str) -> float:
    channels = [int(color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(a: str, b: str) -> float:
    """WCAG contrast ratio of two colours, 1 to 21."""
    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


# Kinds of small businesses. Items are separated by "|", fields of an item by "=".
# offers: name=what it is=price; prices are numbers, "from N" for services.
SITE_KINDS = {
    "bakery": {
        "names": "Rye|Hearth|Crumb|Ember|Morning|Wheatfield|Larder|Millstone",
        "suffix": "Bakery|Bakehouse|Bread Co.",
        "hero": "Bread baked before sunrise|Sourdough worth getting up for|Good bread takes two"
        " days",
        "lead": "We bake in small batches with flour from a stone mill. Order by noon and collect"
        " the next morning.|Everything leaves the oven before seven. When a tray is gone, it is"
        " gone until tomorrow.",
        "offers": "Sourdough loaf=Two days of fermentation and a dark, crackling crust=6.50"
        "|Seeded rye=Sunflower, flax and pumpkin seeds in a dense rye=5.80"
        "|Cardamom buns=Twisted by hand and brushed with a little syrup=3.20"
        "|Focaccia=Olive oil, rosemary and flaky salt=4.90"
        "|Butter croissants=Three days from dough to tray=2.80"
        "|Apple tart=Seasonal apples on almond cream=4.40",
        "about": "The bakery started in {since} in a rented kitchen with one oven. We still bake"
        " by hand and still at night, now for the neighbourhood and a few cafes.|Our flour comes"
        " from a mill we visit every season, and our starter is older than the shop.",
        "facts": "Baked by hand every night|Flour from a stone mill|No improvers, no shortcuts",
        "menu": "Today's bakes|What we bake|The bread list",
        "cta": "Order bread|See today's bakes",
        "motif": "loaf",
        "opens": 7,
        "fonts": ("oldstyle|didone|slab", "humanist|transitional"),
        "hue": (18, 50),
        "dark": 0.1,
    },
    "coffee": {
        "names": "Copper|Kettle|Ridge|Harbor|North|Cinder|Ember|Fable",
        "suffix": "Coffee Roasters|Coffee|Roastery",
        "hero": "Coffee roasted on Tuesdays|Fresh beans, honest roasts|Coffee you can taste the"
        " farm in",
        "lead": "We roast small batches every week and print the roast date on every bag. Come"
        " by for a cup or take beans home.|Single origin beans from farms we know by name,"
        " roasted light enough to taste where they grew.",
        "offers": "House espresso=Chocolate, hazelnut and a long finish=14.00"
        "|Ethiopia Guji=Peach, jasmine and black tea=16.50"
        "|Colombia Huila=Red apple, caramel and cocoa=15.00"
        "|Filter tasting set=Three 100 g bags of this month's coffees=18.00"
        "|Cold brew=Steeped for sixteen hours, sold by the bottle=4.50"
        "|Brewing class=Two hours on grind, ratio and water=from 35",
        "about": "We started roasting in {since} on a machine the size of a washing machine."
        " The roaster is bigger now, the batches are not.|Every coffee is cupped before it"
        " goes on the shelf. If it does not taste right, it does not go out.",
        "facts": "Roast date on every bag|Green beans bought directly|Free grind on request",
        "menu": "Coffee and more|On the shelf|The menu",
        "cta": "Order beans|Visit the café",
        "motif": "cup",
        "opens": 8,
        "fonts": ("slab|grotesk|didone", "neo|humanist"),
        "hue": (10, 40),
        "dark": 0.45,
    },
    "bikes": {
        "names": "Spoke|Gear|Chain|Tandem|Pedal|Crank|Freewheel|Cadence",
        "suffix": "Bike Workshop|Cycles|Bicycle Repair",
        "hero": "Repairs done the same week|Your bike, running like new|We fix what others replace",
        "lead": "Brakes, gears, wheels and old frames. Book a slot online or just ride in, and"
        " we will tell you honestly what it needs.|A small workshop for everyday bikes, road"
        " bikes and the old ones in the shed that deserve a second life.",
        "offers": "Full service=Every bolt, cable and bearing checked and adjusted=from 89"
        "|Wheel truing=Spokes tensioned and the wheel brought back true=from 25"
        "|Brake tune-up=Pads, cables and alignment for quiet, sure stops=from 30"
        "|Bike fitting=Saddle, bars and cleats set to the way you ride=from 60"
        "|Winter storage=Dry, safe and serviced before spring=from 15"
        "|Used bikes=Checked, serviced and sold with a three-month warranty=from 180",
        "about": "We opened the workshop in {since} with two stands and a box of spare parts."
        " Most of our customers ride to work and need their bike back tomorrow.|We would rather"
        " true an old wheel than sell you a new one, and we will tell you which makes sense.",
        "facts": "Free safety check at the door|Repairs within a week|Old frames welcome",
        "menu": "Services|Repairs and prices|What we do",
        "cta": "Book a repair|Ask about your bike",
        "motif": "bicycle",
        "opens": 9,
        "fonts": ("industrial|grotesk|neo", "neo|grotesk"),
        "hue": (0, 360),
        "dark": 0.35,
    },
    "photo": {
        "names": "Aperture|Lumen|Frame|Silver|Contact|Grain|Darkroom|Exposure",
        "suffix": "Photo Studio|Photography|Pictures",
        "hero": "Portraits in natural light|Pictures you will keep for decades|Unhurried"
        " sessions, honest pictures",
        "lead": "A daylight studio for portraits, families and small brands. Every picture is"
        " edited by hand and delivered within two weeks.|We take our time, so you can forget"
        " about the camera. The pictures look like you on a good day.",
        "offers": "Portrait session=One hour in the studio, ten edited pictures=from 150"
        "|Family session=Up to six people, at home or in the studio=from 220"
        "|Product photos=Clean shots for shops and catalogues=from 180"
        "|Film scanning=High-resolution scans of negatives and slides=from 2 per frame"
        "|Fine art prints=Archival cotton paper, signed=from 45",
        "about": "The studio opened in {since} in a former print shop with tall north windows."
        " The light is still the best thing about it.|We shoot digital and on film, and we"
        " print in house, so we see every picture through to the paper.",
        "facts": "Pictures delivered within two weeks|Printing in house|Film and digital",
        "menu": "Sessions and prints|Services|What we offer",
        "cta": "Book a session|See the portfolio",
        "motif": "camera",
        "opens": 10,
        "fonts": ("didone|grotesk|geometric", "grotesk|neo"),
        "hue": (180, 300),
        "dark": 0.5,
    },
    "translate": {
        "names": "Lingua|Parallel|Margin|Glossa|Atlas|Verso|Idiom|Polyglot",
        "suffix": "Translations|Language Services|Translation Studio",
        "hero": "Translations that read like originals|Every text read twice|Your words, in"
        " their language",
        "lead": "Legal, technical and marketing texts in twelve languages, translated by native"
        " speakers and checked by a second linguist.|We translate documents, manuals and"
        " websites, and we keep the deadline we promise.",
        "offers": "Legal documents=Contracts, certificates and court papers=from 0.12 per word"
        "|Technical manuals=Consistent terminology across every update=from 0.10 per word"
        "|Websites=Translated, localised and checked in the layout=from 0.11 per word"
        "|Certified copies=Sworn translations accepted by authorities=from 35"
        "|Interpreting=Meetings, notaries and site visits=from 70",
        "about": "We started in {since} as two translators sharing an office. Today a team of"
        " linguists works with us, each in their own language pair.|Every text is translated"
        " by a native speaker and read by a second one before it leaves the office.",
        "facts": "Native speakers only|Second reading for every text|Confidential by default",
        "menu": "Services|What we translate|Rates",
        "cta": "Request a quote|Send your text",
        "motif": "bubbles",
        "opens": 9,
        "fonts": ("transitional|neo|geometric", "neo|humanist|transitional"),
        "hue": (190, 250),
        "dark": 0.15,
    },
    "architecture": {
        "names": "Grid|Plinth|Atrium|Lintel|Cornice|Facade|Vault|Gable",
        "suffix": "Architects|Architecture|Studio",
        "hero": "Buildings that age well|Houses designed around the way you live|Small"
        " buildings, carefully made",
        "lead": "We design houses, renovations and interiors, from the first sketch to the"
        " last site visit.|A small practice for private clients. We listen first and draw"
        " second.",
        "offers": "New houses=From the site visit to the building permit=on request"
        "|Renovations=Old buildings made comfortable without losing their character=on request"
        "|Interiors=Kitchens, stairs and built-in furniture=on request"
        "|Feasibility studies=What your site allows before you buy it=from 900"
        "|Planning permits=Drawings and paperwork for the authorities=from 1200",
        "about": "The practice was founded in {since}. We take on a handful of projects a"
        " year so that we can see each one through.|We draw by hand first, build models,"
        " and only then move to the computer.",
        "facts": "A few projects a year|Models before drawings|Site visits included",
        "menu": "What we do|Services|Projects we take on",
        "cta": "Start a project|Talk to us",
        "motif": "building",
        "opens": 9,
        "fonts": ("grotesk|didone|neo", "grotesk|neo"),
        "hue": (0, 360),
        "dark": 0.3,
    },
    "pottery": {
        "names": "Kiln|Clay|Glaze|Terra|Wheel|Slip|Ochre|Ember",
        "suffix": "Ceramics|Pottery|Clay Studio",
        "hero": "Thrown by hand, fired twice|Tableware for every day|Pots made slowly",
        "lead": "Plates, bowls and cups thrown on the wheel and glazed in the studio. Every"
        " piece is a little different.|A small studio making tableware and teaching beginners"
        " on the wheel.",
        "offers": "Dinner plate=Stoneware with a satin glaze, 27 cm=38.00"
        "|Breakfast bowl=Wide and deep, safe in the dishwasher=29.00"
        "|Tea cup=No handle, sits warm in the hand=22.00"
        "|Wheel class for beginners=Four evenings, clay and firing included=from 180"
        "|Seconds shelf=Small flaws, same pots, lower prices=from 10",
        "about": "The studio has been firing since {since}. Our glazes are mixed in the"
        " studio from raw materials, so no two batches are quite the same.|Classes are small,"
        " six people at most, so everyone gets time at the wheel.",
        "facts": "Glazes mixed in the studio|Classes of six or fewer|Food safe and oven proof",
        "menu": "In the shop|Pots and classes|What we make",
        "cta": "Visit the shop|Book a class",
        "motif": "vase",
        "opens": 11,
        "fonts": ("oldstyle|rounded|geometric", "humanist|geometric"),
        "hue": (10, 210),
        "dark": 0.15,
    },
    "tea": {
        "names": "Leaf|Oolong|Steam|Jade|Willow|Monsoon|Camellia|Lantern",
        "suffix": "Tea House|Teas|Tea Room",
        "hero": "Tea from small gardens|A quiet cup in a busy town|Loose leaf, brewed right",
        "lead": "Green, oolong and black teas from small gardens, brewed at the right"
        " temperature and served in a quiet room.|Taste before you buy: every tea on our"
        " shelves can be brewed for you on the spot.",
        "offers": "Sencha=Fresh and grassy, from a family garden=12.00"
        "|Aged oolong=Roasted, honeyed and very calm=19.00"
        "|Darjeeling first flush=Bright, floral, picked in spring=16.00"
        "|Herbal blend=Mint, lemon verbena and chamomile=9.00"
        "|Tasting flight=Three teas brewed side by side=from 14",
        "about": "We opened the tea room in {since} after years of travelling to tea gardens."
        " Most of our teas come from growers we have met.|We brew every tea at its own"
        " temperature and time, and we are happy to show you how.",
        "facts": "Teas from small gardens|Samples before you buy|Brewed at the right temperature",
        "menu": "On the shelf|The tea list|The menu",
        "cta": "Visit the tea room|Order tea",
        "motif": "teacup",
        "opens": 11,
        "fonts": ("oldstyle|rounded|humanist", "humanist|transitional"),
        "hue": (70, 170),
        "dark": 0.2,
    },
    "bindery": {
        "names": "Folio|Quire|Vellum|Spine|Octavo|Colophon|Signature|Marbled",
        "suffix": "Bindery|Bookbinding|Book Arts",
        "hero": "Old books brought back to life|Stitched, not glued|Books made to be kept",
        "lead": "Repairs of old books, custom journals and boxes, all sewn and bound by hand"
        " at our bench.|We repair family bibles, cookbooks and first editions, and we make"
        " new books that will outlive their owners.",
        "offers": "Book repair=Loose pages, broken spines and torn covers=from 40"
        "|Custom journal=Your paper, your cover, your size=from 65"
        "|Thesis binding=Hard cover, gold lettering, ready in three days=from 30"
        "|Boxes and cases=Made to measure for precious books=from 55"
        "|Weekend workshop=Sew your first book in two days=from 120",
        "about": "The bindery has been at its bench since {since}. Most of our work is"
        " repair: books that have been read for generations.|We sew every book by hand and"
        " use reversible glues, so the next binder can repair it again.",
        "facts": "Sewn by hand|Reversible materials|Gold lettering in house",
        "menu": "What we do|Repairs and books|Services",
        "cta": "Bring a book|Order a journal",
        "motif": "book",
        "opens": 10,
        "fonts": ("oldstyle|didone|transitional", "oldstyle|transitional"),
        "hue": (330, 390),
        "dark": 0.25,
    },
    "garden": {
        "names": "Fern|Meadow|Hedge|Moss|Orchard|Thyme|Juniper|Bramble",
        "suffix": "Garden Design|Gardens|Landscapes",
        "hero": "Gardens for every season|Plants that suit your soil|From a balcony to an orchard",
        "lead": "We design and plant gardens that look after themselves, with plants chosen"
        " for your soil, light and time.|Garden plans, planting and seasonal care from a small"
        " team that loves what grows.",
        "offers": "Garden plan=A drawn plan with a planting list=from 350"
        "|Planting=We bring the plants and put them in the ground=from 40 per hour"
        "|Seasonal care=Four visits a year to prune, feed and tidy=from 280"
        "|Balcony gardens=Pots, soil and plants for small spaces=from 120"
        "|Hedges and trees=Planting, shaping and advice=on request",
        "about": "We have been planting gardens since {since}. Most of them are small, and"
        " all of them are meant to be lived in.|We use no chemicals and prefer plants that"
        " feed bees and birds.",
        "facts": "No chemicals|Plants for bees and birds|Plans drawn by hand",
        "menu": "What we do|Services|Gardens and care",
        "cta": "Plan your garden|Book a visit",
        "motif": "fern",
        "opens": 8,
        "fonts": ("oldstyle|geometric|humanist", "humanist|geometric"),
        "hue": (75, 160),
        "dark": 0.15,
    },
    "wood": {
        "names": "Oak|Dovetail|Timber|Chisel|Birch|Walnut|Plane|Heartwood",
        "suffix": "Woodworks|Joinery|Furniture",
        "hero": "Solid wood, oiled by hand|Furniture made to measure|Joints without screws",
        "lead": "Tables, shelves and kitchens made from solid wood in our workshop, finished"
        " with oil and built to be repaired.|We make furniture to measure and restore the old"
        " pieces you cannot replace.",
        "offers": "Dining tables=Oak, walnut or ash, made to your size=from 1400"
        "|Shelving=Built in or free standing, solid wood throughout=from 450"
        "|Kitchen fronts=New doors for the kitchen you already have=from 900"
        "|Restoration=Old furniture repaired and refinished=on request"
        "|Cutting boards=End grain, oiled, from our offcuts=from 45",
        "about": "The workshop opened in {since}. We use timber from local sawmills and dry"
        " it ourselves.|Everything we make can be taken apart and repaired, because good"
        " furniture outlives its first owner.",
        "facts": "Local timber|Oil finishes, no lacquer|Built to be repaired",
        "menu": "What we make|Furniture and repairs|In the workshop",
        "cta": "Ask for a quote|Visit the workshop",
        "motif": "rings",
        "opens": 8,
        "fonts": ("slab|grotesk|oldstyle", "humanist|neo"),
        "hue": (20, 45),
        "dark": 0.3,
    },
    "music": {
        "names": "Octave|Cadence|Tempo|Chord|Sonata|Reed|Allegro|Overture",
        "suffix": "Music School|Music Lessons|Music Studio",
        "hero": "Lessons for every age|Learn the instrument you always wanted|Play with other"
        " people",
        "lead": "Piano, guitar and voice lessons with teachers who perform. The first lesson is"
        " free.|Private lessons and small ensembles for children and adults, beginners and"
        " returners.",
        "offers": "Piano=Weekly lessons, 30 or 45 minutes=from 28 a lesson"
        "|Guitar=Classical, acoustic and electric=from 26 a lesson"
        "|Voice=Breathing, range and repertoire=from 30 a lesson"
        "|Music theory=Reading, harmony and ear training=from 22"
        "|Ensemble=Play together once a week=from 18",
        "about": "The school opened in {since} with one piano and three students. Our"
        " teachers still play concerts, and our students play two of their own each year.|"
        "We teach children from six and adults of any age, including those who stopped years"
        " ago.",
        "facts": "First lesson free|Concerts twice a year|Teachers who perform",
        "menu": "Lessons|What we teach|Courses",
        "cta": "Book a free lesson|Meet the teachers",
        "motif": "notes",
        "opens": 12,
        "fonts": ("didone|geometric|oldstyle", "humanist|neo"),
        "hue": (220, 330),
        "dark": 0.4,
    },
    "tailor": {
        "names": "Thread|Seam|Tweed|Bobbin|Linen|Button|Selvedge|Hemline",
        "suffix": "Tailoring|Tailors|Alterations",
        "hero": "Clothes that fit, kept for years|Alterations by tomorrow|Made to measure,"
        " made to last",
        "lead": "Alterations, repairs and made-to-measure clothes from a small atelier. Most"
        " hems are ready the next day.|We take in, let out, shorten and mend, and we make"
        " suits and dresses from the first fitting.",
        "offers": "Trouser hems=Ready the next day=from 15"
        "|Taking in=Jackets, dresses and shirts fitted to you=from 25"
        "|Repairs=Zips, linings, elbows and invisible mending=from 12"
        "|Made to measure=Suits, coats and dresses, three fittings=from 900"
        "|Wedding wear=Fittings and alterations without a rush=on request",
        "about": "The atelier opened in {since}. We still cut by hand and keep every"
        " customer's measurements on paper.|Good clothes are worth fixing, and we would"
        " rather mend a coat than see it thrown away.",
        "facts": "Hems by the next day|Measurements kept on file|Fabrics you can touch",
        "menu": "Services|Alterations and tailoring|What we do",
        "cta": "Book a fitting|Bring your clothes",
        "motif": "spool",
        "opens": 10,
        "fonts": ("didone|transitional|oldstyle", "transitional|humanist"),
        "hue": (200, 260),
        "dark": 0.35,
    },
    "yoga": {
        "names": "Lotus|Breath|Cedar|Dawn|Balance|Stillness|Tide|Haven",
        "suffix": "Yoga|Yoga Studio|Movement",
        "hero": "Classes for stiff bodies|Breathe, move, rest|Small groups, calm room",
        "lead": "Gentle and dynamic classes in groups of ten or fewer. Mats, blocks and tea are"
        " waiting for you.|A calm room near the park for yoga, breathing and rest, whatever"
        " your age or shape.",
        "offers": "Morning flow=An hour of movement to start the day=14 a class"
        "|Gentle yoga=Slow classes for beginners and stiff backs=12 a class"
        "|Private session=One to one, at the studio or at home=from 55"
        "|Breathing course=Four weeks of simple practices=from 70"
        "|Monthly pass=As many classes as you like=95",
        "about": "We opened the studio in {since} for people who thought yoga was not for"
        " them. Most of our students started with the gentle class.|Classes are small, so the"
        " teacher knows your name and your knees.",
        "facts": "Ten people or fewer|Mats and tea provided|First class free",
        "menu": "Classes|Timetable and passes|What we offer",
        "cta": "Book a class|See the timetable",
        "motif": "sun",
        "opens": 7,
        "fonts": ("rounded|geometric|humanist", "humanist|geometric"),
        "hue": (150, 210),
        "dark": 0.15,
    },
}


SITE_FONTS = {
    "oldstyle": "'Iowan Old Style','Palatino Linotype','URW Palladio L',P052,serif",
    "transitional": "Charter,'Bitstream Charter','Sitka Text',Cambria,serif",
    "didone": "Didot,'Bodoni MT','Noto Serif Display','URW Palladio L',P052,Sylfaen,serif",
    "slab": "Rockwell,'Rockwell Nova','Roboto Slab','DejaVu Serif','Sitka Small',serif",
    "humanist": "Seravek,'Gill Sans Nova',Ubuntu,Calibri,'DejaVu Sans',source-sans-pro,sans-serif",
    "geometric": "Avenir,Montserrat,Corbel,'URW Gothic',source-sans-pro,sans-serif",
    "grotesk": "'Helvetica Neue',Helvetica,'Nimbus Sans',Arial,sans-serif",
    "neo": "Inter,Roboto,'Helvetica Neue','Arial Nova','Nimbus Sans',Arial,sans-serif",
    "industrial": "Bahnschrift,'DIN Alternate','Franklin Gothic Medium','Nimbus Sans Narrow',"
    "sans-serif-condensed,sans-serif",
    "rounded": "ui-rounded,'Hiragino Maru Gothic ProN',Quicksand,Comfortaa,Manjari,"
    "'Arial Rounded MT','Arial Rounded MT Bold',Calibri,source-sans-pro,sans-serif",
}
SITE_PEOPLE = (
    "Anna K.|Ben O.|Clara M.|David R.|Emma L.|Felix B.|Greta S.|Hugo D.|Ines P.|Jonas W."
    "|Lena H.|Marco V.|Nora T.|Oscar F.|Paula G.|Ruben A.|Sofia N.|Theo C.|Vera J.|Yusuf E."
)
SITE_REVIEWS = (
    "Friendly people, honest prices and work done properly. I would not go anywhere else."
    "|They explained everything and finished a day earlier than promised."
    "|I came once out of curiosity and I have been coming back every week since."
    "|Exactly what I hoped for, and they remembered my name the second time."
    "|Careful, quick and kind. My friends now go there too."
    "|Worth the trip across town. The quality speaks for itself."
)
SITE_STREETS = (
    "Mill Lane|Harbour Street|Linden Row|Old Market|Station Road|Willow Walk|Kiln Yard"
    "|Brewery Lane|Garden Court|Bridge Street|Orchard Row|Chapel Yard"
)
SITE_QUESTIONS = (
    "Do I need to book?=Booking helps us plan, but you are welcome to drop by."
    "|Can I pay by card?=Yes, by card or in cash."
    "|Do you sell gift cards?=Yes, for any amount, valid for a year."
    "|How long does an order take?=Usually a few days. We tell you the date when you order."
    "|Is there parking nearby?=There is free parking in the next street."
    "|Do you work with companies?=Yes, write to us and we will send an offer."
)
SITE_SECTION_TITLES = {
    "offers": "What we make|Our work|The menu|Services|Prices",
    "about": "About us|Our story|Who we are|How we work",
    "reviews": "Kind words|What people say|From our customers",
    "faq": "Questions|Good to know|Before you come",
    "visit": "Visit us|Find us|Opening hours|Get in touch",
}


def _site_tokens(rng: SiteRandom, kind: dict) -> dict:
    """Type, spacing and shape of one site."""
    base = rng.choice((16, 17, 18))
    ratio = rng.choice((1.2, 1.25, 1.333))
    heading = rng.choice(kind["fonts"][0].split("|"))
    body = rng.choice(kind["fonts"][1].split("|"))
    shape = rng.choice(("sharp", "soft", "round"))
    radius = {"sharp": (0, 2), "soft": (6, 12), "round": (14, 22)}[shape]
    return {
        "base": base,
        "h1": round(base * ratio**5),
        "h2": round(base * ratio**3),
        "h3": round(base * ratio),
        "lead": round(base * ratio),
        "line": 1.65 if body in ("oldstyle", "transitional") else 1.55,
        "heading": SITE_FONTS[heading],
        "body": SITE_FONTS[body],
        "weight": rng.choice((500, 600, 700)) if heading not in ("didone",) else 400,
        "tracking": "-0.02em" if heading in ("grotesk", "neo", "geometric") else "0",
        "small": radius[0],
        "large": radius[1],
        "pill": shape == "round" and rng.chance(0.6),
        "width": rng.choice((1040, 1120, 1180)),
        "gap": rng.choice((72, 88, 104)),
    }


def site_theme(rng: SiteRandom, kind: dict) -> dict:
    """Colours of one site; text, muted text and links keep a contrast of 4.5:1 or more."""
    low, high = kind["hue"]
    hue = low + rng.below(high - low + 1)
    dark = rng.chance(kind["dark"])
    if dark:
        background = hsl_hex(hue, rng.uniform(0.1, 0.35), rng.uniform(0.07, 0.12))
        text = hsl_hex(hue, rng.uniform(0.05, 0.2), rng.uniform(0.88, 0.95))
    else:
        background = hsl_hex(hue, rng.uniform(0.1, 0.45), rng.uniform(0.96, 0.99))
        text = hsl_hex(hue, rng.uniform(0.1, 0.4), rng.uniform(0.09, 0.18))
    accent_hue = hue + rng.choice((0, 150, 180, 200, 210, 330))
    saturation = rng.uniform(0.45, 0.8)
    lightness = rng.uniform(0.55, 0.68) if dark else rng.uniform(0.3, 0.44)
    accent = hsl_hex(accent_hue, saturation, lightness)
    while contrast(accent, background) < 4.6 and 0.04 < lightness < 0.96:
        lightness += 0.03 if dark else -0.03
        accent = hsl_hex(accent_hue, saturation, lightness)
    share = 0.4
    muted = mix(text, background, share)
    while contrast(muted, background) < 4.6 and share > 0:
        share = round(share - 0.05, 2)
        muted = mix(text, background, share)
    return {
        "dark": dark,
        "background": background,
        "text": text,
        "accent": accent,
        "onAccent": max(
            (background, text, "#ffffff", "#141414"), key=lambda color: contrast(color, accent)
        ),
        "muted": muted,
        "soft": mix(accent, background, rng.uniform(0.78, 0.88)),
        "deep": mix(accent, text, rng.uniform(0.3, 0.45)),
        "band": mix(background, accent, rng.uniform(0.05, 0.09)),
        "surface": mix(background, text, rng.uniform(0.025, 0.05)),
        "border": mix(background, text, rng.uniform(0.12, 0.18)),
    }


def site_spec(seed: int) -> dict:
    """What the site of `seed` is: kind, name and colours (S7 shows them before applying)."""
    text = SiteRandom(seed, "text")
    kind_id = text.choice(sorted(SITE_KINDS))
    kind = SITE_KINDS[kind_id]
    first, second = text.words(kind["names"], 2)
    pattern = text.below(3)
    if pattern == 0:
        title = f"{first} {text.word(kind['suffix'])}"
    elif pattern == 1:
        title = f"{first} & {second}"
    else:
        title = f"{first} {second} {text.word(kind['suffix'])}"
    return {"kind": kind_id, "title": title, "theme": site_theme(SiteRandom(seed, "theme"), kind)}


def _site_motif(name: str, t: dict, rng: SiteRandom) -> str:
    """The illustration of the hero: the most recognisable thing of the trade."""
    a, d, s, p, i = t["accent"], t["deep"], t["soft"], t["surface"], t["text"]
    shapes = {
        "loaf": f'<ellipse cx="120" cy="172" rx="96" ry="12" fill="{s}"/>'
        f'<path d="M26 142C26 82 78 50 120 50s94 32 94 92c0 18-16 24-94 24S26 160 26 142Z"'
        f' fill="{a}"/><path d="M66 96l28 32M102 78l30 38M140 74l28 34" stroke="{p}"'
        ' stroke-width="8" stroke-linecap="round"/>',
        "cup": f'<ellipse cx="112" cy="176" rx="90" ry="12" fill="{s}"/>'
        f'<path d="M48 92h128v36c0 30-24 44-64 44s-64-14-64-44Z" fill="{a}"/>'
        f'<path d="M176 104c30 0 32 40 0 40" fill="none" stroke="{a}" stroke-width="11"/>'
        f'<path d="M86 76c-10-14 10-24 0-40M112 76c-10-14 10-24 0-40M138 76c-10-14 10-24 0-40"'
        f' fill="none" stroke="{d}" stroke-width="6" stroke-linecap="round"/>',
        "bicycle": f'<circle cx="62" cy="134" r="42" fill="none" stroke="{i}" stroke-width="7"/>'
        f'<circle cx="182" cy="134" r="42" fill="none" stroke="{i}" stroke-width="7"/>'
        f'<path d="M62 134l42-54h58l20 54M104 80l24 54 34-54M128 134H62" fill="none"'
        f' stroke="{a}" stroke-width="8" stroke-linejoin="round"/>'
        f'<path d="M92 64h26M162 80l-6-24 18-4" fill="none" stroke="{i}" stroke-width="7"'
        f' stroke-linecap="round"/><circle cx="128" cy="134" r="10" fill="{d}"/>',
        "camera": f'<rect x="30" y="62" width="180" height="116" rx="18" fill="{a}"/>'
        f'<rect x="74" y="40" width="60" height="30" rx="7" fill="{d}"/>'
        f'<circle cx="120" cy="120" r="42" fill="{p}"/><circle cx="120" cy="120" r="27"'
        f' fill="{i}"/><circle cx="109" cy="109" r="8" fill="{p}"/>'
        f'<rect x="168" y="78" width="24" height="13" rx="4" fill="{s}"/>',
        "bubbles": f'<path d="M30 30h112a16 16 0 0 1 16 16v54a16 16 0 0 1-16 16H76l-30 26v-26H30'
        f'a16 16 0 0 1-16-16V46a16 16 0 0 1 16-16Z" fill="{a}"/>'
        f'<path d="M110 84h100a16 16 0 0 1 16 16v54a16 16 0 0 1-16 16h-14v24l-28-24h-58a16 16'
        f' 0 0 1-16-16v-54a16 16 0 0 1 16-16Z" fill="{s}"/>'
        f'<path d="M46 58h80M46 82h56" stroke="{p}" stroke-width="9" stroke-linecap="round"/>'
        f'<path d="M126 114h80M126 138h52" stroke="{d}" stroke-width="9"'
        ' stroke-linecap="round"/>',
        "building": f'<path d="M24 178h192" stroke="{i}" stroke-width="5"/>'
        f'<rect x="54" y="72" width="132" height="106" fill="{p}" stroke="{i}" stroke-width="5"/>'
        f'<path d="M42 78l78-46 78 46" fill="none" stroke="{i}" stroke-width="5"'
        f' stroke-linejoin="round"/><path d="M98 178v-46a22 22 0 0 1 44 0v46" fill="{a}"/>'
        f'<rect x="70" y="92" width="26" height="26" fill="{s}"/>'
        f'<rect x="144" y="92" width="26" height="26" fill="{s}"/>',
        "vase": f'<ellipse cx="120" cy="180" rx="74" ry="10" fill="{s}"/>'
        f'<path d="M94 28h52v14c0 14 34 30 34 78 0 38-24 58-60 58s-60-20-60-58c0-48 34-64'
        f' 34-78Z" fill="{a}"/><path d="M64 106h112M62 128h116" stroke="{p}" stroke-width="7"/>'
        f'<path d="M86 28h68" stroke="{d}" stroke-width="9" stroke-linecap="round"/>',
        "teacup": f'<ellipse cx="106" cy="176" rx="82" ry="10" fill="{s}"/>'
        f'<path d="M36 100h140v12c0 38-28 58-70 58s-70-20-70-58Z" fill="{a}"/>'
        f'<path d="M176 108c28 0 30 34-2 36" fill="none" stroke="{a}" stroke-width="10"/>'
        f'<path d="M146 84c0-38 32-56 68-56 0 36-20 58-56 58Z" fill="{d}"/>'
        f'<path d="M152 80c16-18 34-32 56-44" stroke="{p}" stroke-width="4" fill="none"/>',
        "book": f'<path d="M120 58c-26-16-62-20-94-14v124c32-6 68-2 94 14 26-16 62-20 94-14V44'
        f'c-32-6-68-2-94 14Z" fill="{p}" stroke="{i}" stroke-width="5"'
        f' stroke-linejoin="round"/><path d="M120 58v124" stroke="{i}" stroke-width="5"/>'
        f'<path d="M44 76c24-4 46-2 62 6M44 102c24-4 46-2 62 6M134 82c16-8 38-10 62-6M134 108'
        f'c16-8 38-10 62-6" stroke="{a}" stroke-width="6" fill="none" stroke-linecap="round"/>'
        f'<path d="M154 44v50l13-11 13 11V40" fill="{d}"/>',
        "rings": "".join(
            [f'<ellipse cx="120" cy="104" rx="96" ry="82" fill="{a}"/>']
            + [
                f'<ellipse cx="{120 + rng.below(5) - 2}" cy="{104 + rng.below(5) - 2}"'
                f' rx="{96 - k * 15}" ry="{82 - k * 13}" fill="none"'
                f' stroke="{d if k % 2 else p}" stroke-width="{3 + k % 2}"/>'
                for k in range(1, 6)
            ]
            + [
                f'<path d="M120 104l18-12 6-14 22-10 10-14" stroke="{d}" stroke-width="4"'
                ' fill="none" stroke-linejoin="round"/>'
            ]
        ),
        "notes": "".join(
            f'<path d="M14 {y}h212" stroke="{s}" stroke-width="3"/>'
            for y in (56, 80, 104, 128, 152)
        )
        + f'<ellipse cx="78" cy="150" rx="20" ry="14" transform="rotate(-20 78 150)" fill="{a}"/>'
        f'<ellipse cx="160" cy="126" rx="20" ry="14" transform="rotate(-20 160 126)" fill="{a}"/>'
        f'<path d="M96 146V54l82-22v92" fill="none" stroke="{i}" stroke-width="7"/>'
        f'<path d="M96 70l82-22" stroke="{d}" stroke-width="14"/>',
        "spool": f'<rect x="60" y="34" width="96" height="16" rx="5" fill="{d}"/>'
        f'<rect x="60" y="150" width="96" height="16" rx="5" fill="{d}"/>'
        f'<rect x="72" y="50" width="72" height="100" fill="{a}"/>'
        + "".join(
            f'<path d="M72 {y}h72" stroke="{p}" stroke-width="2" opacity=".6"/>'
            for y in range(60, 150, 12)
        )
        + f'<path d="M166 178L222 26" stroke="{i}" stroke-width="5" stroke-linecap="round"/>'
        f'<path d="M144 112c30 10 34 40 46 52" fill="none" stroke="{a}" stroke-width="3"/>',
        "sun": f'<path d="M58 124a62 62 0 0 1 124 0Z" fill="{a}"/>'
        f'<path d="M14 142c28-12 48 12 78 0s50-12 78 0 46 12 60 0" stroke="{d}" stroke-width="7"'
        f' fill="none" stroke-linecap="round"/><path d="M34 168c28-12 48 12 78 0s50-12 78 0"'
        f' stroke="{s}" stroke-width="7" fill="none" stroke-linecap="round"/>',
    }
    if name == "fern":
        leaves = []
        for k in range(7):
            x, y = 122 + k * 4, 168 - k * 19
            size = 30 - k * 3
            leaves.append(
                f'<ellipse cx="{x - size}" cy="{y}" rx="{size}" ry="{size // 3 + 3}"'
                f' transform="rotate(25 {x - size} {y})" fill="{a if k % 2 else d}"/>'
                f'<ellipse cx="{x + size}" cy="{y - 8}" rx="{size}" ry="{size // 3 + 3}"'
                f' transform="rotate(-25 {x + size} {y - 8})" fill="{d if k % 2 else a}"/>'
            )
        shapes["fern"] = (
            f'<path d="M120 190C120 140 126 92 150 34" stroke="{i}" stroke-width="5"'
            f' fill="none"/>' + "".join(leaves)
        )
    return shapes[name]


SITE_ROLES = (
    "wrap|top|brand|mark|nav|cta|hero|copy|lead|actions|button|ghost|stage|band|tint|head"
    "|grid|card|menu|row|dots|price|note|split|facts|quote|who|avatar|map|hours|faq|foot"
    "|cols|small|centered|flip|prose|inline"
).split("|")


def _site_classes(rng: SiteRandom) -> dict:
    """Random class names: the stylesheets of two sites share no selectors."""
    letters, chars = "abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz0123456789"
    names: dict = {}
    for role in SITE_ROLES:
        name = ""
        while not name or name in names.values():
            name = rng.choice(letters) + "".join(rng.choice(chars) for _ in range(2 + rng.below(5)))
        names[role] = name
    return names


def _site_price(value: str, currency: str) -> str:
    match = re.search(r"\d+(?:\.\d+)?", value)
    if not match:
        return value
    return value[: match.start()] + currency + value[match.start() :]


def _site_offers(rng: SiteRandom, c: dict, offers: list, currency: str) -> str:
    items = [(name, what, _site_price(price, currency)) for name, what, price in offers]
    shape = rng.below(4)
    if shape == 0:  # a menu with dotted leaders
        rows = "".join(
            f'<li class="{c["row"]}"><div><span>{n}</span><i class="{c["dots"]}"></i>'
            f'<b class="{c["price"]}">{p}</b></div><p class="{c["note"]}">{w}</p></li>'
            for n, w, p in items
        )
        return f'<ul class="{c["menu"]}">{rows}</ul>'
    if shape == 1:  # cards
        rows = "".join(
            f'<article class="{c["card"]}"><h3>{n}</h3><p>{w}</p>'
            f'<p class="{c["price"]}">{p}</p></article>'
            for n, w, p in items
        )
        return f'<div class="{c["grid"]}">{rows}</div>'
    if shape == 2:  # a definition list in two columns
        rows = "".join(
            f'<div class="{c["row"]}"><dt>{n}</dt><dd>{w}</dd>'
            f'<dd class="{c["price"]}">{p}</dd></div>'
            for n, w, p in items
        )
        return f'<dl class="{c["menu"]} {c["cols"]}">{rows}</dl>'
    rows = "".join(
        f'<tr><th scope="row">{n}</th><td>{w}</td><td class="{c["price"]}">{p}</td></tr>'
        for n, w, p in items
    )
    return f'<table class="{c["menu"]}"><tbody>{rows}</tbody></table>'


def _site_about(rng: SiteRandom, c: dict, kind: dict, since: int, founder: str) -> str:
    paragraphs = [p.replace("{since}", str(since)) for p in kind["about"].split("|")]
    facts = "".join(f"<li>{fact}</li>" for fact in kind["facts"].split("|"))
    shape = rng.below(3)
    if shape == 0:
        text = "".join(f"<p>{p}</p>" for p in paragraphs)
        return (f'<div class="{c["split"]}"><div>{text}</div>'
                f'<ul class="{c["facts"]}">{facts}</ul></div>')  # fmt: skip
    if shape == 1:
        quote = f'<blockquote class="{c["quote"]}"><p>{paragraphs[1]}</p>'
        quote += f'<footer class="{c["who"]}">{founder}, founder</footer></blockquote>'
        return f'<div class="{c["split"]}"><p>{paragraphs[0]}</p>{quote}</div>'
    text = "".join(f"<p>{p}</p>" for p in paragraphs)
    prose = f'<div class="{c["prose"]}">{text}</div>'
    return prose + f'<ul class="{c["facts"]} {c["inline"]}">{facts}</ul>'


def _site_reviews(rng: SiteRandom, c: dict, people: list) -> str:
    quotes = rng.words(SITE_REVIEWS, len(people))
    since = [2016 + rng.below(9) for _ in people]
    cards = "".join(
        f'<figure class="{c["card"]}"><blockquote><p>{q}</p></blockquote><figcaption>'
        f'<span class="{c["avatar"]}" aria-hidden="true">{who[0]}</span>'
        f'<span>{who}<br><small class="{c["note"]}">customer since {year}</small></span>'
        "</figcaption></figure>"
        for q, who, year in zip(quotes, people, since)
    )
    return f'<div class="{c["grid"]}">{cards}</div>'


def _site_map(rng: SiteRandom, c: dict, t: dict) -> str:
    """A small street plan with a pin: no map service is asked for anything."""
    x1, x2 = 40 + rng.below(40), 150 + rng.below(50)
    y1, y2 = 30 + rng.below(30), 100 + rng.below(30)
    roads = (f"M0 {y1}H260M0 {y2}H260M{x1} 0V170M{x2} 0V170"
             f"M0 {150 - rng.below(40)}L260 {rng.below(50)}")  # fmt: skip
    px, py = (x1 + x2) // 2, (y1 + y2) // 2
    return (
        f'<svg class="{c["map"]}" viewBox="0 0 260 170" role="img" aria-label="Map">'
        f'<rect width="260" height="170" fill="{t["surface"]}"/>'
        f'<path d="{roads}" stroke="{t["border"]}" stroke-width="12" fill="none"/>'
        f'<path d="M{px} {py - 30}c-13 0-23 10-23 23 0 17 23 37 23 37s23-20 23-37c0-13-10-23'
        f'-23-23Z" fill="{t["accent"]}"/><circle cx="{px}" cy="{py - 7}" r="8"'
        f' fill="{t["background"]}"/></svg>'
    )


def _site_visit(rng: SiteRandom, c: dict, t: dict, kind: dict, domain: str) -> str:
    opens = kind["opens"]
    closes = opens + 7 + rng.below(3)
    saturday = rng.choice((f"{opens + 1}:00 to 14:00", f"{opens}:00 to {opens + 5}:00", "closed"))
    sunday = rng.choice(("closed", "closed", "by appointment"))
    days = [("Monday to Friday", f"{opens}:00 to {closes}:00"), ("Saturday", saturday),
            ("Sunday", sunday)]  # fmt: skip
    hours = "".join(f"<dt>{d}</dt><dd>{h}</dd>" for d, h in days)
    street = f"{rng.word(SITE_STREETS)} {3 + rng.below(60)}"
    answer = f'<p class="{c["note"]}">We answer within two working days.</p>'
    address = f"<address><p>{street}</p><p>Write to us: hello at {domain}</p>{answer}</address>"
    block = f'<div><dl class="{c["hours"]}">{hours}</dl>{address}</div>'
    return f'<div class="{c["split"]}">{block}{_site_map(rng, c, t)}</div>'


def _site_faq(rng: SiteRandom, c: dict) -> str:
    pairs = [q.split("=") for q in rng.words(SITE_QUESTIONS, 3 + rng.below(2))]
    return "".join(
        f'<details class="{c["faq"]}"><summary>{q}</summary><p>{a}</p></details>' for q, a in pairs
    )


def _site_top(rng: SiteRandom, c: dict, title: str, links: list, cta: tuple) -> str:
    initial = title[0]
    mark_shape = rng.choice(("circle", "square", "leaf"))
    if mark_shape == "circle":
        shape = '<circle cx="16" cy="16" r="16"/>'
    elif mark_shape == "square":
        shape = '<rect width="32" height="32" rx="7"/>'
    else:
        shape = '<path d="M0 32C0 14 14 0 32 0c0 18-14 32-32 32Z"/>'
    mark = (f'<svg class="{c["mark"]}" viewBox="0 0 32 32" aria-hidden="true">{shape}'
            f'<text x="16" y="21.5" text-anchor="middle">{initial}</text></svg>')  # fmt: skip
    brand = f'<a class="{c["brand"]}" href="/">{mark}<span>{title}</span></a>'
    items = "".join(f'<li><a href="#{ident}">{text}</a></li>' for ident, text in links)
    nav = f'<nav class="{c["nav"]}" aria-label="Main"><ul>{items}</ul></nav>'
    button = ""
    if rng.chance(0.6):
        button = f'<a class="{c["cta"]}" href="#{cta[1]}">{cta[0]}</a>'
    return f'<header class="{c["top"]}">{brand}{nav}{button}</header>'


def _site_hero(rng: SiteRandom, c: dict, page: dict, kind: dict, art: str, headline: str) -> tuple:
    """(class of the hero layout, HTML)."""
    lead = rng.word(kind["lead"])
    primary, secondary = kind["cta"].split("|")
    actions = (f'<p class="{c["actions"]}"><a class="{c["button"]}" href="#{page["visit"]}">'
               f'{primary}</a><a class="{c["ghost"]}" href="#{page["offers"]}">{secondary}</a>'
               "</p>")  # fmt: skip
    copy = f'<div class="{c["copy"]}"><h1>{headline}</h1><p class="{c["lead"]}">{lead}</p>'
    copy += actions + "</div>"
    stage = (f'<div class="{c["stage"]}"><svg viewBox="0 0 240 200" role="img"'
             f' aria-label="{page["title"]}">{art}</svg></div>')  # fmt: skip
    layout = rng.choice(("split", "split", "centered", "band"))
    if layout == "centered":
        return layout, f'<section class="{c["hero"]} {c["centered"]}">{stage}{copy}</section>'
    if layout == "band":
        return layout, f'<section class="{c["hero"]} {c["tint"]}">{copy}{stage}</section>'
    if rng.chance(0.3):
        return "flip", f'<section class="{c["hero"]} {c["flip"]}">{stage}{copy}</section>'
    return layout, f'<section class="{c["hero"]}">{copy}{stage}</section>'


def _site_foot(rng: SiteRandom, c: dict, title: str, tagline: str, since: int, domain: str) -> str:
    about = f'<div><p class="{c["brand"]}">{title}</p><p class="{c["note"]}">{tagline}.</p></div>'
    contact = f"<div><p>hello at {domain}</p><p>Since {since}</p></div>"
    small = f'<p class="{c["small"]}">&copy; {title}</p>'
    columns = f'<div class="{c["cols"]}">{about}{contact}</div>'
    return f'<footer class="{c["foot"]}">{columns}{small}</footer>'


def site_css(c: dict, t: dict, k: dict) -> str:
    """The stylesheet: class names are random, values come from the tokens of the site."""
    button = "999px" if k["pill"] else f"{k['small']}px"
    rules = (
        "*{box-sizing:border-box}",
        f"body{{margin:0;background:{t['background']};color:{t['text']};"
        f"font:{k['base']}px/{k['line']} {k['body']}}}",
        f"h1,h2,h3{{font-family:{k['heading']};font-weight:{k['weight']};"
        f"letter-spacing:{k['tracking']};line-height:1.15;margin:0 0 .5em}}",
        f"h1{{font-size:clamp(2.2rem,4vw + 1rem,{k['h1']}px)}}",
        f"h2{{font-size:clamp(1.6rem,2vw + 1rem,{k['h2']}px)}}",
        f"h3{{font-size:{k['h3']}px}}",
        "p{margin:0 0 1em}",
        f"a{{color:{t['accent']}}}",
        f"a:focus-visible,summary:focus-visible{{outline:2px solid {t['accent']};"
        "outline-offset:3px}",
        f".{c['wrap']}{{max-width:{k['width']}px;margin:0 auto;padding:0 24px}}",
        f".{c['top']}{{display:flex;flex-wrap:wrap;align-items:center;gap:16px 32px;"
        f"padding:22px 0;border-bottom:1px solid {t['border']}}}",
        f".{c['brand']}{{display:flex;align-items:center;gap:10px;font:700 1.15rem"
        f" {k['heading']};color:{t['text']};text-decoration:none;margin:0}}",
        f".{c['mark']}{{width:32px;height:32px;fill:{t['accent']}}}",
        f".{c['mark']} text{{fill:{t['onAccent']};font:700 17px {k['heading']}}}",
        f".{c['nav']}{{margin-left:auto}}",
        f".{c['nav']} ul{{display:flex;flex-wrap:wrap;gap:8px 24px;list-style:none;margin:0;"
        "padding:0}",
        f".{c['nav']} a{{color:{t['text']};text-decoration:none}}",
        f".{c['nav']} a:hover{{color:{t['accent']};text-decoration:underline}}",
        f".{c['cta']}{{border:1.5px solid {t['accent']};color:{t['accent']};padding:8px 16px;"
        f"border-radius:{button};text-decoration:none;font-weight:600}}",
        f".{c['hero']}{{display:grid;grid-template-columns:1.15fr .85fr;gap:48px;"
        f"align-items:center;padding:{k['gap']}px 0}}",
        f".{c['lead']}{{font-size:{k['lead']}px;max-width:34em}}",
        f".{c['actions']}{{display:flex;flex-wrap:wrap;gap:12px 24px;align-items:center;"
        "margin-top:28px}",
        f".{c['button']}{{background:{t['accent']};color:{t['onAccent']};padding:13px 24px;"
        f"border-radius:{button};text-decoration:none;font-weight:600}}",
        f".{c['ghost']}{{color:{t['text']};font-weight:600;text-underline-offset:4px}}",
        f".{c['stage']}{{background:{t['soft']};border-radius:{k['large'] * 2}px;padding:8%;"
        "display:grid;place-items:center}",
        f".{c['stage']} svg{{width:100%;max-width:340px;height:auto}}",
        f".{c['tint']}{{background:{t['band']};border-radius:{k['large']}px;"
        "padding:48px clamp(24px,5vw,56px)}",
        f".{c['band']}{{padding:{round(k['gap'] * 0.55)}px 0;scroll-margin-top:24px}}",
        f".{c['band']}.{c['tint']}{{padding:48px clamp(24px,5vw,56px);margin:24px 0}}",
        f".{c['head']}{{max-width:40em;margin-bottom:32px}}",
        f".{c['grid']}{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));"
        "gap:20px}",
        f".{c['card']}{{background:{t['surface']};border:1px solid {t['border']};"
        f"border-radius:{k['large']}px;padding:24px;margin:0}}",
        f".{c['card']} blockquote{{margin:0}}",
        f".{c['card']} figcaption{{display:flex;gap:12px;align-items:center;margin-top:16px}}",
        f"ul.{c['menu']}{{list-style:none;margin:0;padding:0;max-width:46em}}",
        f"ul.{c['menu']} .{c['row']}{{padding:14px 0;border-bottom:1px solid {t['border']}}}",
        f"ul.{c['menu']} .{c['row']}>div{{display:flex;align-items:baseline;gap:10px;"
        "font-weight:600}",
        f".{c['dots']}{{flex:1;border-bottom:2px dotted {t['border']}}}",
        f".{c['note']}{{color:{t['muted']};margin:.3em 0 0}}",
        f".{c['price']}{{color:{t['accent']};font-weight:700;white-space:nowrap}}",
        f"dl.{c['menu']}{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));"
        "gap:8px 48px;margin:0}",
        f"dl.{c['menu']} .{c['row']}{{padding:16px 0;border-top:1px solid {t['border']}}}",
        f"dl.{c['menu']} dt{{font-weight:700}}",
        f"dl.{c['menu']} dd{{margin:.3em 0 0}}",
        f"table.{c['menu']}{{width:100%;border-collapse:collapse}}",
        f"table.{c['menu']} th,table.{c['menu']} td{{text-align:left;vertical-align:top;"
        f"padding:14px 12px 14px 0;border-bottom:1px solid {t['border']}}}",
        f"table.{c['menu']} td:last-child{{text-align:right}}",
        f".{c['split']}{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));"
        "gap:40px;align-items:start}",
        f".{c['facts']}{{list-style:none;margin:0;padding:0}}",
        f".{c['facts']} li{{position:relative;padding:12px 0 12px 28px;"
        f"border-bottom:1px solid {t['border']}}}",
        f".{c['facts']} li::before{{content:'';position:absolute;left:0;top:1.15em;width:12px;"
        f"height:12px;border-radius:50%;background:{t['accent']}}}",
        f".{c['prose']}{{columns:2 320px;column-gap:48px;max-width:60em}}",
        f".{c['prose']} p{{break-inside:avoid}}",
        f".{c['facts']}.{c['inline']}{{display:flex;flex-wrap:wrap;gap:0 40px;margin-top:16px}}",
        f".{c['facts']}.{c['inline']} li{{border-bottom:0}}",
        f".{c['quote']}{{margin:0;padding:28px;border-left:4px solid {t['accent']};"
        f"background:{t['surface']};font-size:{k['lead']}px}}",
        f".{c['who']}{{color:{t['muted']};font-size:{k['base']}px}}",
        f".{c['avatar']}{{display:inline-grid;place-items:center;width:42px;height:42px;"
        f"border-radius:50%;background:{t['accent']};color:{t['onAccent']};font-weight:700}}",
        f".{c['hours']}{{display:grid;grid-template-columns:auto 1fr;gap:8px 24px;"
        "margin:0 0 24px}",
        f".{c['hours']} dd{{margin:0}}",
        "address{font-style:normal}",
        f".{c['map']}{{width:100%;height:auto;border-radius:{k['large']}px;"
        f"border:1px solid {t['border']}}}",
        f".{c['faq']}{{border-bottom:1px solid {t['border']};padding:16px 0;max-width:46em}}",
        f".{c['faq']} summary{{cursor:pointer;font-weight:600}}",
        f".{c['faq']} p{{margin:.6em 0 0;color:{t['muted']}}}",
        f".{c['foot']}{{border-top:1px solid {t['border']};padding:40px 0 32px;margin-top:24px}}",
        f".{c['cols']}{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));"
        "gap:24px}",
        f".{c['small']}{{color:{t['muted']};font-size:.875rem;margin-top:24px}}",
        f".{c['hero']}.{c['tint']}{{padding:56px clamp(24px,5vw,56px);margin-top:32px}}",
        f".{c['hero']}.{c['centered']}{{grid-template-columns:1fr;text-align:center;"
        "justify-items:center}",
        f".{c['centered']} .{c['stage']}{{max-width:300px;width:100%}}",
        f".{c['centered']} .{c['lead']}{{margin:0 auto}}",
        f".{c['centered']} .{c['actions']}{{justify-content:center}}",
        f".{c['hero']}.{c['flip']}{{grid-template-columns:.85fr 1.15fr}}",
        "@media (max-width:760px){"
        f".{c['hero']}{{grid-template-columns:1fr}}.{c['nav']}{{margin-left:0;width:100%}}"
        "}",
    )
    return "".join(rules)


def _site_icon(accent: str, shape: str) -> str:
    """An inline icon in the accent colour: browsers do not ask for /favicon.ico."""
    return (
        "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E"
        f"{shape} fill='%23{accent[1:]}'/%3E%3C/svg%3E"
    )


def site_html(seed: int, domain: str) -> str:
    """The stub site of `seed`: a small business with its own name, texts, colours and layout."""
    spec = site_spec(seed)
    kind, t = SITE_KINDS[spec["kind"]], spec["theme"]
    rng = SiteRandom(seed, "layout")
    c = _site_classes(rng)
    k = _site_tokens(rng, kind)
    title, domain = html.escape(spec["title"]), html.escape(domain)
    currency = rng.choice(("€", "€", "£", "$"))
    since = 2004 + rng.below(18)
    people = rng.words(SITE_PEOPLE, 4)
    ids = {
        "offers": rng.word("menu|work|services|prices|offer"),
        "about": rng.word("about|story|us|studio"),
        "reviews": rng.word("reviews|kind-words|customers"),
        "faq": rng.word("faq|questions|good-to-know"),
        "visit": rng.word("visit|contact|find-us|hours"),
    }
    titles = {name: rng.word(SITE_SECTION_TITLES[name]) for name in ids}
    titles["offers"] = rng.word(kind["menu"])
    offers = [item.split("=") for item in rng.words(kind["offers"], 4 + rng.below(2))]
    middle = ["about", "reviews"] + (["faq"] if rng.chance(0.6) else [])
    middle = rng.shuffled(middle)
    order = ["offers", *middle] if rng.chance(0.75) else [middle[0], "offers", *middle[1:]]
    order.append("visit")
    content = {
        "offers": lambda: _site_offers(rng, c, offers, currency),
        "about": lambda: _site_about(rng, c, kind, since, people[0]),
        "reviews": lambda: _site_reviews(rng, c, people[1 : 3 + rng.below(2)]),
        "faq": lambda: _site_faq(rng, c),
        "visit": lambda: _site_visit(rng, c, t, kind, domain),
    }
    sections = []
    for name in order:
        tint = f" {c['tint']}" if name != "visit" and rng.chance(0.3) else ""
        sections.append(
            f'<section id="{ids[name]}" class="{c["band"]}{tint}"><div class="{c["head"]}">'
            f"<h2>{titles[name]}</h2></div>{content[name]()}</section>"
        )
    links = [(ids[name], titles[name]) for name in order if name != "faq"][:4]
    top = _site_top(rng, c, spec["title"], links, (kind["cta"].split("|")[0], ids["visit"]))
    art = _site_motif(kind["motif"], t, rng)
    headline = rng.word(kind["hero"])
    layout, hero = _site_hero(rng, c, {"title": title, **ids}, kind, art, headline)
    lines = kind["hero"].split("|")
    tagline = lines[(lines.index(headline) + 1 + rng.below(len(lines) - 1)) % len(lines)]
    foot = _site_foot(rng, c, title, tagline, since, domain)
    icon = _site_icon(t["accent"], rng.choice(("%3Crect width='16' height='16' rx='4'",
                                               "%3Ccircle cx='8' cy='8' r='8'")))  # fmt: skip
    head = (
        f'<meta charset="utf-8"><title>{title}</title>'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta name="description" content="{rng.word(kind["lead"])}">'
        f'<meta name="theme-color" content="{t["background"]}">'
        f'<link rel="icon" href="{icon}"><style>{site_css(c, t, k)}</style>'
    )
    body = f'<div class="{c["wrap"]}">{top}<main>{hero}{"".join(sections)}</main>{foot}</div>'
    return f'<!doctype html>\n<html lang="en"><head>{head}</head><body>{body}</body></html>\n'


def nginx_site(domain: str, with_tls: bool, names: tuple = ()) -> str:
    """`names`: of certificates renewed through KERBEROS's webroot (§10.4, K16); the CA asks
    for them on :80 too, so this block answers them with the webroot and the redirect."""
    acme = (
        "server {\n"
        "    listen 80;\n"
        "    listen [::]:80;\n"
        f"    server_name {' '.join([domain, *names])};\n"
        f"    location /.well-known/acme-challenge/ {{ root {ACME_ROOT}; }}\n"
        "    location / { return 301 https://$host$request_uri; }\n"
        "}\n"
    )
    if not with_tls:
        return acme
    return acme + (
        "server {\n"
        "    listen 127.0.0.1:8445 ssl http2;\n"
        f"    server_name {domain};\n"
        f"    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;\n"
        f"    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;\n"
        "    ssl_protocols TLSv1.2 TLSv1.3;\n"
        f"    root {SITE_ROOT};\n"
        "    index index.html;\n"
        "    location / { try_files $uri $uri/ =404; }\n"
        "}\n"
    )


def domain_param(params: dict) -> str:
    domain = str(params.get("domain", "")).lower().rstrip(".")
    if not DOMAIN.match(domain):
        raise AgentError("bad_params", "domain")
    return domain


# -- certificates that renew by listening on :80 themselves (§10.4, K16) --------
# acme.sh and certbot in standalone mode open :80 for each renewal and give up when
# it is taken. Once nginx of self-steal holds it, they renew through its webroot.
ACME_HOME = "/root/.acme.sh"
CERTBOT_RENEWAL = "/etc/letsencrypt/renewal"
CERTBOT_CLI = "/etc/letsencrypt/cli.ini"
CERTBOT_PRE_HOOKS = "/etc/letsencrypt/renewal-hooks/pre"
CHALLENGES = f"{ACME_ROOT}/.well-known/acme-challenge"
PROBE_NAME = "kerberos-check"
PROBE = f"{CHALLENGES}/{PROBE_NAME}"
ACME_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
ACME_B64 = re.compile(r"^__ACME_BASE64__START_(.*)__ACME_BASE64__END_$", re.S)
STANDALONE = "no"  # acme.sh writes this into Le_Webroot for --standalone
STOP_WORD = re.compile(r"\b(stop|kill|killall|pkill|quit)\b", re.I)
# Keys of cli.ini that choose how every certbot renewal proves its names: they beat
# the renewal files, so a moved file would change nothing.
CERTBOT_METHOD_KEYS = frozenset({"authenticator", "standalone", "webroot", "webroot-path"})


def acme_value(raw: str) -> str:
    """A value of an acme.sh domain conf: quoted; hooks are base64 between markers."""
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        raw = raw[1:-1]
    match = ACME_B64.match(raw)
    if match:
        try:
            return base64.b64decode(match.group(1)).decode("utf-8", "replace")
        except ValueError:
            return ""
    return raw


def acme_conf(text: str) -> dict:
    values = {}
    for line in text.splitlines():
        match = ACME_KEY.match(line.strip())
        if match:
            values[match.group(1)] = acme_value(match.group(2))
    return values


def acme_domains(values: dict) -> list:
    names = [values.get("Le_Domain") or ""]
    alt = values.get("Le_Alt") or ""
    if alt and alt != STANDALONE:  # acme.sh writes «no» for «no other names» too
        names += alt.split(",")
    return [n.strip() for n in names if n.strip()]


def acme_roots(values: dict, count: int) -> list:
    """`Le_Webroot` of each domain: past the end of the list acme.sh takes the last one."""
    roots = [r.strip() for r in (values.get("Le_Webroot") or "").split(",")]
    return [roots[min(i, len(roots) - 1)] for i in range(count)]


HOOK_SPLIT = re.compile(r"\n|;|&&|\|\|")


def hook_commands(hooks: list) -> list:
    """The commands of hooks, one by one and without comments: «nginx» in a comment, or in
    another command than the stop, frees nothing (K17)."""
    commands = []
    for hook in hooks:
        for command in HOOK_SPLIT.split(hook or ""):
            command = command.split("#", 1)[0].strip()
            if command:
                commands.append(command)
    return commands


def kills_port80(command: str) -> bool:
    """`fuser -k 80/tcp`: kills whatever holds the port, nginx included."""
    low = command.lower()
    return "fuser" in low and "80/tcp" in low and re.search(r"\s-\w*k", low) is not None


def stops_nginx(hooks: list) -> bool:
    """A hook command that stops nginx before a renewal: standalone then gets :80 by itself
    and keeps working. A reload or a test of nginx frees nothing."""
    return any(("nginx" in c.lower() and STOP_WORD.search(c)) or kills_port80(c)
               for c in hook_commands(hooks))  # fmt: skip


def frees_port(hooks: list) -> bool:
    """A hook command that stops or kills anything before a renewal: whoever set it up looks
    after port 80 for that renewal (`acme.port80` leaves it alone)."""
    return any(STOP_WORD.search(c) or kills_port80(c) for c in hook_commands(hooks))


def conf_key(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped[0] in "#[":
        return ""
    key, sep, _ = stripped.partition("=")
    return key.strip() if sep else ""


def conf_value(line: str) -> str:
    return line.partition("=")[2].strip().strip("'\"")


def certbot_lines(text: str) -> list:
    """(section, line) of a certbot renewal conf (configobj): '' on top, 'params' in
    [renewalparams], 'map' in its [[webroot_map]], 'other' elsewhere."""
    section = ""
    result = []
    for line in text.splitlines(keepends=True):
        stripped = line.strip().replace(" ", "")
        if stripped.startswith("[["):
            section = "map" if stripped == "[[webroot_map]]" else "other"
        elif stripped.startswith("["):
            section = "params" if stripped == "[renewalparams]" else "other"
        result.append((section, line))
    return result


def certbot_conf(text: str) -> tuple:
    """(top-level keys, [renewalparams] keys) of a certbot renewal conf."""
    top: dict = {}
    params: dict = {}
    for section, line in certbot_lines(text):
        key = conf_key(line)
        if key and section == "":
            top[key] = conf_value(line)
        elif key and section == "params":
            params[key] = conf_value(line)
    return top, params


def certbot_global(system: System) -> tuple:
    """(the pre-hooks certbot runs before every renewal, whether cli.ini sets the method).
    Like certbot, only executable files of renewal-hooks/pre count, backups ending in «~» not."""
    hooks = []
    folder = system.path(CERTBOT_PRE_HOOKS)
    for entry in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        full = os.path.join(folder, entry)
        if entry.endswith("~") or not os.path.isfile(full) or not os.access(full, os.X_OK):
            continue
        hooks.append(system.read(f"{CERTBOT_PRE_HOOKS}/{entry}") or "")
    keys = {}
    for line in (system.read(CERTBOT_CLI) or "").splitlines():
        stripped = line.strip()
        if stripped and stripped[0] not in "#;[":
            key, _, value = stripped.partition("=")
            keys[key.strip().lower().replace("_", "-")] = value.strip()
    hooks.append(keys.get("pre-hook", ""))
    return hooks, bool(CERTBOT_METHOD_KEYS & set(keys))


def our_webroot(path: Optional[str]) -> bool:
    return (path or "").strip().rstrip(", ") == ACME_ROOT


def cert_names(path: str) -> list:
    try:
        import _ssl

        decoded = _ssl._test_decode_cert(path)  # noqa: SLF001 - stdlib has no public decoder
    except Exception:  # noqa: BLE001 - unreadable: no names
        return []
    return [str(value).strip() for kind, value in decoded.get("subjectAltName", ())
            if kind in ("DNS", "IP Address")]  # fmt: skip


def renewal_name(name: str) -> Optional[str]:
    """The name as nginx and the CA see it (IDN in punycode), or None for what nginx
    cannot answer for, such as an IPv6 zone index."""
    name = name.strip().rstrip(".")
    if "%" in name:
        return None
    try:
        return ipaddress.ip_address(name).compressed
    except ValueError:
        pass
    try:
        name = name.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    return name if DOMAIN.match(name) else None


def to_move(item: dict) -> dict:
    """«move», or «blocked» when nginx could not answer for one of its names."""
    names = [renewal_name(n) for n in item["names"]]
    if None in names:
        return {**item, "state": "blocked", "reason": "name"}
    return {**item, "names": names, "state": "move"}


def renewals(system: System) -> list:
    """Certificates renewed through port 80 of this server, each with its `state`: «move»
    (it opens :80 itself and self_steal.site moves it), «moved» (on KERBEROS's webroot
    already) or «blocked» (KERBEROS cannot move it: `reason`). Renewals whose hook stops
    nginx first get :80 by themselves and are left out."""
    found = []
    home = system.path(ACME_HOME)
    for entry in sorted(os.listdir(home)) if os.path.isdir(home) else []:
        main = entry[: -len("_ecc")] if entry.endswith("_ecc") else entry
        path = f"{ACME_HOME}/{entry}/{main}.conf"
        text = system.read(path)
        if text is None:
            continue
        values = acme_conf(text)
        domains = acme_domains(values)
        if not domains or domains[0] != main:
            continue
        pairs = list(zip(domains, acme_roots(values, len(domains))))
        item = {"tool": "acme.sh", "name": main, "path": path,
                "cert": f"{ACME_HOME}/{entry}/{main}.cer"}  # fmt: skip
        standalone = [d for d, root in pairs if root == STANDALONE]
        kept = [d for d, root in pairs if our_webroot(root)]
        on80 = values.get("Le_HTTPPort", "").strip() in ("", "80")
        own = [values.get("Le_PreHook", "")]
        if standalone and on80 and not stops_nginx(own):
            found.append(to_move({**item, "names": standalone, "freesPort": frees_port(own)}))
        elif kept:
            found.append({**item, "names": kept, "state": "moved"})
    hooks, cli_method = certbot_global(system)
    folder = system.path(CERTBOT_RENEWAL)
    for entry in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        path = f"{CERTBOT_RENEWAL}/{entry}"
        text = system.read(path) if entry.endswith(".conf") else None
        if text is None:
            continue
        top, params = certbot_conf(text)
        names = cert_names(system.path(top["cert"])) if top.get("cert") else []
        if not names:
            continue
        item = {"tool": "certbot", "name": entry[: -len(".conf")], "path": path,
                "names": names, "cert": top["cert"]}  # fmt: skip
        method = params.get("authenticator")
        on80 = params.get("http01_port", "").strip() in ("", "80")
        effective = [params.get("pre_hook", ""), *hooks]  # its own hook and certbot's global
        if method == "standalone" and on80 and not stops_nginx(effective):
            item["freesPort"] = frees_port(effective)
            if cli_method:  # cli.ini picks the method of every renewal: a moved file would not
                found.append({**item, "state": "blocked", "reason": "cli.ini"})
            else:
                found.append(to_move(item))
        elif method == "webroot" and our_webroot(params.get("webroot_path")):
            found.append({**item, "state": "moved"})
    return found


def set_acme_key(text: str, key: str, value: str) -> str:
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        match = ACME_KEY.match(line.strip())
        if match and match.group(1) == key:
            lines[i] = f"{key}='{value}'\n"
            return "".join(lines)
    return (
        "".join(lines)
        + ("" if not lines or lines[-1].endswith("\n") else "\n")
        + (f"{key}='{value}'\n")
    )


def certbot_move(text: str) -> tuple:
    """(the conf with `authenticator = webroot` and KERBEROS's `webroot_path`, the entries
    of [[webroot_map]] it pointed at KERBEROS's webroot too: they beat `webroot_path`)."""
    lines = certbot_lines(text)
    has_path = any(s == "params" and conf_key(line) == "webroot_path" for s, line in lines)
    out = []
    old_map = {}
    for section, line in lines:
        key = conf_key(line)
        if section == "params" and key == "authenticator":
            out.append("authenticator = webroot\n")
            if not has_path:
                out.append(f"webroot_path = {ACME_ROOT},\n")
        elif section == "params" and key == "webroot_path":
            out.append(f"webroot_path = {ACME_ROOT},\n")
        elif section == "map" and key:
            old_map[key] = conf_value(line)
            out.append(f"{key} = {ACME_ROOT}\n")
        else:
            out.append(line)
    return "".join(out), old_map


def certbot_back(text: str, before: dict) -> Optional[str]:
    """Standalone again, with the old `webroot_path` and map entries; None when the method
    is no longer KERBEROS's webroot. Map entries certbot itself wrote for the webroot after
    a renewal go."""
    lines = certbot_lines(text)
    _top, params = certbot_conf(text)
    if params.get("authenticator") != "webroot" or not our_webroot(params.get("webroot_path")):
        return None
    old_path = before.get("webroot_path")
    old_map = before.get("webroot_map") or {}
    out = []
    for section, line in lines:
        key = conf_key(line)
        if section == "params" and key == "authenticator":
            out.append("authenticator = standalone\n")
        elif section == "params" and key == "webroot_path":
            if old_path is not None:
                out.append(f"webroot_path = {old_path}\n")
        elif section == "map" and key and our_webroot(conf_value(line)):
            if key in old_map:
                out.append(f"{key} = {old_map[key]}\n")
        else:
            out.append(line)
    result = []
    for i, line in enumerate(out):
        if line.strip().replace(" ", "") == "[[webroot_map]]":
            rest = [r for r in out[i + 1 :] if r.strip() and not r.strip().startswith("#")]
            if not rest or rest[0].strip().startswith("["):
                continue  # nothing left in the map
        result.append(line)
    return "".join(result)


def move_renewals(system: System, record: dict, moves: list) -> None:
    """Once nginx answers every name with a probe from the webroot, asked at a public
    address of the server the way a CA asks, the renewals move there; each move is in
    the record before its file. Who reaches :80 from outside does not change: these
    renewals were answered on this port before, by their own listener."""
    v4, _v6 = parse_ip_addr(system.run(["ip", "-j", "addr", "show"]).stdout)
    address = v4[0] if v4 else "127.0.0.1"
    content = base64.b32encode(os.urandom(15)).decode().lower()
    system.write(PROBE, content + "\n", 0o644)
    try:
        for name in dict.fromkeys(n for move in moves for n in move["names"]):
            try:
                status, body = system.http(
                    address, name, f"/.well-known/acme-challenge/{PROBE_NAME}"
                )
            except OSError:
                status, body = 0, ""
            if status != 200 or body.strip() != content:
                raise AgentError("acme_check_failed", name)
    finally:
        if system.exists(PROBE):
            os.remove(system.path(PROBE))
    for move in moves:
        text = system.read(move["path"])
        if text is None:
            raise AgentError("acme_check_failed", move["path"])
        if move["tool"] == "acme.sh":
            before: Any = acme_conf(text).get("Le_Webroot", "")
            after = ",".join(ACME_ROOT if r.strip() == STANDALONE else r.strip()
                             for r in before.split(","))  # fmt: skip
            new = set_acme_key(text, "Le_Webroot", after)
        else:
            new, old_map = certbot_move(text)
            before = {"webroot_path": certbot_conf(text)[1].get("webroot_path"),
                      "webroot_map": old_map}  # fmt: skip
            after = f"{ACME_ROOT},"
        record.setdefault("renewals", []).append(
            {"path": move["path"], "tool": move["tool"], "before": before, "after": after}
        )
        save_record(system, record)
        system.write(move["path"], new, mode_of(system, move["path"]) or 0o644)


def revert_renewals(system: System, record: dict) -> None:
    """Only the method of renewal goes back, not the bytes: acme.sh and certbot rewrite
    these files at every renewal. A method changed after KERBEROS stays (§10.4)."""
    left = []
    for edit in reversed(record.get("renewals") or []):
        text = system.read(edit["path"])
        if text is None:
            continue
        if edit["tool"] == "acme.sh":
            now = acme_conf(text).get("Le_Webroot", "")
            if now == edit["before"]:
                continue  # the move never reached the file
            new = set_acme_key(text, "Le_Webroot", edit["before"]) if now == edit["after"] else None
        else:
            if certbot_conf(text)[1].get("authenticator") == "standalone":
                continue
            new = certbot_back(text, edit["before"])
        if new is None:
            left.append(edit["path"])
            continue
        system.write(edit["path"], new, mode_of(system, edit["path"]) or 0o644)
    if left:
        record.setdefault("details", {})["renewalsLeft"] = left


@fix("self_steal.site")
def fix_site(system: System, params: dict) -> Plan:
    domain = domain_param(params)
    seed = params.get("siteSeed", 0)
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < SITE_SEEDS:
        raise AgentError("bad_params", "siteSeed")
    on80 = [s for s in parse_ss_listen(system.run(["ss", "-Hlntup"]).stdout)
            if s["port"] == 80 and s["proto"] == "tcp"]  # fmt: skip
    nginx_enabled, nginx_active = service_state(system, "nginx")
    # A process called nginx is nginx.service only while that runs: a container with
    # host networking may hold :80 under the same name.
    if any(s["process"] != "nginx" or not nginx_active for s in on80):
        raise AgentError("port80_busy", ", ".join(s["process"] or "?" for s in on80))
    hooks, _cli_method = certbot_global(system)
    if stops_nginx(hooks):  # the domain's own renewal goes through nginx: it would never pass
        raise AgentError("certbot_hook", "a certbot pre-hook of every renewal stops nginx")
    found = renewals(system)
    blocked = [r for r in found if r["state"] == "blocked"]
    if blocked:  # self-steal would leave it without a way to renew
        raise AgentError("acme_standalone", f"{blocked[0]['name']}: {blocked[0]['reason']}")
    moves = [r for r in found if r["state"] == "move"]
    names: list = []
    for item in found:
        for name in filter(None, map(renewal_name, item["names"])):
            if name != domain and name not in names:
                names.append(name)
    served = tuple(f"[{n}]" if ":" in n else n for n in names)
    had_nginx = system.exists("/usr/sbin/nginx")
    plan = Plan("self_steal.site")
    if needs_package(system, "nginx", "/usr/sbin/nginx"):
        plan.packages.append("nginx")
    if needs_package(system, "certbot", "/usr/bin/certbot"):
        plan.packages.append("certbot")
    page = site_html(seed, domain)
    plan.step_write(f"{ACME_ROOT}/.kerberos", "acme webroot of KERBEROS\n")
    plan.step_write(SITE_CONF, nginx_site(domain, with_tls=False, names=served))
    plan.step_run(["nginx", "-t"], "nginx_test_failed")
    plan.step_run(["systemctl", "enable", "nginx"])
    plan.step_run(["systemctl", "reload-or-restart", "nginx"])
    plan.step_run(["certbot", "certonly", "--webroot", "-w", ACME_ROOT, "-d", domain,
                   "--register-unsafely-without-email", "--agree-tos", "--non-interactive",
                   "--keep-until-expiring"], "certbot_failed", timeout=300)  # fmt: skip
    plan.step_write(f"{SITE_ROOT}/index.html", page)
    plan.step_write(SITE_CONF, nginx_site(domain, with_tls=True, names=served))
    # Renewal reloads nginx only: Xray rereads certificates itself every hour.
    plan.step_write(RENEW_HOOK, "#!/bin/sh\nsystemctl reload nginx\n", 0o755)
    plan.step_run(["nginx", "-t"], "nginx_test_failed")
    plan.step_run(["systemctl", "reload", "nginx"])
    if had_nginx:
        # A stopped nginx stays stopped: it would serve the person's old sites again.
        plan.undo_after += service_back("nginx", nginx_enabled, nginx_active, "reload-or-restart")
    else:
        plan.undo_after += [["systemctl", "reload-or-restart", "nginx"],
                            ["systemctl", "disable", "--now", "nginx"]]  # fmt: skip
    # Last: nginx answers for their names only once the final config is loaded.
    plan.moves = moves
    if moves:
        plan.created.append(PROBE)  # an interrupted apply takes the probe away too
    spec = site_spec(seed)
    plan.details = {"domain": domain, "template": template_hash(page), "siteSeed": seed,
                    "site": {"title": spec["title"], "kind": spec["kind"],
                             "background": spec["theme"]["background"],
                             "accent": spec["theme"]["accent"]},
                    "renewals": [{"tool": m["tool"], "name": m["name"], "names": m["names"]}
                                 for m in moves]}  # fmt: skip
    return plan


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip())


def service_block(lines: list, service: str) -> tuple:
    """(first line, end, indentation of the keys) of one service of a compose file."""
    start = next((i for i, line in enumerate(lines)
                  if re.match(rf"^(\s+){re.escape(service)}:\s*$", line)), None)  # fmt: skip
    if start is None:
        raise AgentError("bad_params", f"service {service} not in the compose file")
    indent = indent_of(lines[start])
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip()
                and not lines[i].strip().startswith("#") and indent_of(lines[i]) <= indent),
               len(lines))  # fmt: skip
    child = next((indent_of(lines[i]) for i in range(start + 1, end) if lines[i].strip()),
                 indent + 2)  # fmt: skip
    return start, end, child


def is_item(stripped: str) -> bool:
    return stripped == "-" or stripped.startswith("- ")


def volumes_list(lines: list, key: int, end: int, child: int) -> tuple:
    """(last line of the list under `volumes:`, indentation of its items or None). Items
    may sit deeper than the key or at the key's own indentation; both are YAML."""
    last, items = key, None
    for i in range(key + 1, end):
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("#"):
            continue
        if indent_of(lines[i]) < child or (indent_of(lines[i]) == child and not is_item(stripped)):
            break  # the next key of the service: the volumes list is over
        if items is None and is_item(stripped):
            items = indent_of(lines[i])
        last = i
    return last, items


def add_volume(text: str, service: str, volume: str) -> str:
    """Add a volume to one service of a compose file, keeping its indentation."""
    lines = text.splitlines()
    start, end, child = service_block(lines, service)
    key = next((i for i in range(start + 1, end)
                if re.match(rf"^\s{{{child}}}volumes:\s*$", lines[i])), None)  # fmt: skip
    if key is None:
        insert = [f"{' ' * child}volumes:", f"{' ' * (child + 2)}- {volume}"]
        return "\n".join(lines[:end] + insert + lines[end:]) + "\n"
    last, items = volumes_list(lines, key, end, child)
    item = f"{' ' * (child + 2 if items is None else items)}- {volume}"
    return "\n".join(lines[: last + 1] + [item] + lines[last + 1 :]) + "\n"


def compose_mounts(text: str, service: str, target: str) -> bool:
    """The service's volumes already name `target` inside the container (short or long form)."""
    lines = text.splitlines()
    start, end, child = service_block(lines, service)
    for i in range(start + 1, end):
        stripped = lines[i].strip().lstrip("-").strip().strip("'\"")
        long_form = re.match(r"^target:\s*['\"]?([^'\"\s]+)", stripped)
        if long_form and long_form.group(1).rstrip("/") == target:
            return True
        parts = stripped.split(":")
        if len(parts) >= 2 and parts[0].startswith(("/", ".", "~", "$")):
            if parts[1].strip().rstrip("/") == target:
                return True
    return False


@fix("node.letsencrypt_mount")
def fix_mount(system: System, params: dict) -> Plan:
    """Decided by the container, not by the text: the file may name /etc/letsencrypt in a
    comment, for another path, or in an edit that never reached the container."""
    text = system.read(COMPOSE_FILE)
    if text is None:
        raise AgentError("bad_params", f"no {COMPOSE_FILE}")
    plan = Plan("node.letsencrypt_mount")
    if parse_remnanode(system.run(["docker", "inspect", "remnanode"]).stdout)["letsencryptMounted"]:
        return plan
    if not compose_mounts(text, "remnanode", "/etc/letsencrypt"):
        plan.write(COMPOSE_FILE, add_volume(text, "remnanode", LETSENCRYPT_VOLUME), private=True)
    plan.run(["docker", "compose", "-f", COMPOSE_FILE, "up", "-d"])
    plan.undo_after.append(["docker", "compose", "-f", COMPOSE_FILE, "up", "-d"])
    return plan


# -- CDN origin and the watch (§10.6, §10.3) -----------------------------------
EDGES_CONF = "/etc/nginx/conf.d/kerberos-edges.conf"
EDGE_SNIPPET = "error_page 418 = @kerberos_not_edge; if ($from_cdn_edge = 0) { return 418; }"
NOT_EDGE = "location @kerberos_not_edge { return 404; }"
WATCH_BIN = "/usr/local/sbin/kerberos-watch"
WATCH_CRON = "/etc/cron.d/kerberos-watch"
WATCH_ROTATE = "/etc/logrotate.d/kerberos-watch"
WATCH_LOG = "/var/log/kerberos-watch.log"

# The watch counts with the agent's own code: one file to keep up to date.
WATCH_SCRIPT = """#!/usr/bin/env python3
# KERBEROS watch (tech.md section 10.3): one line of block signs every 5 minutes.
# Counts and /16 nets only: no client addresses, users or e-mails.
import importlib.machinery
import importlib.util

LOADER = importlib.machinery.SourceFileLoader("kerberos_agent", "__AGENT__")
SPEC = importlib.util.spec_from_loader("kerberos_agent", LOADER)
AGENT = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(AGENT)
WATCH = AGENT.collect_watch(AGENT.System())
V4, V6, XRAY = WATCH["v4"], WATCH["v6"], WATCH["xray"]
NETS = ",".join("%s:%s" % (n["net"], n["count"]) for n in V4["cutNets"] + V6["cutNets"])
LINE = "%s port=%s conn=%d ips=%d cut=%d nets=%s stall=%d users5m=%s req5m=%s\\n" % (
    WATCH["at"],
    ",".join(str(p) for p in WATCH["ports"]) or "-",
    V4["connections"] + V6["connections"],
    V4["clientIps"] + V6["clientIps"],
    V4["cut"] + V6["cut"],
    NETS or "-",
    V4["stalled"] + V6["stalled"],
    XRAY["users5m"],
    XRAY["accepted5m"],
)
with open("__LOG__", "a") as log:
    log.write(LINE)
""".replace("__AGENT__", AGENT_PATH).replace("__LOG__", WATCH_LOG)


def location_open(text: str, path: str) -> Optional[tuple]:
    """(line index, position after its `{`) of `location <path>` (plain, = or ^~)."""
    pattern = re.compile(rf"^\s*location\s+(?:=\s*|\^~\s*)?{re.escape(path)}/?\s*\{{")
    for index, line in enumerate(text.splitlines()):
        match = pattern.match(line)
        if match:
            return index, match.end()
    return None


def location_line(text: str, path: str) -> Optional[int]:
    found = location_open(text, path)
    return None if found is None else found[0]


def guard_location(text: str, path: str) -> str:
    """First thing in the location: anyone but the edges gets the answer of a missing page.
    Right after the `{`: a location on one line keeps the guard inside, not at server level."""
    found = location_open(text, path)
    if found is None:
        return text
    index, after = found
    lines = text.splitlines()
    rest = lines[index][after:]
    if rest.strip() and not rest.strip().startswith("#"):
        if rest.lstrip().startswith(EDGE_SNIPPET):
            return text
        lines[index] = lines[index][:after] + " " + EDGE_SNIPPET + rest
        return "\n".join(lines) + "\n"
    if index + 1 < len(lines) and EDGE_SNIPPET in lines[index + 1]:
        return text
    indent = re.match(r"^\s*", lines[index]).group(0)
    guarded = lines[: index + 1] + [indent + "    " + EDGE_SNIPPET] + lines[index + 1 :]
    return "\n".join(guarded) + "\n"


def add_not_edge(text: str, path: str) -> str:
    """The named location next to the tunnel's, inside the same server block."""
    if re.search(r"location\s+@kerberos_not_edge\b", text):
        return text
    lines = text.splitlines()
    index = location_line(text, path)
    if index is None:
        return text
    indent = re.match(r"^\s*", lines[index]).group(0)
    return "\n".join(lines[:index] + [indent + NOT_EDGE] + lines[index:]) + "\n"


def edge_guarded(text: str, paths: list) -> str:
    for path in [*paths, "/cdn-check"]:
        text = guard_location(text, path)
    return add_not_edge(text, paths[0])


def link_target(system: System, path: str) -> str:
    """sites-enabled usually links to sites-available: change the file, keep the link."""
    seen = 0
    while seen < 8 and os.path.islink(system.path(path)):
        link = os.readlink(system.path(path))
        path = os.path.normpath(link if link.startswith("/")
                                else os.path.join(os.path.dirname(path), link))  # fmt: skip
        seen += 1
    return path


def edge_geo(addresses: list) -> str:
    rows = "".join(f"    {address} 1;\n" for address in dict.fromkeys(addresses))
    return (
        "# KERBEROS (tech.md 10.6): requests to the tunnel only from the confirmed CDN edges.\n"
        "geo $from_cdn_edge {\n    default 0;\n" + rows + "}\n"
    )


@fix("cdn.edge_only")
def fix_edge_only(system: System, params: dict) -> Plan:
    paths = [str(p) for p in params.get("paths") or []]
    if not paths or any(not URL_PATH.match(p) or p == "/" for p in paths):
        raise AgentError("bad_params", "paths")
    nets = []
    for value in params.get("nets") or []:
        try:
            nets.append(str(ipaddress.ip_network(str(value), strict=False)))
        except ValueError as exc:
            raise AgentError("bad_params", "nets") from exc
    if not nets:
        raise AgentError("bad_params", "nets")
    files = collect_files(system, "/etc/nginx/sites-enabled")
    files.update(collect_files(system, "/etc/nginx/conf.d", ".conf"))
    main = system.read("/etc/nginx/nginx.conf")
    if parse_nginx({**files, "/etc/nginx/nginx.conf": main or ""})["realip"]:
        raise AgentError("realip_enabled", "real_ip rewrites the client address")
    sites = [name for name, text in files.items()
             if name != EDGES_CONF and location_line(text, paths[0]) is not None]  # fmt: skip
    site = sites[0] if sites else None
    if site is None:
        raise AgentError("bad_params", f"no nginx location for {paths[0]}")
    v4, v6 = parse_ip_addr(system.run(["ip", "-j", "addr", "show"]).stdout)
    plan = Plan("cdn.edge_only")
    plan.write(EDGES_CONF, edge_geo(["127.0.0.1", "::1", *v4, *v6, *nets]))
    plan.write(link_target(system, site), edge_guarded(files[site], paths), private=True)
    plan.run(["nginx", "-t"], "nginx_test_failed")
    plan.run(["systemctl", "reload", "nginx"])
    plan.undo_after.append(["systemctl", "reload", "nginx"])
    plan.details = {"site": site, "paths": paths, "nets": nets}
    return plan


@fix("watch.install")
def fix_watch(system: System, params: dict) -> Plan:
    plan = Plan("watch.install")
    # Minimal Debian images come without cron; logrotate keeps the log small.
    for package, binary in (("cron", "/usr/sbin/cron"), ("logrotate", "/usr/sbin/logrotate")):
        if needs_package(system, package, binary):
            plan.packages.append(package)
    plan.write(WATCH_BIN, WATCH_SCRIPT, 0o755)
    plan.write(WATCH_CRON, f"*/5 * * * * root {WATCH_BIN} >/dev/null 2>&1\n")
    plan.write(WATCH_ROTATE, f"{WATCH_LOG} {{\n    monthly\n    rotate 12\n    compress\n"
                             "    missingok\n    notifempty\n}\n")  # fmt: skip
    return plan


KEY_LINE = re.compile(
    r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com)"
    r" [A-Za-z0-9+/=]{16,}( [\x20-\x7e]{0,200})?$"
)


@fix("access.admin_keys")
def fix_admin_keys(system: System, params: dict) -> Plan:
    keys = params.get("keys")
    if (
        not isinstance(keys, list)
        or not keys
        or not all(isinstance(k, str) and KEY_LINE.match(k.strip()) for k in keys)
    ):
        raise AgentError("bad_params", "keys")
    current = system.read(AUTHORIZED_KEYS) or ""
    lines = current.splitlines()
    blobs = {
        line.split()[1] for line in lines if len(line.split()) > 1 and not line.startswith("#")
    }
    blobs |= {w for line in lines for w in line.split() if len(w) > 40}
    added = [k.strip() for k in keys if k.split()[1] not in blobs]
    plan = Plan("access.admin_keys")
    if added:
        plan.write(AUTHORIZED_KEYS, "\n".join(lines + added) + "\n", 0o600, private=True)
    plan.details = {"added": len(added)}
    return plan


# -- commands ---------------------------------------------------------------
def cmd_version(system: System, args: list[str], data: Any) -> dict:
    return {
        "protocol": PROTOCOL,
        "agent": AGENT_VERSION,
        "sha256": sha256_bytes(own_source(system)),
    }


VERSION_RE = re.compile(rb'^AGENT_VERSION = "([0-9]+\.[0-9]+\.[0-9]+)"$', re.M)


def cmd_update(system: System, args: list[str], data: bytes) -> dict:
    expected = args[0]
    if sha256_bytes(data) != expected:
        raise AgentError("sha_mismatch", "the new agent file does not match its sha256")
    match = VERSION_RE.search(data)
    if not match:
        raise AgentError("bad_params", "the new file is not a KERBEROS agent")
    system.write_bytes(AGENT_PATH, data, 0o755)
    if sha256_bytes(system.read_bytes(AGENT_PATH) or b"") != expected:
        raise AgentError("sha_mismatch", "the written agent differs from the sent one")
    return {"agent": match.group(1).decode()}


# name -> (handler, argument patterns, stdin: None | "json" | "bytes")
COMMANDS: dict[str, tuple[Callable[[System, list[str], Any], dict], tuple, Optional[str]]] = {
    "version": (cmd_version, (), None),
    "facts": (cmd_facts, (), None),
    "watch": (cmd_watch, (), None),
    "site-check": (cmd_site_check, (), "json"),
    "edge-sources": (cmd_edge_sources, (), "json"),
    "plan": (cmd_plan, (FIX_ID,), "json"),
    "apply": (cmd_apply, (FIX_ID, CHANGE_ID), "json"),
    "confirm": (cmd_confirm, (CHANGE_ID,), None),
    "rollback": (cmd_rollback, (CHANGE_ID,), None),
    "undo": (cmd_undo, (CHANGE_ID,), None),
    "update": (cmd_update, (SHA256,), "bytes"),
}


# Changes go one at a time: the undo timer and a confirm over SSH may meet.
LOCK_FILE = STATE_DIR + "/agent.lock"
LOCK_WAIT = 150.0
LOCKED = {"apply", "confirm", "rollback", "undo", "update"}


@contextlib.contextmanager
def agent_lock(system: System):
    path = system.path(LOCK_FILE)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + LOCK_WAIT
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise AgentError("change_conflict", "another change is running") from exc
                time.sleep(0.2)
        yield
    finally:
        os.close(fd)


def dispatch(system: System, words: list[str], stdin: bytes) -> dict:
    if not words:
        raise AgentError("unknown_command", "no command")
    name, args = words[0], words[1:]
    if name not in COMMANDS:
        raise AgentError("unknown_command", name)
    handler, patterns, stdin_kind = COMMANDS[name]
    if name in LOCKED:
        with agent_lock(system):
            return dispatch_args(system, name, args, patterns, stdin_kind, stdin, handler)
    return dispatch_args(system, name, args, patterns, stdin_kind, stdin, handler)


def dispatch_args(system: System, name: str, args: list, patterns: tuple,
                  stdin_kind: Optional[str], stdin: bytes, handler: Callable) -> dict:  # fmt: skip
    if len(args) != len(patterns) or not all(p.match(a) for p, a in zip(patterns, args)):
        raise AgentError("bad_params", f"{name} expects {len(patterns)} valid arguments")
    data: Any = None
    if stdin_kind == "bytes":
        data = stdin
    elif stdin_kind == "json":
        try:
            data = json.loads(stdin.decode("utf-8") or "{}")
        except (UnicodeDecodeError, ValueError) as exc:
            raise AgentError("bad_params", "stdin is not JSON") from exc
        if not isinstance(data, dict):
            raise AgentError("bad_params", "stdin must be a JSON object")
    return handler(system, args, data)


def command_words(argv: list[str], environ: dict) -> list[str]:
    if argv:
        return list(argv)
    try:
        return shlex.split(environ.get("SSH_ORIGINAL_COMMAND", ""))
    except ValueError as exc:
        raise AgentError("bad_params", "cannot parse the command") from exc


def main(
    argv: Optional[list[str]] = None,
    system: Optional[System] = None,
    stdin: Optional[bytes] = None,
    out: Any = None,
) -> int:
    system = system or System()
    out = out or sys.stdout
    argv = sys.argv[1:] if argv is None else argv
    try:
        words = command_words(argv, system.environ)
        needs_stdin = bool(words) and COMMANDS.get(words[0], (None, (), None))[2] is not None
        if stdin is None:
            stdin = sys.stdin.buffer.read() if needs_stdin else b""
        answer = dispatch(system, words, stdin)
    except AgentError as exc:
        out.write(json.dumps({"error": {"code": exc.code, "message": exc.message}}) + "\n")
        return 1
    out.write(json.dumps(answer, ensure_ascii=False, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
