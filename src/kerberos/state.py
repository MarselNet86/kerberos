"""State of KERBEROS on the panel server (tech.md §5.4).

/var/lib/kerberos (0700, root): KERBEROS and admin keys, pinned host keys,
nodes.json, runs and the lock. Tests and --demo use a temporary directory.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from kerberos.nodes.keys import known_hosts_name

if TYPE_CHECKING:
    from kerberos.nodes.transport import Target

DEFAULT_ROOT = Path("/var/lib/kerberos")
LOCK_STEP = 5.0  # seconds between two tries of a lock that is busy
ADMIN_MODES = ("mine", "create")  # the answers of §8.5 that are remembered (K25)
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class Locked(Exception):
    """Another KERBEROS run holds the lock."""


@dataclass
class NodeRecord:
    uuid: str
    name: str
    address: str
    ssh_port: int = 22
    fingerprint: str = ""
    agent: str = ""
    panel_ip: str = ""
    access: str = "none"  # ok | none | denied
    extra: dict = field(default_factory=dict)
    # 3x-ui (§7.6): the server reaches itself over SSH at this address, not its public one.
    ssh_address: str = ""

    def target(self, address: str) -> Target:
        from kerberos.nodes.transport import Target

        return Target(self.uuid, self.name, self.ssh_address or address, self.ssh_port)


_CAMEL = {"ssh_port": "sshPort", "panel_ip": "panelIp", "ssh_address": "sshAddress"}
_SNAKE = {v: k for k, v in _CAMEL.items()}


class State:
    def __init__(self, root: Path = DEFAULT_ROOT) -> None:
        self.root = Path(root)

    # -- layout ------------------------------------------------------------
    @property
    def key(self) -> Path:
        return self.root / "id_ed25519"

    @property
    def admin_key(self) -> Path:
        return self.root / "admin_ed25519"

    @property
    def known_hosts(self) -> Path:
        return self.root / "known_hosts"

    @property
    def nodes_file(self) -> Path:
        return self.root / "nodes.json"

    @property
    def panel_token(self) -> Path:
        return self.root / "panel.token"

    @property
    def runs(self) -> Path:
        return self.root / "runs"

    @property
    def answers_file(self) -> Path:
        return self.root / "answers.json"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    @contextmanager
    def lock(
        self, wait: float = 0.0, sleep: Callable[[float], None] = time.sleep
    ) -> Iterator[None]:
        """One KERBEROS at a time (flock on /var/lib/kerberos/lock).

        `wait`: seconds to wait for another KERBEROS to finish before giving up.
        """
        import fcntl

        self.ensure()
        fd = os.open(self.root / "lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            waited = 0.0
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as exc:
                    if waited >= wait:
                        raise Locked() from exc
                    step = min(LOCK_STEP, wait - waited)
                    sleep(step)
                    waited += step
            yield
        finally:
            os.close(fd)

    # -- files ---------------------------------------------------------------
    def write_private(self, path: Path, text: str) -> None:
        """Write a file only root may read (keys, reports, run files)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    def _panel_token(self) -> dict:
        """{token, write, uuid} (§7.3): `write` once the token was made by KERBEROS, given
        for changes or made one; `uuid` only for a token KERBEROS made itself (K30)."""
        try:
            text = self.panel_token.read_text(encoding="utf-8").strip()
        except OSError:
            return {}
        try:
            data = json.loads(text)
        except ValueError:
            return {"token": text} if text else {}  # a bare token: its rights are not known
        return data if isinstance(data, dict) else {}

    def read_panel_token(self) -> Optional[str]:
        """The Remnawave API token S2 saved (§7.3); None when there is none."""
        token = self._panel_token().get("token")
        return token if isinstance(token, str) and token else None

    def panel_token_can_write(self) -> bool:
        return self.read_panel_token() is not None and self._panel_token().get("write") is True

    def panel_token_uuid(self) -> Optional[str]:
        """The panel's uuid of the token KERBEROS made itself (K30): only that one KERBEROS
        may delete. None for a token the person pasted."""
        value = self._panel_token().get("uuid")
        return value if isinstance(value, str) and UUID_RE.fullmatch(value) else None

    def write_panel_token(self, token: str, write: bool, uuid: Optional[str] = None) -> None:
        self.ensure()
        data: dict = {"token": token.strip(), "write": bool(write)}
        if uuid:
            data["uuid"] = uuid
        self.write_private(self.panel_token, json.dumps(data) + "\n")

    def mark_panel_token_writable(self) -> None:
        token = self.read_panel_token()
        if token and not self.panel_token_can_write():
            self.write_panel_token(token, True, self.panel_token_uuid())

    def forget_panel_token(self) -> None:
        """The panel refused the token (§7.3): it goes. Of a token KERBEROS made the uuid
        stays, so that the next login deletes it in the panel (K30)."""
        uuid = self.panel_token_uuid()
        if uuid is None:
            self.panel_token.unlink(missing_ok=True)
            return
        self.ensure()
        self.write_private(self.panel_token, json.dumps({"uuid": uuid}) + "\n")

    # -- answers.json (K25) -----------------------------------------------------
    def answers(self) -> dict:
        """What the person answered before (§5.4): {whois: bool, admin: {mode, keys}}.

        Only well formed values come back: `admin.mode` is `mine` or `create`, and its
        keys are fingerprints, never the key lines (their comments may be an email)."""
        try:
            data = json.loads(self.answers_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        if not isinstance(data, dict):
            return {}
        answers: dict = {}
        if isinstance(data.get("whois"), bool):
            answers["whois"] = data["whois"]
        admin = data.get("admin")
        if isinstance(admin, dict) and admin.get("mode") in ADMIN_MODES:
            keys = [k for k in admin.get("keys") or []
                    if isinstance(k, str) and k.startswith("SHA256:")]  # fmt: skip
            answers["admin"] = {"mode": admin["mode"], "keys": keys}
        return answers

    def remember(self, **answers: object) -> None:
        """Keep answers for the next runs; None forgets one."""
        data = self.answers()
        for name, value in answers.items():
            if value is None:
                data.pop(name, None)
            else:
                data[name] = value
        self.ensure()
        self.write_private(self.answers_file, json.dumps(data, ensure_ascii=False) + "\n")

    def public_key(self, admin: bool = False) -> Optional[str]:
        path = (self.admin_key if admin else self.key).with_suffix(".pub")
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError:
            return None

    # -- nodes.json ------------------------------------------------------
    def nodes(self) -> dict[str, NodeRecord]:
        try:
            raw = json.loads(self.nodes_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        records = {}
        for uuid, item in raw.items() if isinstance(raw, dict) else ():
            if not isinstance(item, dict):
                continue
            fields = {_SNAKE.get(k, k): v for k, v in item.items()}
            fields = {k: v for k, v in fields.items() if k in NodeRecord.__dataclass_fields__}
            fields.pop("uuid", None)
            try:
                records[uuid] = NodeRecord(uuid=uuid, **fields)
            except TypeError:
                continue
        return records

    def node(self, uuid: str) -> Optional[NodeRecord]:
        return self.nodes().get(uuid)

    def save_node(self, record: NodeRecord) -> None:
        records = self.nodes()
        records[record.uuid] = record
        data = {
            uuid: {_CAMEL.get(k, k): v for k, v in asdict(r).items() if k != "uuid"}
            for uuid, r in sorted(records.items())
        }
        self.ensure()
        self.write_private(self.nodes_file, json.dumps(data, ensure_ascii=False, indent=2) + "\n")

    def find_node(self, name_or_uuid: str) -> Optional[NodeRecord]:
        records = self.nodes()
        if name_or_uuid in records:
            return records[name_or_uuid]
        matches = [r for r in records.values() if r.name == name_or_uuid]
        return matches[0] if len(matches) == 1 else None

    # -- known_hosts -----------------------------------------------------
    def pin(self, address: str, port: int, key_type: str, blob: str) -> None:
        """Pin the host key; an older key for the same name is replaced."""
        name = known_hosts_name(address, port)
        lines = []
        try:
            lines = self.known_hosts.read_text(encoding="utf-8").splitlines()
        except OSError:
            pass
        kept = [line for line in lines if line.split(" ", 1)[0] != name]
        kept.append(f"{name} {key_type} {blob}")
        self.ensure()
        self.write_private(self.known_hosts, "\n".join(kept) + "\n")

    def pinned(self, address: str, port: int) -> Optional[str]:
        name = known_hosts_name(address, port)
        try:
            for line in self.known_hosts.read_text(encoding="utf-8").splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == name:
                    return parts[2]
        except OSError:
            return None
        return None
