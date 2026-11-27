"""PanelClient port (tech.md §7): Remnawave API over a pluggable HTTP transport.

The live transport is urllib against the panel on this server; the fake is
an in-memory panel (`kerberos.panel.fake`). The client logic (headers,
retries, envelope, both host forms) is the same for both.

KERBEROS works with an API token of the panel (§7.3): Remnawave accepts the
admin login token only from its own web UI, and only that token may make an
API token. So KERBEROS signs in as the admin once, with the browser header on
those requests alone, makes its own API token and forgets the password and
the login token (K30). The API token is kept 0600 in
/var/lib/kerberos/panel.token by S2, never in a log or a run file.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Any, Optional, Protocol

from kerberos import __version__
from kerberos.clock import Clock
from kerberos.panel import schema
from kerberos.panel.errors import PanelError
from kerberos.panel.model import Host, Node, PanelSnapshot, Profile, Squad, SubSettings, Template

TIMEOUT = 15.0
RETRY_DELAYS = (1, 4, 15)
FORWARD_HEADERS = {
    "x-forwarded-proto": "https",
    "x-forwarded-for": "127.0.0.1",
    "x-real-ip": "127.0.0.1",
}
# The panel's web UI sends this with the admin login token; without it the panel refuses that
# token to programs (§7.3). KERBEROS sends it only with that token, to make its own (K30).
CLIENT_TYPE_HEADER = "x-remnawave-client-type"
TOKEN_NAME = "KERBEROS"
TOKEN_DAYS = 3650  # the panel makes no token without an expiry (K30)
# Scope sections of the API token (§7.3), by the path KERBEROS calls.
SECTIONS = {
    "/nodes": "nodes",
    "/config-profiles": "config-profiles",
    "/hosts": "hosts",
    "/subscription-templates": "subscription-template",
    "/internal-squads": "internal-squads",
    "/subscription-settings": "subscription-settings",
}
# Rights to give the token, as the panel's «create token» window takes them pasted.
# «Исправление» changes nodes only by `PATCH /nodes` (the inbounds a node runs, §10.4, K20):
# the endpoint scope, not the whole write right of the section.
SCOPES_CHECK = [f"{section}:read" for section in SECTIONS.values()]
SCOPES_FIX = ["nodes:read", "nodes:update"] + [f"{s}:*" for s in SECTIONS.values() if s != "nodes"]


def password_login(status: Any) -> bool:
    """§7.3, step 1 (K30): whether the panel takes the admin password at all. An answer
    without these fields (another version) counts as yes: the login itself will tell."""
    if not isinstance(status, dict):
        return True
    if status.get("isLoginAllowed") is False:
        return False
    auth = status.get("authentication")
    password = auth.get("password") if isinstance(auth, dict) else None
    return not (isinstance(password, dict) and password.get("enabled") is False)


def section_of(operation: str) -> tuple[str, str]:
    """("hosts", "write") for "PATCH /hosts"; ("", kind) for a path outside the sections."""
    method, _, path = operation.partition(" ")
    kind = "read" if method == "GET" else "write"
    for prefix, section in SECTIONS.items():
        if path == prefix or path.startswith(prefix + "/"):
            return section, kind
    return "", kind


class NoResponse(Exception):
    """The request may have reached the panel, but no answer came back."""


class Unreachable(Exception):
    """The connection was refused: the request never reached the panel."""


class Transport(Protocol):
    def __call__(
        self, method: str, url: str, headers: dict, body: Optional[bytes], timeout: float
    ) -> tuple[int, bytes]: ...


def urllib_transport(
    method: str, url: str, headers: dict, body: Optional[bytes], timeout: float
) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read() or b""
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ConnectionRefusedError):
            raise Unreachable(str(exc.reason)) from exc
        raise NoResponse(str(exc.reason)) from exc
    except (socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
        raise NoResponse(str(exc)) from exc


class PanelClient:
    def __init__(self, base_url: str, transport: Transport, clock: Clock) -> None:
        self.base = base_url.rstrip("/")
        self.transport = transport
        self.clock = clock
        self._token: Optional[str] = None
        self.host_shape = "tags"
        self._shape_known = False  # learnt from GET /hosts before the first host is written
        self.calls: list[tuple[str, str]] = []
        self.token_source = ""  # "saved", "typed" or "made": S2 says which (§7.3, K30)
        self.refused = False  # the panel refused this token something (403)
        self.wrote = False  # the panel took a change with this token
        self.password_login = True  # the panel takes the admin password (§7.3, K30)

    @property
    def authenticated(self) -> bool:
        return self._token is not None

    def set_token(self, token: str) -> None:
        self._token = token.strip()

    def forget_token(self) -> None:
        self._token = None

    # -- transport -----------------------------------------------------
    def request(
        self, method: str, path: str, body: Any = None, *, auth: bool = True,
        admin: Optional[str] = None,
    ) -> Any:  # fmt: skip
        """`admin`: the admin login token of `make_token`, sent as the web UI sends it."""
        headers = dict(FORWARD_HEADERS)
        headers["accept"] = "application/json"
        headers["user-agent"] = f"kerberos/{__version__}"
        data = None
        if body is not None:
            headers["content-type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        with_token = admin is None and auth and bool(self._token)
        if admin is not None:
            headers["authorization"] = f"Bearer {admin}"
            headers[CLIENT_TYPE_HEADER] = "browser"
        elif with_token:
            headers["authorization"] = f"Bearer {self._token}"
        operation = f"{method} {path}"
        self.calls.append((method, path))
        attempt = 0
        while True:
            try:
                status, raw = self.transport(method, self.base + path, headers, data, TIMEOUT)
            except NoResponse as exc:
                if method == "POST":
                    # The host may have been created: never send it twice (§7.2).
                    raise PanelError("no_response", operation=operation, detail=str(exc)) from exc
                if attempt < len(RETRY_DELAYS):
                    self.clock.sleep(RETRY_DELAYS[attempt])
                    attempt += 1
                    continue
                raise PanelError("timeout", operation=operation, detail=str(exc)) from exc
            except Unreachable as exc:
                if attempt < len(RETRY_DELAYS):
                    self.clock.sleep(RETRY_DELAYS[attempt])
                    attempt += 1
                    continue
                raise PanelError("unreachable", operation=operation, detail=str(exc)) from exc
            except ValueError as exc:
                # Headers go out as Latin-1: a token with other letters cannot be a token.
                code = "unauthorized" if with_token else "bad_request"
                raise PanelError(code, operation=operation, detail="not Latin-1") from exc
            if status >= 500:
                if attempt < len(RETRY_DELAYS):
                    self.clock.sleep(RETRY_DELAYS[attempt])
                    attempt += 1
                    continue
                raise PanelError("server_error", status, operation)
            break
        if status == 401:
            raise PanelError("unauthorized", 401, operation)
        if status == 403:
            # Only what the API token was refused counts: a wrong admin password does not.
            self.refused = self.refused or with_token
            raise PanelError("forbidden", 403, operation, _message(raw))
        if status >= 400:
            raise PanelError("bad_request", status, operation, _message(raw))
        if method != "GET" and with_token:
            self.wrote = True
        if status == 204:
            return None  # 3.x: bulk calls and deletes answer without a body (§7.2)
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else None
        except (UnicodeDecodeError, ValueError) as exc:
            raise PanelError("bad_response", status, operation, "not JSON") from exc
        try:
            return schema.unwrap(payload)
        except PanelError as exc:
            exc.operation = operation
            raise

    # -- auth (§7.3) -----------------------------------------------------
    def reachable(self) -> None:
        """The panel answers at all; its answer says whether it takes the admin password."""
        self.password_login = password_login(self.request("GET", "/auth/status", auth=False))

    def make_token(
        self, username: str, password: str, previous: Optional[str] = None
    ) -> tuple[str, str]:
        """§7.3, step 3 (K30): sign in as the admin of the panel, make the API token of
        KERBEROS and delete the one KERBEROS made before (`previous`, its uuid). The new
        (token, uuid); the client does not take the token itself.

        The admin login token lives in this call only, and the browser header goes with it
        alone. A failed login is 403 whatever the reason (wrong name, wrong password).
        """
        answer = self.request("POST", "/auth/login",
                              {"username": username, "password": password}, auth=False)  # fmt: skip
        session = schema.access_token(answer)
        body = {"name": TOKEN_NAME, "expiresInDays": TOKEN_DAYS, "scopes": list(SCOPES_FIX)}
        token, uuid = schema.api_token(self.request("POST", "/tokens", body, admin=session))
        if previous and previous != uuid:
            try:
                self.request("DELETE", f"/tokens/{previous}", admin=session)
            except PanelError:
                pass  # deleted in the panel already (404), or it stays in the panel's list
        return token, uuid

    # -- reading ---------------------------------------------------------
    def nodes(self) -> list[Node]:
        return [schema.node(n) for n in schema.items(self.request("GET", "/nodes"), "nodes")]

    def profiles(self) -> list[Profile]:
        answer = self.request("GET", "/config-profiles")
        return [schema.profile(p) for p in schema.items(answer, "configProfiles")]

    def hosts(self) -> list[Host]:
        raw = schema.items(self.request("GET", "/hosts"), "hosts")
        self.host_shape = schema.detect_shape(raw)
        self._shape_known = True
        return [schema.host(h, self.host_shape) for h in raw]

    def host(self, uuid: str) -> Host:
        self.learn_shape()
        return schema.host(self.request("GET", f"/hosts/{uuid}"), self.host_shape)

    def learn_shape(self) -> None:
        """§7.4: hosts are written in the form the panel reads them in (a fresh client, e.g.
        the one of `kerberos rollback`, has not read any host yet)."""
        if not self._shape_known:
            self.hosts()

    def templates(self) -> list[Template]:
        answer = self.request("GET", "/subscription-templates")
        return [schema.template(t) for t in schema.items(answer, "templates")]

    def template(self, uuid: str) -> Template:
        return schema.template(self.request("GET", f"/subscription-templates/{uuid}"))

    def squads(self) -> list[Squad]:
        answer = self.request("GET", "/internal-squads")
        return [schema.squad(s) for s in schema.items(answer, "internalSquads")]

    def sub_settings(self) -> SubSettings:
        return schema.sub_settings(self.request("GET", "/subscription-settings"))

    def snapshot(self, version: str, panel_domain: Optional[str] = None) -> PanelSnapshot:
        hosts = self.hosts()
        templates = []
        for item in self.templates():
            if item.type == "XRAY_JSON" and item.json is None:
                item = self.template(item.uuid)
            templates.append(item)
        return PanelSnapshot(
            version=version,
            nodes=self.nodes(),
            hosts=hosts,
            profiles=self.profiles(),
            templates=templates,
            squads=self.squads(),
            sub_settings=self.sub_settings(),
            host_shape=self.host_shape,
            panel_domain=panel_domain,
        )

    # -- changes (used by «Исправление» only) ----------------------------
    def patch_profile(self, uuid: str, config: dict) -> Profile:
        return schema.profile(
            self.request("PATCH", "/config-profiles", {"uuid": uuid, "config": config})
        )

    def create_profile(self, name: str, config: dict) -> Profile:
        """A node's own profile (§10.4, K24). Inbound tags are unique across the panel and
        so is the name: either taken answers 409."""
        return schema.profile(
            self.request("POST", "/config-profiles", {"name": name, "config": config})
        )

    def delete_profile(self, uuid: str) -> None:
        """The panel stops every node of the profile; hosts on it lose their profile."""
        self.request("DELETE", f"/config-profiles/{uuid}")

    def patch_node_inbounds(self, uuid: str, profile_uuid: str, inbounds: list[str]) -> Node:
        """The inbounds a node runs (§10.4, K20). The panel replaces the whole list, every
        inbound must be one of the profile's, and the node restarts."""
        body = {"uuid": uuid, "configProfile": {"activeConfigProfileUuid": profile_uuid,
                                                "activeInbounds": list(inbounds)}}  # fmt: skip
        return schema.node(self.request("PATCH", "/nodes", body))

    def create_host(self, fields: dict) -> Host:
        self.learn_shape()
        body = schema.host_write_fields(fields, self.host_shape)
        return schema.host(self.request("POST", "/hosts", body), self.host_shape)

    def patch_host(self, uuid: str, fields: dict) -> Host:
        self.learn_shape()
        body = {"uuid": uuid, **schema.host_write_fields(fields, self.host_shape)}
        if "isDisabled" not in body:
            # 2.8 sets an absent isDisabled to false: the host would be switched on (§7.4).
            body["isDisabled"] = self.host(uuid).is_disabled
        return schema.host(self.request("PATCH", "/hosts", body), self.host_shape)

    def disable_hosts(self, uuids: list[str]) -> None:
        self.request("POST", "/hosts/bulk/disable", {"uuids": list(uuids)})

    def enable_hosts(self, uuids: list[str]) -> None:
        self.request("POST", "/hosts/bulk/enable", {"uuids": list(uuids)})

    def delete_host(self, uuid: str) -> None:
        self.request("DELETE", f"/hosts/{uuid}")

    def create_template(self, name: str) -> Template:
        body = {"name": name, "templateType": "XRAY_JSON"}
        return schema.template(self.request("POST", "/subscription-templates", body))

    def patch_template(self, uuid: str, template_json: dict) -> Template:
        body = {"uuid": uuid, "templateJson": template_json}
        return schema.template(self.request("PATCH", "/subscription-templates", body))

    def patch_squad(self, uuid: str, inbound_uuids: list[str]) -> Squad:
        body = {"uuid": uuid, "inbounds": list(inbound_uuids)}
        return schema.squad(self.request("PATCH", "/internal-squads", body))

    def patch_sub_settings(self, uuid: str, headers: dict) -> SubSettings:
        body = {"uuid": uuid, "customResponseHeaders": headers}
        return schema.sub_settings(self.request("PATCH", "/subscription-settings", body))


def _message(raw: bytes) -> str:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return ""
    if isinstance(payload, dict):
        message = payload.get("message")
        if isinstance(message, str):
            return message[:200]
    return ""
