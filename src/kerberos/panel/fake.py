"""Fake Remnawave panel: the PanelClient transport for tests and --demo.

It keeps panel objects in memory, answers in the `{response: ...}` envelope,
and checks every request against the contract of tech.md §7.4: missing
headers, unknown fields, wrong types and unknown uuids fail loudly, as a
strict panel would. Failures can be injected per endpoint.

It behaves like the real backend where KERBEROS once went wrong (§7.3, §7.4):
an admin login token is refused without the browser header, every failed
login is 403, only that token may make or delete API tokens, API tokens have
scopes per section, 3.x answers 204 without a body to bulk calls and deletes,
2.8 enables a host whose PATCH lacks `isDisabled`, remarks, tags and template
names have limits, and a profile PATCH may store a normalized config.
"""

from __future__ import annotations

import copy
import json
import random
import re
import secrets
import uuid as uuidlib
from dataclasses import dataclass
from typing import Any, Callable, Optional, Union
from urllib.parse import urlsplit

from kerberos.panel.client import CLIENT_TYPE_HEADER, FORWARD_HEADERS, NoResponse, Unreachable

COMMON_HOST_FIELDS = {
    "remark",
    "address",
    "port",
    "path",
    "sni",
    "host",
    "alpn",
    "fingerprint",
    "isDisabled",
    "securityLayer",
    "muxParams",
    "sockoptParams",
    "inbound",
    "serverDescription",
    "isHidden",
    "overrideSniFromAddress",
    "keepSniBlank",
    "vlessRouteId",
    "allowInsecure",
    "shuffleHost",
    "mihomoX25519",
    "nodes",
    "xrayJsonTemplateUuid",
    "excludedInternalSquads",
}
SHAPE_FIELDS = {"tags": {"tags", "xhttpExtraParams"}, "tag": {"tag", "xHttpExtraParams"}}
ADMIN_ONLY_FROM_BROWSER = "For API requests you must create own API-token in the admin dashboard."
TEMPLATE_NAME = re.compile(r"[A-Za-z0-9_\s-]{2,255}")
PROFILE_NAME = re.compile(r"[A-Za-z0-9_\s-]{2,30}")  # 2.8.1 and 3.4.11: 2 to 30 characters
TAG_TAKEN = {"message": "Inbounds with same tag already exists in database. Inbound tags must "
                        "be unique.", "errorCode": "A113"}  # fmt: skip
# Scope sections of the endpoints KERBEROS may call: what an API token needs (§7.3).
SECTIONS = {
    "/nodes": "nodes",
    "/config-profiles": "config-profiles",
    "/hosts": "hosts",
    "/subscription-templates": "subscription-template",
    "/internal-squads": "internal-squads",
    "/subscription-settings": "subscription-settings",
}
# Scopes of single endpoints, `<section>:<slug>` (scope slugs of the 2.8.1 and 3.4.11 contract).
ENDPOINT_SCOPES = {("PATCH", "/nodes"): "nodes:update"}
# Every failed login, whatever went wrong (2.8.1 and 3.4.11: ERRORS.FORBIDDEN).
LOGIN_FAILED = {"message": "Forbidden", "errorCode": "A068"}
BAD_SCOPE = {"message": "One or more provided API token scopes are invalid", "errorCode": "A229"}
TOKEN_NOT_FOUND = {"message": "Requested token not found", "errorCode": "A007"}
# Scopes a token may get: the wildcard, a section, its read or write, an endpoint of it.
VALID_SCOPES = {"*", *ENDPOINT_SCOPES.values()} | {
    f"{section}:{kind}" for section in SECTIONS.values() for kind in ("*", "read", "write")
}


class ContractError(Exception):
    """KERBEROS sent something the panel contract does not allow."""


@dataclass
class Failure:
    method: str
    path: str
    # HTTP status, "timeout", "refused", "lost" (applied, no answer) or "applied:<status>"
    # (applied, then that status: the panel failed after it stored the change).
    kind: Union[int, str]
    times: int = 1
    after: int = 0  # matching requests let through first


_rng = random.Random()


def seed_uuids(seed: int) -> None:
    """Make generated uuids repeatable (demo fleet, snapshots)."""
    _rng.seed(seed)


def new_uuid() -> str:
    return str(uuidlib.UUID(int=_rng.getrandbits(128), version=4))


class FakePanel:
    def __init__(
        self,
        *,
        shape: str = "tags",
        version: str = "3.4.11",
        password_enabled: bool = True,
        credentials: tuple[str, str] = ("admin", "admin-password"),
        accept_any_token: bool = False,
        accept_any_login: bool = False,
        normalize_profile: Optional[Callable[[dict], dict]] = None,
    ) -> None:
        self.shape = shape
        self.version = version
        self.major = int(version.split(".")[0])
        self.password_enabled = password_enabled
        self.credentials = credentials
        self.accept_any_token = accept_any_token  # the demo: any token is a full-access one
        self.accept_any_login = accept_any_login  # the demo: any name and password sign in
        self.normalize_profile = normalize_profile
        self.sessions: set[str] = set()  # admin login tokens: only the web UI may use them
        self.api_tokens: dict[str, list[str]] = {}  # token -> scopes
        self.made_tokens: dict[str, dict] = {}  # uuid -> {token, name, expiresInDays, scopes}
        self.logins: list[str] = []  # names of every login try: the panel's notifications
        self.nodes: list[dict] = []
        self.profiles: list[dict] = []
        self.hosts: list[dict] = []
        self.templates: list[dict] = []
        self.squads: list[dict] = []
        self.sub_settings: dict = {"uuid": new_uuid(), "customResponseHeaders": {}}
        self.failures: list[Failure] = []
        self.log: list[tuple[str, str, Any]] = []
        self.forbidden: set[tuple[str, str]] = set()

    # -- setup -----------------------------------------------------------
    def add_api_token(self, token: Optional[str] = None, scopes: tuple = ("*",)) -> str:
        token = token or "rw-" + secrets.token_hex(16)
        self.api_tokens[token] = list(scopes)
        return token

    def fail(
        self, method: str, path: str, kind: Union[int, str], times: int = 1, after: int = 0
    ) -> None:
        self.failures.append(Failure(method, path, kind, times, after))

    @property
    def mutations(self) -> list[tuple[str, str, Any]]:
        """Requests that change panel settings. Login does not, and neither does the API
        token KERBEROS makes itself: access, as the agent key on a node (§2, K30)."""
        return [entry for entry in self.log if entry[0] != "GET" and entry[1] != "/auth/login"
                and not entry[1].startswith("/tokens")]  # fmt: skip

    def made_token(self, uuid: str, token: str, name: str, days: int, scopes: list) -> None:
        self.api_tokens[token] = list(scopes)
        self.made_tokens[uuid] = {"token": token, "name": name, "expiresInDays": days,
                                  "scopes": list(scopes)}  # fmt: skip

    def host(self, uuid: str) -> dict:
        for item in self.hosts:
            if item["uuid"] == uuid:
                return item
        raise KeyError(uuid)

    # -- transport -------------------------------------------------------
    def __call__(
        self, method: str, url: str, headers: dict, body: Optional[bytes], timeout: float
    ) -> tuple[int, bytes]:
        path = urlsplit(url).path
        if not path.startswith("/api/"):
            return self._json(404, {"message": "not found"})
        path = path[len("/api") :]
        lowered = {k.lower(): v for k, v in headers.items()}
        for name, value in FORWARD_HEADERS.items():
            if lowered.get(name) != value:
                return self._json(400, {"message": f"missing header {name}"})
        data: Any = None
        if body is not None:
            try:
                data = json.loads(body.decode("utf-8"))
            except ValueError:
                return self._json(400, {"message": "body is not JSON"})
        self.log.append((method, path, copy.deepcopy(data)))
        failure = self._failure(method, path)
        lost = False
        applied_status = 0
        if failure is not None:
            if failure.kind == "timeout":
                raise NoResponse("timed out")
            if failure.kind == "refused":
                raise Unreachable("connection refused")
            if failure.kind == "lost":
                lost = True
            elif str(failure.kind).startswith("applied:"):
                applied_status = int(str(failure.kind).split(":", 1)[1])
            else:
                return self._json(int(failure.kind), {"message": "injected"})
        if path not in ("/auth/status", "/auth/login"):
            token = lowered.get("authorization", "").removeprefix("Bearer ").strip()
            refused = self._refusal(token, lowered, method, path)
            if refused is not None:
                return refused
        if (method, path) in self.forbidden:
            return self._json(403, {"message": "Forbidden"})
        try:
            status, answer = self._route(method, path, data)
        except ContractError as exc:
            return self._json(400, {"message": str(exc)})
        if lost:
            raise NoResponse("connection reset after the request")
        if applied_status:
            return self._json(applied_status, {"message": "injected after the change"})
        if status == 204:
            return 204, b""
        return self._json(status, {"response": answer} if status < 400 else answer)

    def _refusal(self, token: str, headers: dict, method: str, path: str) -> Optional[tuple]:
        """401 for an unknown token, 403 for what the panel refuses a known one (§7.3)."""
        if token in self.sessions:
            if headers.get(CLIENT_TYPE_HEADER) != "browser":
                return self._json(403, {"message": ADMIN_ONLY_FROM_BROWSER})
            return None
        if token in self.api_tokens:
            scopes = self.api_tokens[token]
        elif self.accept_any_token and token:
            scopes = ["*"]
        else:
            return self._json(401, {"message": "Unauthorized"})
        section = next((s for p, s in SECTIONS.items() if path == p or path.startswith(p + "/")),
                       None)  # fmt: skip
        if path.startswith("/tokens"):
            return self._json(403, {"message": "Forbidden resource"})  # admin login token only
        kind = "read" if method == "GET" else "write"
        if section is None or {"*", f"{section}:*", f"{section}:{kind}"} & set(scopes):
            return None
        if ENDPOINT_SCOPES.get((method, path)) in scopes:
            return None
        return self._json(403, {"message": "Forbidden resource"})

    def _deleted(self) -> tuple[int, Any]:
        """3.x answers bulk calls and deletes with 204 and no body; 2.8 with a body."""
        return (204, None) if self.major >= 3 else (200, {"isDeleted": True})

    def _failure(self, method: str, path: str) -> Optional[Failure]:
        for failure in self.failures:
            if failure.method == method and failure.path == path and failure.times > 0:
                if failure.after > 0:
                    failure.after -= 1
                    return None
                failure.times -= 1
                return failure
        return None

    @staticmethod
    def _json(status: int, payload: Any) -> tuple[int, bytes]:
        return status, json.dumps(payload).encode("utf-8")

    # -- routing ---------------------------------------------------------
    def _route(self, method: str, path: str, data: Any) -> tuple[int, Any]:
        if method == "GET" and path == "/auth/status":
            return 200, {
                "isLoginAllowed": True,
                "isRegisterAllowed": False,
                "authentication": {
                    "passkey": {"enabled": not self.password_enabled},
                    "password": {"enabled": self.password_enabled},
                },
            }
        if method == "POST" and path == "/auth/login":
            body = self._body(data, {"username": str, "password": str})
            self.logins.append(body["username"])
            good = (body["username"], body["password"]) == self.credentials
            if not self.password_enabled or not (good or (
                    self.accept_any_login and body["username"] and body["password"])):  # fmt: skip
                return 403, dict(LOGIN_FAILED)  # disabled, no such admin or a wrong password
            token = "jwt-" + secrets.token_hex(16)
            self.sessions.add(token)
            return 200, {"accessToken": token}
        if path == "/tokens" or path.startswith("/tokens/"):
            return self._tokens(method, path, data)
        if method == "GET" and path == "/nodes":
            return 200, copy.deepcopy(self.nodes)
        if method == "GET" and path == "/config-profiles":
            profiles = copy.deepcopy(self.profiles)
            for profile in profiles:
                profile["nodes"] = [
                    {"uuid": n["uuid"], "name": n["name"], "countryCode": n.get("countryCode")}
                    for n in self.nodes
                    if (n.get("configProfile") or {}).get("activeConfigProfileUuid")
                    == profile["uuid"]
                ]
            return 200, {"total": len(profiles), "configProfiles": profiles}
        if method == "POST" and path == "/config-profiles":
            return self._create_profile(data)
        if method == "DELETE" and path.startswith("/config-profiles/"):
            return self._delete_profile(path.rsplit("/", 1)[1])
        if method == "PATCH" and path == "/config-profiles":
            body = self._body(data, {"uuid": str, "config": dict})
            profile = self._find(self.profiles, body["uuid"], "config profile")
            if self._taken_tags(body["config"], profile["uuid"]):
                return 409, dict(TAG_TAKEN)
            config = copy.deepcopy(body["config"])
            # The panel stores the config validated and sorted, not byte for byte (§10.4).
            profile["config"] = self.normalize_profile(config) if self.normalize_profile else config
            self._sync_inbounds(profile)
            # An inbound that left the profile leaves the nodes too; a new one is active on no
            # node until PATCH /nodes switches it on (2.8.1 and 3.4.11, K20).
            known = {i["uuid"] for i in profile["inbounds"]}
            for node in self.nodes:
                ref = node.get("configProfile") or {}
                if ref.get("activeConfigProfileUuid") == profile["uuid"]:
                    ref["activeInbounds"] = [i for i in ref.get("activeInbounds") or []
                                             if i.get("uuid") in known]  # fmt: skip
            return 200, copy.deepcopy(profile)
        if method == "PATCH" and path == "/nodes":
            return self._patch_node(data)
        if method == "GET" and path == "/hosts":
            return 200, copy.deepcopy(self.hosts)
        if method == "GET" and path.startswith("/hosts/") and path.count("/") == 2:
            return 200, copy.deepcopy(self._find(self.hosts, path.rsplit("/", 1)[1], "host"))
        if method == "POST" and path == "/hosts":
            host = self._host_fields(data, create=True)
            host["uuid"] = new_uuid()
            host["viewPosition"] = max([h.get("viewPosition", 0) for h in self.hosts] + [0]) + 1
            self.hosts.append(host)
            return 200, copy.deepcopy(host)
        if method == "PATCH" and path == "/hosts":
            if not isinstance(data, dict) or not isinstance(data.get("uuid"), str):
                raise ContractError("uuid is required")
            host = self._find(self.hosts, data["uuid"], "host")
            fields = self._host_fields({k: v for k, v in data.items() if k != "uuid"}, create=False)
            if self.major < 3 and "isDisabled" not in fields:
                # 2.8: `isDisabled: z.boolean().default(false)` turns the host back on.
                fields["isDisabled"] = False
            host.update(fields)
            return 200, copy.deepcopy(host)
        if method == "POST" and path in ("/hosts/bulk/disable", "/hosts/bulk/enable"):
            body = self._body(data, {"uuids": list})
            for ref in body["uuids"]:
                self._find(self.hosts, ref, "host")["isDisabled"] = path.endswith("disable")
            if self.major >= 3:
                return 204, None
            return 200, [copy.deepcopy(self._find(self.hosts, r, "host")) for r in body["uuids"]]
        if method == "DELETE" and path.startswith("/hosts/"):
            ref = path.rsplit("/", 1)[1]
            self._find(self.hosts, ref, "host")
            self.hosts = [h for h in self.hosts if h["uuid"] != ref]
            return self._deleted()
        if method == "GET" and path == "/subscription-templates":
            listing = [{k: v for k, v in t.items() if k != "templateJson"} for t in self.templates]
            return 200, {"total": len(listing), "templates": copy.deepcopy(listing)}
        if method == "GET" and path.startswith("/subscription-templates/"):
            ref = path.rsplit("/", 1)[1]
            return 200, copy.deepcopy(self._find(self.templates, ref, "template"))
        if method == "POST" and path == "/subscription-templates":
            body = self._body(data, {"name": str, "templateType": str})
            if body["templateType"] != "XRAY_JSON":
                raise ContractError("templateType must be XRAY_JSON")
            if not TEMPLATE_NAME.fullmatch(body["name"]):
                raise ContractError("Name can only contain letters, numbers, underscores, dashes "
                                    "and spaces")  # fmt: skip
            if any(t["name"] == body["name"] for t in self.templates):
                return 409, {"message": "template name exists"}
            item = {
                "uuid": new_uuid(),
                "name": body["name"],
                "templateType": "XRAY_JSON",
                "templateJson": {},
            }
            self.templates.append(item)
            return 200, copy.deepcopy(item)
        if method == "PATCH" and path == "/subscription-templates":
            body = self._body(data, {"uuid": str, "templateJson": dict})
            item = self._find(self.templates, body["uuid"], "template")
            item["templateJson"] = copy.deepcopy(body["templateJson"])
            return 200, copy.deepcopy(item)
        if method == "GET" and path == "/internal-squads":
            return 200, {"total": len(self.squads), "internalSquads": copy.deepcopy(self.squads)}
        if method == "PATCH" and path == "/internal-squads":
            body = self._body(data, {"uuid": str, "inbounds": list})
            squad = self._find(self.squads, body["uuid"], "squad")
            known = {i["uuid"]: i for p in self.profiles for i in p.get("inbounds", [])}
            for ref in body["inbounds"]:
                if ref not in known:
                    raise ContractError(f"unknown inbound {ref}")
            squad["inbounds"] = [copy.deepcopy(known[r]) for r in body["inbounds"]]
            return 200, copy.deepcopy(squad)
        if method == "GET" and path == "/subscription-settings":
            return 200, copy.deepcopy(self.sub_settings)
        if method == "PATCH" and path == "/subscription-settings":
            body = self._body(data, {"uuid": str, "customResponseHeaders": dict})
            if body["uuid"] != self.sub_settings["uuid"]:
                raise ContractError("unknown subscription settings")
            self.sub_settings["customResponseHeaders"] = copy.deepcopy(
                body["customResponseHeaders"]
            )
            return 200, copy.deepcopy(self.sub_settings)
        return 404, {"message": f"no route {method} {path}"}

    def _tokens(self, method: str, path: str, data: Any) -> tuple[int, Any]:
        """API tokens as 2.8.1 and 3.4.11 make and delete them; `_refusal` already let only
        the admin login token with the browser header through (K30)."""
        if method == "POST" and path == "/tokens":
            if not isinstance(data, dict) or set(data) - {"name", "expiresInDays", "scopes"}:
                raise ContractError("body must be {name, expiresInDays, scopes}")
            name, days = data.get("name"), data.get("expiresInDays")
            if not isinstance(name, str) or not 2 <= len(name) <= 30:
                raise ContractError("name must be 2 to 30 characters")
            if isinstance(days, bool) or not isinstance(days, (int, float)) or days < 1:
                raise ContractError("expiresInDays must be a number of at least 1")
            scopes = data.get("scopes", ["*"])
            if not isinstance(scopes, list) or not all(isinstance(x, str) for x in scopes):
                raise ContractError("scopes must be a list of strings")
            if any(scope not in VALID_SCOPES for scope in scopes):
                return 400, dict(BAD_SCOPE)
            uuid, token = str(uuidlib.uuid4()), "rw-" + secrets.token_hex(24)
            self.made_token(uuid, token, name, int(days), scopes)
            stamp = "2026-11-27T12:00:00.000Z"
            return 201, {"uuid": uuid, "name": name, "expireAt": stamp, "scopes": list(scopes),
                         "createdAt": stamp, "updatedAt": stamp, "token": token}  # fmt: skip
        if method == "DELETE" and path.count("/") == 2:
            ref = path.rsplit("/", 1)[1]
            made = self.made_tokens.pop(ref, None)
            if made is None:
                return 404, dict(TOKEN_NOT_FOUND)
            self.api_tokens.pop(made["token"], None)
            return (204, None) if self.major >= 3 else (200, True)
        if method == "GET" and path == "/tokens":
            listing = [{"uuid": u, "name": m["name"], "scopes": m["scopes"]}
                       for u, m in self.made_tokens.items()]  # fmt: skip
            return 200, {"apiKeys": listing}
        return 404, {"message": f"no route {method} {path}"}

    def _taken_tags(self, config: dict, own: Optional[str]) -> list:
        """Tags of the config that another profile already has: unique across the panel
        (`@@unique([tag])` of ConfigProfileInbounds in 2.8.1 and 3.4.11)."""
        others = {i["tag"] for p in self.profiles if p["uuid"] != own for i in p["inbounds"]}
        return [i.get("tag") for i in config.get("inbounds") or []
                if isinstance(i, dict) and i.get("tag") in others]  # fmt: skip

    def _create_profile(self, data: Any) -> tuple[int, Any]:
        """POST /config-profiles as 2.8.1 and 3.4.11 answer it (K24)."""
        body = self._body(data, {"name": str, "config": dict})
        if not PROFILE_NAME.fullmatch(body["name"]):
            raise ContractError("Name can only contain letters, numbers, underscores, dashes and "
                                "spaces, 2 to 30 characters")  # fmt: skip
        if body["name"] == "Default-Profile":
            return 400, {"message": "This name is reserved by Remnawave.", "errorCode": "A145"}
        inbounds = body["config"].get("inbounds")
        tags = [i.get("tag") for i in inbounds or [] if isinstance(i, dict)]
        if not inbounds or not all(isinstance(t, str) and t and "," not in t for t in tags) \
                or len(set(tags)) != len(tags):  # fmt: skip
            # XRayConfig throws, the service answers its generic error.
            return 500, {"message": "Create config profile error", "errorCode": "A112"}
        if any(p["name"] == body["name"] for p in self.profiles):
            return 409, {"message": "Config profile name already exists", "errorCode": "A114"}
        if self._taken_tags(body["config"], None):
            return 409, dict(TAG_TAKEN)
        config = copy.deepcopy(body["config"])
        profile = {"uuid": new_uuid(), "name": body["name"], "inbounds": [],
                   "config": self.normalize_profile(config) if self.normalize_profile
                   else config}  # fmt: skip
        self._sync_inbounds(profile)
        self.profiles.append(profile)
        return 200, {**copy.deepcopy(profile), "nodes": []}

    def _delete_profile(self, ref: str) -> tuple[int, Any]:
        """The panel stops the nodes of the profile (they keep no profile: SetNull), its
        hosts lose the profile but stay, its inbounds leave the squads (cascade)."""
        profile = self._find(self.profiles, ref, "config profile")
        gone = {i["uuid"] for i in profile["inbounds"]}
        for node in self.nodes:
            if (node.get("configProfile") or {}).get("activeConfigProfileUuid") == ref:
                node["configProfile"] = {"activeConfigProfileUuid": None, "activeInbounds": []}
                node["isConnected"] = False
        for host in self.hosts:
            if (host.get("inbound") or {}).get("configProfileUuid") == ref:
                host["inbound"] = {"configProfileUuid": None, "configProfileInboundUuid": None}
        for squad in self.squads:
            squad["inbounds"] = [
                i
                for i in squad.get("inbounds") or []
                if (i.get("uuid") if isinstance(i, dict) else i) not in gone
            ]
        self.profiles = [p for p in self.profiles if p["uuid"] != ref]
        return self._deleted()

    def _patch_node(self, data: Any) -> tuple[int, Any]:
        """Only the inbounds a node runs (K20): the list is replaced as a whole, every inbound
        must be one of the profile's, and the node restarts (the fake keeps it connected)."""
        body = self._body(data, {"uuid": str, "configProfile": dict})
        node = self._find(self.nodes, body["uuid"], "node")
        ref = body["configProfile"]
        if set(ref) != {"activeConfigProfileUuid", "activeInbounds"}:
            raise ContractError("configProfile needs activeConfigProfileUuid and activeInbounds")
        profile = self._find(self.profiles, ref["activeConfigProfileUuid"], "config profile")
        uuids = ref["activeInbounds"]
        if not isinstance(uuids, list) or not all(isinstance(u, str) for u in uuids):
            raise ContractError("activeInbounds must be a list of uuids")
        inbounds = {i["uuid"]: i for i in profile["inbounds"]}
        if any(u not in inbounds for u in uuids):
            return 404, {"message": "Config profile inbound not found in specified profile",
                         "errorCode": "A124"}  # fmt: skip
        node["configProfile"] = {
            "activeConfigProfileUuid": profile["uuid"],
            "activeInbounds": [{"uuid": u, "tag": inbounds[u]["tag"]} for u in uuids],
        }
        return 200, copy.deepcopy(node)

    # -- contract checks -------------------------------------------------
    @staticmethod
    def _body(data: Any, fields: dict) -> dict:
        if not isinstance(data, dict):
            raise ContractError("body must be an object")
        extra = set(data) - set(fields)
        if extra:
            raise ContractError(f"unknown fields {sorted(extra)}")
        for name, kind in fields.items():
            value = data.get(name)
            if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
                raise ContractError(f"{name} must be {kind.__name__}")
        return data

    @staticmethod
    def _find(items: list, ref: str, what: str) -> dict:
        for item in items:
            if item.get("uuid") == ref:
                return item
        raise ContractError(f"unknown {what} {ref}")

    def _host_fields(self, data: Any, create: bool) -> dict:
        if not isinstance(data, dict):
            raise ContractError("host must be an object")
        allowed = COMMON_HOST_FIELDS | SHAPE_FIELDS[self.shape]
        extra = set(data) - allowed
        if extra:
            raise ContractError(f"unknown host fields {sorted(extra)}")
        if create:
            for name in ("remark", "address", "port", "inbound"):
                if name not in data:
                    raise ContractError(f"{name} is required")
        if "remark" in data:
            limit = 100 if self.major >= 3 else 40
            remark = data["remark"]
            # zod counts UTF-16 code units: a flag emoji is four of them.
            if (
                not isinstance(remark, str)
                or not 1 <= len(remark.encode("utf-16-le")) // 2 <= limit
            ):
                raise ContractError(f"Remark must be 1 to {limit} characters")
        if "inbound" in data:
            ref = data["inbound"]
            if not isinstance(ref, dict):
                raise ContractError("inbound must be an object")
            profile = self._find(self.profiles, ref.get("configProfileUuid"), "config profile")
            if not any(
                i["uuid"] == ref.get("configProfileInboundUuid")
                for i in profile.get("inbounds", [])
            ):
                raise ContractError("unknown inbound of the profile")
        if "sni" in data and data["sni"] is None:
            raise ContractError("sni must be a string: clear it with an empty string")
        if self.shape == "tags" and "tags" in data:
            tags = data["tags"]
            if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
                raise ContractError("tags must be a list of strings")
            if len(tags) > 10:
                raise ContractError("Maximum 10 tags")
            for tag in tags:
                _check_tag(tag, 36)
        if self.shape == "tag" and data.get("tag") is not None:
            _check_tag(data["tag"], 32)  # 2.2–2.7: one tag of up to 32 characters
        if "port" in data and (not isinstance(data["port"], int) or isinstance(data["port"], bool)):
            raise ContractError("port must be a number")
        return copy.deepcopy(data)

    @staticmethod
    def _sync_inbounds(profile: dict) -> None:
        """Inbounds follow the config by tag; known tags keep their uuid."""
        by_tag = {i["tag"]: i for i in profile.get("inbounds", [])}
        result = []
        for raw in profile["config"].get("inbounds") or []:
            if not isinstance(raw, dict) or not isinstance(raw.get("tag"), str):
                raise ContractError("inbound without a tag")
            known = by_tag.get(raw["tag"])
            stream = raw.get("streamSettings") or {}
            result.append(
                {
                    "uuid": known["uuid"] if known else new_uuid(),
                    "profileUuid": profile["uuid"],
                    "tag": raw["tag"],
                    "type": raw.get("protocol", ""),
                    "network": stream.get("network"),
                    "security": stream.get("security"),
                    "port": raw.get("port"),
                }
            )
        profile["inbounds"] = result


def _check_tag(tag: str, limit: int) -> None:
    if not re.fullmatch(r"[A-Z0-9_:]+", tag):
        raise ContractError(f"tag {tag!r} does not match ^[A-Z0-9_:]+$")
    if len(tag) > limit:
        raise ContractError(f"tag {tag!r}: each tag must be less than {limit} characters")


# -- builders of raw panel objects (tests and the demo fleet) ----------------
def raw_profile(name: str, config: dict) -> dict:
    profile = {"uuid": new_uuid(), "name": name, "config": copy.deepcopy(config), "inbounds": []}
    FakePanel._sync_inbounds(profile)
    return profile


def raw_node(
    name: str,
    address: str,
    country: str,
    profile: Optional[dict],
    *,
    port: int = 2222,
    connected: bool = True,
    disabled: bool = False,
    users: int = 0,
) -> dict:
    return {
        "uuid": new_uuid(),
        "name": name,
        "address": address,
        "port": port,
        "isConnected": connected,
        "isDisabled": disabled,
        "countryCode": country,
        "usersOnline": users,
        "configProfile": {
            "activeConfigProfileUuid": profile["uuid"] if profile else None,
            "activeInbounds": [{"uuid": i["uuid"], "tag": i["tag"]} for i in profile["inbounds"]]
            if profile
            else [],
        },
    }


def raw_host(
    shape: str,
    profile: dict,
    inbound_tag: str,
    remark: str,
    address: str,
    *,
    sni: str = "",
    port: int = 443,
    fingerprint: str = "",
    tags: Optional[list[str]] = None,
    hidden: bool = False,
    disabled: bool = False,
    extra: Optional[dict] = None,
    template_uuid: Optional[str] = None,
    position: int = 0,
) -> dict:
    inbound = next(i for i in profile["inbounds"] if i["tag"] == inbound_tag)
    host = {
        "uuid": new_uuid(),
        "viewPosition": position,
        "remark": remark,
        "address": address,
        "port": port,
        "path": "",
        "sni": sni,
        "host": "",
        "alpn": None,
        "fingerprint": fingerprint,
        "isDisabled": disabled,
        "securityLayer": "DEFAULT",
        "muxParams": None,
        "sockoptParams": None,
        "inbound": {
            "configProfileUuid": profile["uuid"],
            "configProfileInboundUuid": inbound["uuid"],
        },
        "serverDescription": None,
        "isHidden": hidden,
        "overrideSniFromAddress": False,
        "keepSniBlank": False,
        "allowInsecure": False,
        "shuffleHost": False,
        "mihomoX25519": False,
        "nodes": [],
        "xrayJsonTemplateUuid": template_uuid,
        "excludedInternalSquads": [],
    }
    if shape == "tags":
        host["tags"] = list(tags or [])
        host["xhttpExtraParams"] = extra
    else:
        host["tag"] = (tags or [None])[0]
        host["xHttpExtraParams"] = extra
    return host
