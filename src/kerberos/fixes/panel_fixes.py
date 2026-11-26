"""Fixes in the panel (tech.md §10.5, §10.9): templates, hosts, settings, reserves.

Each is a journaled change with a snapshot of what it touches, so rollback
can put the objects back. Templates of the person are never edited: hosts
move to the KERBEROS templates instead.
"""

from __future__ import annotations

import random
import uuid as uuidlib
from typing import Any, Optional

from kerberos.fixes import subscription, xhttp
from kerberos.fixes.journal import iso
from kerberos.fixes.model import ROLLBACK_FAILED, Change, is_applied
from kerberos.fixes.panel_changes import diff_text, digest, load_snapshot, save_snapshot, undo
from kerberos.panel.errors import PanelError

PANEL_ITEMS = {
    "sub.template",
    "sub.ping_type",
    "host.fingerprint",
    "reserve",
    "xhttp.padding",
    "xhttp.uplink_get",
}
PING_TYPE = "proxy-head"


class Refused(Exception):
    """The fix cannot run as planned; nothing was written. `code` goes to the journal."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PanelFixes:
    """Panel changes of one run; the KERBEROS templates are made once and shared."""

    def __init__(self, engine: Any) -> None:
        self.engine = engine
        self.env = engine.env
        self.session = engine.session
        self.client = self.session.panel
        self._templates: Optional[dict] = None
        self.current: Optional[Change] = None  # the change a failing step belongs to

    # -- journal -------------------------------------------------------------
    def change(self, fix_id: str, target: str, params: Optional[dict] = None) -> Change:
        change: Change = {
            "changeId": str(uuidlib.uuid4()),
            "fixId": fix_id,
            "target": target,
            "state": "applying",
            "params": params or {},
            "before": None,
            "details": {},
            "error": None,
            "startedAt": iso(self.env.clock),
            "finishedAt": None,
        }
        self.engine.run["changes"].append(change)
        self.engine.save()
        self.current = change
        return change

    def snapshot(self, change: Change, name: str, value: Any) -> None:
        change["before"] = save_snapshot(self.engine.store, self.engine.run["runId"], name, value)
        self.engine.save()

    # -- the two KERBEROS templates (§10.9) ----------------------------------
    def fleet_domains(self) -> list[str]:
        data = self.session.data["input"]
        domains = []
        for item in data.nodes:
            domains += data.own_domains(item)
        for change in self.engine.run["changes"]:
            if change["fixId"] == "self_steal.site" and is_applied(change):
                domains.append(change["params"].get("domain", ""))
        return [d for d in dict.fromkeys(domains) if d]

    def templates(self) -> dict:
        """{"reserve": uuid, "single": uuid}, created or brought up to date once per run."""
        if self._templates is not None:
            return self._templates
        change = self.change("sub.templates", "panel")
        details: dict = {"templates": {}}
        change["details"] = details
        result = {}
        try:
            existing = {t.name: t for t in self.client.templates()}
            for kind, name in (("reserve", subscription.RESERVE_NAME),
                               ("single", subscription.SINGLE_NAME)):  # fmt: skip
                wanted = subscription.build(kind, self.fleet_domains())
                current = existing.get(name)
                if current is None:
                    current = self.client.create_template(name)
                    details["templates"][current.uuid] = {"created": True, "previousPath": None}
                    self.engine.save()
                else:
                    current = self.client.template(current.uuid)
                    if current.json == wanted:
                        result[kind] = current.uuid
                        continue
                    path = save_snapshot(self.engine.store, self.engine.run["runId"],
                                         f"template-{current.uuid}", current.json)  # fmt: skip
                    details["templates"][current.uuid] = {"created": False, "previousPath": path}
                    self.engine.save()
                    edited = current.json and not subscription.own_write(kind, current.json)
                    if edited and not self.engine.ask_diff(diff_text(wanted, current.json)):
                        result[kind] = current.uuid  # the person keeps their edits
                        continue
                # What is about to be written, before the PATCH: a rollback compares the
                # panel with it, also when the answer to the PATCH never came.
                details["templates"][current.uuid].update(
                    written=digest(wanted),
                    writtenPath=save_snapshot(self.engine.store, self.engine.run["runId"],
                                              f"template-{current.uuid}-written", wanted),
                )  # fmt: skip
                self.engine.save()
                self.client.patch_template(current.uuid, wanted)
                result[kind] = current.uuid
        except Exception as exc:
            # §10.5: a template written already goes back before the error goes on.
            self.settle(change, exc.code if isinstance(exc, PanelError) else "internal_error")
            raise
        self.engine.finish(change, "applied")
        self._templates = result
        return result

    # -- one plan item ---------------------------------------------------------
    def run(self, item: Any) -> bool:
        handler = {
            "sub.template": self.sub_template,
            "sub.ping_type": self.ping_type,
            "host.fingerprint": self.fingerprint,
            "reserve": self.reserve,
            "xhttp.padding": self.padding,
            "xhttp.uplink_get": self.uplink,
        }[item.fix_id]
        self.engine.event("backup", item, "running")
        self.current = None
        try:
            change = handler(item)
        except Refused as exc:
            if self.current is not None:
                self.engine.finish(self.current, "failed", exc.code)
            self.engine.failed += 1
            self.engine.event("apply", item, "failed", exc.code)
            return False
        except PanelError as exc:
            self.fail(item, exc.code)
            return False
        self.engine.event("backup", item, "ok")
        self.engine.event("apply", item, "ok")
        self.engine.event("confirm", item, "skipped")
        if not self.recheck(item, change):
            rolled = self.settle(change, "recheck_failed")
            self.engine.event("check", item, "rolled_back" if rolled else "failed",
                              "recheck_failed" if rolled else ROLLBACK_FAILED)  # fmt: skip
            return False
        self.engine.event("check", item, "ok")
        self.engine.finish(change, "applied")
        return True

    def settle(self, change: Change, code: str) -> bool:
        """What a failed change wrote goes back (§10.5); False: that failed too."""
        rolled = self.engine.settle(change, code, undo(self.client, change,
                                                       ask=self.engine.ask_undo))  # fmt: skip
        if rolled:
            self.engine.failed += 1
        return rolled

    def fail(self, item: Any, code: str) -> None:
        """A step of the fix failed: the change it belongs to is undone and finished."""
        change = self.current
        if change is not None and change["finishedAt"] is None:
            rolled = self.settle(change, code)
        elif change is None:
            self.engine.failed += 1
            rolled = True
        else:
            # Finished already (the shared templates): counted when it was settled.
            rolled = change.get("error") != ROLLBACK_FAILED
        self.engine.event("apply", item, "failed", code if rolled else ROLLBACK_FAILED)

    def abandon(self, item: Any, exc: BaseException) -> None:
        """Not a panel error (a bug, a template that cannot be filled): never left half done."""
        self.engine.store.log(self.engine.run, f"{item.fix_id}: internal error "
                                               f"{type(exc).__name__}")  # fmt: skip
        self.fail(item, "internal_error")

    def guarded(self, change: Change, action) -> Any:
        """A panel call of a change; a failure is undone and finished by `run`."""
        return action()

    def sub_template(self, item: Any) -> Change:
        """§10.5: hosts with the finding move to a KERBEROS template; theirs stay intact."""
        templates = self.templates()
        params = {"hosts": list(item.params["hosts"]), "name": item.params.get("name", "")}
        change = self.change("sub.template", item.target, params)
        hosts = {h.uuid: h for h in self.guarded(change, self.client.hosts)}
        previous = {u: hosts[u].template_uuid for u in item.params["hosts"] if u in hosts}
        self.snapshot(change, f"hosts-{change['changeId'][:8]}", previous)
        paired = set(item.params.get("paired", []))
        written = {u: templates["reserve" if u in paired else "single"] for u in previous}
        change["details"] = {"hosts": previous, "written": written}
        self.engine.save()
        for host_uuid, template in written.items():
            self.guarded(change, lambda u=host_uuid, w=template: self.client.patch_host(
                u, {"xrayJsonTemplateUuid": w}))  # fmt: skip
        return change

    def ping_type(self, item: Any) -> Change:
        """§10.5: read, merge, write: PATCH replaces the whole header object."""
        change = self.change("sub.ping_type", "panel")
        settings = self.guarded(change, self.client.sub_settings)
        self.snapshot(change, "subscription-settings", {"uuid": settings.uuid,
                                                        "headers": settings.headers})  # fmt: skip
        change["details"] = {"uuid": settings.uuid, "previous": dict(settings.headers)}
        headers = dict(settings.headers)
        headers["ping-type"] = PING_TYPE
        self.guarded(change, lambda: self.client.patch_sub_settings(settings.uuid, headers))
        return change

    def fingerprint(self, item: Any) -> Change:
        host_uuid = item.params["host"]
        params = {"host": host_uuid, "remark": item.params.get("remark", "")}
        change = self.change("host.fingerprint", item.target, params)
        hosts = {h.uuid: h for h in self.guarded(change, self.client.hosts)}
        change["details"] = {"previous": hosts[host_uuid].fingerprint if host_uuid in hosts else ""}
        self.guarded(change, lambda: self.client.patch_host(host_uuid, {"fingerprint": "firefox"}))
        return change

    def reserve(self, item: Any) -> Change:
        """§10.9: copies of the main and of the reserve share tags; the reserve's are hidden."""
        main, spare = item.node_uuid, item.params["reserve"]
        params = {"reserve": spare, "node": main}
        code, hosts = self.pair_problem(item), None
        if code is None:
            hosts = {h.uuid: h for h in self.client.hosts()}
            if not any(u in hosts for u in self.copies_of(main)) or not any(
                u in hosts for u in self.copies_of(spare)
            ):
                code = "pair_not_ready"
        if code is not None:
            # Nothing is written: hiding the reserve's copies without a main that injects
            # them would take the reserve out of every subscription.
            self.change("reserve", item.target, params)
            raise Refused(code)
        templates = self.templates()
        change = self.change("reserve", item.target, params)
        main_name = self.session.snapshot.node(main).name
        tags = subscription.pair_tags(main_name)
        plan = {}
        for node_uuid, hidden in ((main, False), (spare, True)):
            for host_uuid in self.copies_of(node_uuid):
                host = hosts.get(host_uuid)
                if host is None:
                    continue
                kind = "hysteria" if self.is_hysteria(host) else "vless"
                plan[host_uuid] = ({"tags": host.tags, "isHidden": host.is_hidden,
                                    "xrayJsonTemplateUuid": host.template_uuid},
                                   {"tags": [tags[kind]], "isHidden": hidden,
                                    "xrayJsonTemplateUuid": templates["reserve"]})  # fmt: skip
        previous = {u: before for u, (before, _after) in plan.items()}
        self.snapshot(change, f"reserve-{main[:8]}", previous)
        change["details"] = {
            "hosts": previous,
            "tags": tags,
            "written": {u: after for u, (_before, after) in plan.items()},
        }
        self.engine.save()
        for host_uuid, (_before, after) in plan.items():
            self.guarded(change, lambda u=host_uuid, a=after: self.client.patch_host(u, a))
        return change

    def pair_problem(self, item: Any) -> Optional[str]:
        """Why a reserve pair cannot be linked now; None when it can."""
        main, spare = item.node_uuid, item.params["reserve"]
        for other in self.engine.queue:
            if other is item or other.fix_id != "reserve":
                continue
            # A chain A→B→C: B would be a hidden reserve and a visible main at once.
            if main == other.params.get("reserve") or spare in (
                other.node_uuid,
                other.params.get("reserve"),
            ):
                return "reserve_chain"
        if not self.copies_of(main) or not self.copies_of(spare):
            return "pair_not_ready"
        return None

    def copies_of(self, node_uuid: str) -> list[str]:
        """Host copies a self-steal of this run made for the node and kept."""
        for change in self.engine.run["changes"]:
            if (
                change["fixId"] == "self_steal.hosts"
                and is_applied(change)
                and (change["params"].get("node") == node_uuid)
            ):
                return list(change["details"].get("created", []))
        return []

    def is_hysteria(self, host: Any) -> bool:
        for profile in self.session.snapshot.profiles:
            for inbound in profile.inbounds:
                if inbound.uuid == host.inbound_uuid:
                    return inbound.type in ("hysteria", "hysteria2")
        return False

    def padding(self, item: Any) -> Change:
        """§10.6: one set of padding fields in the inbound and in every host of it."""
        node_uuid = item.params["node"]
        params = {"node": node_uuid, "inbounds": list(item.params["inbounds"])}
        change = self.change("xhttp.padding", item.target, params)
        node = self.session.snapshot.node(node_uuid)
        profiles = {p.uuid: p for p in self.client.profiles()}
        profile = profiles.get(node.profile_uuid if node else None)
        if profile is None:
            raise PanelError("bad_response", "the node has no profile")
        rng = random.Random(node_uuid) if self.env.demo else random.SystemRandom()
        config, written = xhttp.add_padding(profile.config, params["inbounds"], rng)
        uuids = {i.uuid: i.tag for i in profile.inbounds if i.tag in written}
        hosts = [h for h in self.client.hosts() if h.inbound_uuid in uuids]
        change["details"] = {"profileUuid": profile.uuid, "inbounds": sorted(written),
                             "hosts": {h.uuid: uuids[h.inbound_uuid] for h in hosts}}  # fmt: skip
        if not written:
            self.engine.save()
            return change
        self.snapshot(change, f"profile-{profile.uuid}-padding",
                      {"uuid": profile.uuid, "config": profile.config})  # fmt: skip
        # The written values live in a 0600 file, like every panel snapshot.
        change["details"]["writtenPath"] = save_snapshot(
            self.engine.store, self.engine.run["runId"], f"padding-{change['changeId'][:8]}",
            written)  # fmt: skip
        self.engine.save()
        self.client.patch_profile(profile.uuid, config)
        for host in hosts:
            if xhttp.own_extra(host.xhttp_extra) is None:
                continue  # it hands out the inbound's extra, padding included (§10.6)
            fields = written[uuids[host.inbound_uuid]]
            self.client.patch_host(host.uuid,
                                   {"xhttpExtraParams": xhttp.with_padding(host.xhttp_extra,
                                                                           fields)})  # fmt: skip
        return change

    def uplink(self, item: Any) -> Change:
        """§10.6: only the host's extra: uploads go as GET, which the CDN lets through.

        A host without its own extra hands out the inbound's: it gets a copy of that
        with the method, or it would lose the inbound's other fields.
        """
        host_uuid = item.params["host"]
        params = {"host": host_uuid, "remark": item.params.get("remark", "")}
        change = self.change("xhttp.uplink_get", item.target, params)
        host = next((h for h in self.client.hosts() if h.uuid == host_uuid), None)
        if host is None:
            raise PanelError("bad_response", "the host is gone")
        inbound = self.inbound_extra(host.inbound_uuid)
        own = xhttp.own_extra(host.xhttp_extra)
        written = xhttp.uplink_get(own if own is not None else inbound)
        previous = (xhttp.effective(host.xhttp_extra, inbound) or {}).get("uplinkHTTPMethod")
        # The extras may carry padding values: 0600 snapshots, never run.json (§10.6).
        self.snapshot(change, f"host-{host_uuid[:8]}-extra", {"extra": host.xhttp_extra})
        change["details"] = {
            "previous": previous,
            "extraWasNone": own is None,
            "writtenPath": save_snapshot(self.engine.store, self.engine.run["runId"],
                                         f"host-{host_uuid[:8]}-extra-written", written),
        }  # fmt: skip
        self.engine.save()
        self.client.patch_host(host_uuid, {"xhttpExtraParams": written})
        return change

    def inbound_extra(self, inbound_uuid: Optional[str]) -> Optional[dict]:
        """The extra of the inbound a host belongs to, as the panel holds it now."""
        for profile in self.client.profiles():
            for inbound in profile.inbounds:
                if inbound.uuid == inbound_uuid:
                    return xhttp.inbound_extra(profile.inbound_config(inbound.tag))
        return None

    # -- checking again --------------------------------------------------------
    def recheck(self, item: Any, change: Change) -> bool:
        try:
            if item.fix_id == "sub.ping_type":
                headers = self.client.sub_settings().headers
                return any(k.lower() == "ping-type" for k in headers)
            hosts = {h.uuid: h for h in self.client.hosts()}
            if item.fix_id == "host.fingerprint":
                host = hosts.get(item.params["host"])
                return bool(host and host.fingerprint)
            if item.fix_id == "sub.template":
                wanted = set(self.templates().values())
                return all(hosts[u].template_uuid in wanted for u in change["details"]["hosts"]
                           if u in hosts)  # fmt: skip
            if item.fix_id == "reserve":
                for host_uuid in change["details"]["hosts"]:
                    host = hosts.get(host_uuid)
                    if host is None or not set(host.tags) & set(change["details"]["tags"].values()):
                        return False
                return True
            if item.fix_id == "xhttp.uplink_get":
                host = hosts.get(item.params["host"])
                return bool(host and (host.xhttp_extra or {}).get("uplinkHTTPMethod") == "GET")
            if item.fix_id == "xhttp.padding":
                return self.padding_matches(change, hosts)
        except PanelError:
            return False
        return True

    def padding_matches(self, change: Change, hosts: dict) -> bool:
        """The server and every client of the inbound carry the same padding fields."""
        details = change["details"]
        if not details["inbounds"]:
            return True
        written = load_snapshot(details.get("writtenPath")) or {}
        profile = next((p for p in self.client.profiles() if p.uuid == details["profileUuid"]),
                       None)  # fmt: skip
        if profile is None:
            return False
        for tag in details["inbounds"]:
            server_extra = xhttp.inbound_extra(profile.inbound_config(tag))
            server = xhttp.padding_of(server_extra)
            if not server or server != written.get(tag):
                return False
            for host_uuid, host_tag in details["hosts"].items():
                host = hosts.get(host_uuid)
                if host_tag != tag:
                    continue
                # A client gets its host's extra, or the inbound's when the host has none.
                if (
                    host is None
                    or xhttp.padding_of(xhttp.effective(host.xhttp_extra, server_extra)) != server
                ):
                    return False
        return True
