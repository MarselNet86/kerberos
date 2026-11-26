"""Self-steal of one node (tech.md §10.4): own domain, copies of hosts, old ones off.

Steps, each a journaled change: the site and certificate on the node; the
letsencrypt volume if the node container lacks it; the profile from the
template; its new inbound switched on at the node (the panel runs only the
inbounds active there); the new inbound in the squads; copies of hosts with the new SNI,
then the old hosts disabled (never before the copies exist); a check from
the panel server. A failure undoes what was done, in reverse order: the step
caught half way first. A change that cannot be undone keeps the state it
reached, with error `rollback_failed`.
"""

from __future__ import annotations

import copy
import random
import uuid
from datetime import timedelta
from typing import Any, Optional

from kerberos.checks import is_ip, spec
from kerberos.fixes.hosts import copy_fields, fit_remark, fresh_host, hysteria_host, mismatches
from kerberos.fixes.journal import iso
from kerberos.fixes.model import ROLLBACK_FAILED, Change
from kerberos.fixes.own_profile import fresh_remark, profile_name, running_configs, template_pair
from kerberos.fixes.panel_changes import digest, save_snapshot, undo
from kerberos.fixes.profile import build_profile, server_names, template_tags
from kerberos.nodes import schema
from kerberos.nodes.transport import NodeAgentError, TransportError
from kerberos.panel.errors import PanelError
from kerberos.probe import HttpResult

FINALIZE_AFTER = timedelta(hours=24)
CHECK_ATTEMPTS = 6
CHECK_PAUSE = 5
AGENT_STEPS = ("self_steal.site", "node.letsencrypt_mount")
# The step-5 check judges these findings, and reality.foreign_sni only for the inbounds
# this self-steal changed: another inbound of the person keeps its own SNI.
CHECKED = ("reality.foreign_sni", "probe.no_sni")


class StepFailed(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SelfSteal:
    def __init__(self, engine: Any, item: Any) -> None:
        self.engine = engine
        self.env = engine.env
        self.session = engine.session
        self.item = item
        self.client = self.session.panel
        self.node = self.session.snapshot.node(item.node_uuid)
        self.target = engine.target(item.node_uuid)
        self.domain = item.params["domain"]
        self.done: list[Change] = []
        self.current: Optional[Change] = None  # a panel change caught half way
        self.changed: set = set()  # tags of the Reality inbounds this self-steal changed
        self.clean = True  # False once a change could not be rolled back
        # The node's profile before the run: the shared one a node leaves (K24), whose hosts
        # are the node's only by binding or address.
        self.start_profile = self.session.snapshot.node_profile(self.node)
        self.start_inbounds = list(self.node.inbound_uuids)
        # Kept apart: the profile in memory follows the node once it moves.
        self.shared = self.start_profile is not None and len(self.start_profile.node_uuids) > 1
        self.source_map: dict[str, str] = {}  # inbound before -> the template's inbound now
        self.new_inbounds: list[str] = []  # the template's inbounds the profile did not have
        # Reality keys come from the system's secure source; the demo is repeatable.
        self.rng = random.Random(item.node_uuid) if self.env.demo else random.SystemRandom()

    # -- journal -------------------------------------------------------------
    def change(self, fix_id: str, target: str, params: Optional[dict] = None) -> Change:
        change: Change = {
            "changeId": str(uuid.uuid4()),
            "fixId": fix_id,
            "target": target,
            "state": "applying",
            "params": {**(params or {}), "node": self.node.uuid},
            "before": None,
            "details": {},
            "error": None,
            "startedAt": iso(self.env.clock),
            "finishedAt": None,
        }
        self.engine.run["changes"].append(change)
        self.current = change
        self.engine.save()
        return change

    def applied(self, change: Change) -> None:
        change["state"] = "applied"
        change["finishedAt"] = iso(self.env.clock)
        self.done.append(change)
        self.current = None
        self.engine.save()

    # -- steps ---------------------------------------------------------------
    def agent(self, fix_id: str, params: dict) -> dict:
        change = self.change(fix_id, self.item.target, params)
        try:
            answer = self.env.transport.agent(
                self.target, f"apply {fix_id} {change['changeId']}", params
            )
        except NodeAgentError as exc:
            self.current = None  # the agent put its files back itself
            self.engine.finish(change, "failed", exc.code)
            raise StepFailed(exc.code) from exc
        except TransportError as exc:
            self.current = None
            error = self.engine.rollback(self.target, change["changeId"], missing_ok=True)
            if not self.engine.settle(change, exc.kind, error, done="failed"):
                self.clean = False
            raise StepFailed(exc.kind) from exc
        change["details"] = dict(answer.get("details") or {})
        self.applied(change)
        return change["details"]

    @staticmethod
    def panel_call(action) -> Any:
        """A panel request of the current step; `undo_all` puts back what the step wrote."""
        try:
            return action()
        except PanelError as exc:
            raise StepFailed(exc.code) from exc

    def site(self) -> None:
        self.engine.event("apply", self.item, "running")
        params = {"domain": self.domain, "siteSeed": self.item.params.get("siteSeed", 0)}
        self.agent("self_steal.site", params)

    def mount(self) -> None:
        facts = (self.session.data["input"].node_data(self.node.uuid).facts) or {}
        if not (facts.get("remnanode") or {}).get("letsencryptMounted", True):
            self.agent("node.letsencrypt_mount", {})

    def profile(self) -> tuple:
        profile = self.session.snapshot.node_profile(self.node)
        change = self.change(
            "self_steal.profile", f"profile:{profile.uuid}", {"domain": self.domain}
        )
        profiles = self.panel_call(self.client.profiles)
        current = next(p for p in profiles if p.uuid == profile.uuid)
        run_id = self.engine.run["runId"]
        change["before"] = save_snapshot(
            self.engine.store,
            run_id,
            f"profile-{profile.uuid}",
            {"uuid": profile.uuid, "config": current.config},
        )
        # A new tag (Hysteria2 the node had not) must not repeat one of another profile (§7.4).
        taken = frozenset(i.tag for p in profiles if p.uuid != profile.uuid for i in p.inbounds)
        new = build_profile(current.config, self.node.name, self.domain, self.rng, taken=taken)
        tags = template_tags(new)
        self.changed = {tags["reality"]} - {None}
        written_path = save_snapshot(
            self.engine.store, run_id, f"profile-{profile.uuid}-written", new
        )
        change["details"] = {
            "profileUuid": profile.uuid,
            "domain": self.domain,
            "oldNames": [n for n in server_names(current.config) if n != self.domain],
            "written": digest(new),
            "writtenPath": written_path,
            "tags": tags,
        }
        self.engine.save()
        try:
            patched = self.panel_call(lambda: self.client.patch_profile(profile.uuid, new))
        except StepFailed:
            self.landed(change, profile.uuid, current.config)
            raise
        # The panel stores the config normalized: a rollback compares with what it holds.
        change["details"]["written"] = digest(patched.config)
        change["details"]["writtenPath"] = save_snapshot(
            self.engine.store, run_id, f"profile-{profile.uuid}-written", patched.config
        )
        self.engine.save()
        profile.config, profile.inbounds = patched.config, patched.inbounds
        self.applied(change)
        # The template's inbounds that were there keep their uuid, hosts and squads.
        before = {i.tag: i.uuid for i in current.inbounds}
        after = {i.tag: i.uuid for i in patched.inbounds}
        for tag in (tags["reality"], tags["hysteria"]):
            if tag in after and tag in before:
                self.source_map[before[tag]] = after[tag]
            elif tag in after:
                self.new_inbounds.append(after[tag])
        return patched, tags

    def own_profile(self) -> tuple:
        """K24: a node on a shared profile, or on none, gets a profile of its own. Tags are
        unique across the panel, so its inbounds are new; the Reality key, shortIds and old
        names of the shared profile come along (§10.4)."""
        name = self.item.params["ownProfile"]
        shared = self.start_profile
        change = self.change("self_steal.own_profile", self.item.target,
                             {"domain": self.domain, "profile": name})  # fmt: skip
        profiles = self.panel_call(self.client.profiles)
        now = next((p for p in profiles if shared is not None and p.uuid == shared.uuid), None)
        configs = running_configs(self.session.snapshot, self.node, now.config if now else None)
        reality, hysteria = template_pair(configs)
        taken = frozenset(i.tag for p in profiles for i in p.inbounds)
        subset = {"inbounds": [copy.deepcopy(i) for i in (reality, hysteria) if i is not None]}
        new = build_profile(subset, self.node.name, self.domain, self.rng, taken=taken,
                            fresh=True)  # fmt: skip
        tags = template_tags(new)
        self.changed = {tags["reality"]} - {None}
        names = {p.name for p in profiles}
        if name in names:  # taken since the plan was made
            name = profile_name(self.node.name, names)
            change["params"]["profile"] = name
        run_id = self.engine.run["runId"]
        # Journaled before the request: an answer that never comes still leaves the undo to
        # find the profile by its name. The config holds the Reality key: 0600, not run.json.
        change["details"] = {
            "profileUuid": None,
            "name": name,
            "sharedUuid": shared.uuid if shared else None,
            "domain": self.domain,
            "oldNames": [n for n in server_names(subset) if n != self.domain],
            "written": digest(new),
            "writtenPath": save_snapshot(self.engine.store, run_id,
                                         f"own-profile-{self.node.uuid}-written", new),
            "tags": tags,
        }  # fmt: skip
        self.engine.save()
        try:
            created = self.panel_call(lambda: self.client.create_profile(name, new))
        except StepFailed:
            self.found(change, name)
            raise
        self.created_profile(change, created)
        self.applied(change)
        old = {i.tag: i.uuid for i in (now.inbounds if now else [])}
        after = {i.tag: i.uuid for i in created.inbounds}
        for source, tag in ((reality, tags["reality"]), (hysteria, tags["hysteria"])):
            if tag not in after:
                continue
            if source is not None and source.get("tag") in old:
                self.source_map[old[source["tag"]]] = after[tag]
            self.new_inbounds.append(after[tag])
        # The check of step 5 judges the node on its own profile.
        self.session.snapshot.profiles.append(created)
        return created, tags

    def found(self, change: Change, name: str) -> None:
        """A POST whose answer failed may still have created the profile: the name is the
        panel's unique key, and the undo deletes what it finds."""
        try:
            now = next((p for p in self.client.profiles() if p.name == name), None)
        except PanelError:
            return
        if now is not None:
            self.created_profile(change, now)

    def created_profile(self, change: Change, created: Any) -> None:
        change["target"] = f"profile:{created.uuid}"
        change["details"]["profileUuid"] = created.uuid
        # The panel stores the config validated and sorted: the undo compares with that.
        change["details"]["written"] = digest(created.config)
        change["details"]["writtenPath"] = save_snapshot(
            self.engine.store, self.engine.run["runId"], f"profile-{created.uuid}-written",
            created.config,
        )  # fmt: skip
        self.engine.save()

    def landed(self, change: Change, uuid: str, before: dict) -> None:
        """A PATCH whose answer failed may still have landed, normalized by the panel: then
        what the panel holds is KERBEROS's write, and the undo puts the snapshot back."""
        try:
            now = next((p for p in self.client.profiles() if p.uuid == uuid), None)
        except PanelError:
            return
        if now is not None and digest(now.config) != digest(before):
            change["details"]["written"] = digest(now.config)
            change["details"]["writtenPath"] = save_snapshot(
                self.engine.store, self.engine.run["runId"], f"profile-{uuid}-written", now.config
            )
            self.engine.save()

    def activate(self, patched: Any, tags: dict) -> None:
        """The inbounds of the template run on the node (K20). Remnawave 2.8.1 and 3.4.11 run
        only `configProfile.activeInbounds` of a node, and a new inbound of the profile is
        active nowhere: without this Hysteria2 answers nobody while its hosts are handed out.
        A node that got its own profile (K24) moves onto it with the template's inbounds."""
        by_tag = {i.tag: i.uuid for i in patched.inbounds}
        wanted = [by_tag[t] for t in (tags["reality"], tags["hysteria"]) if t in by_tag]
        node = next((n for n in self.panel_call(self.client.nodes) if n.uuid == self.node.uuid),
                    None)  # fmt: skip
        if node is None:
            raise StepFailed("node_offline")
        own = self.item.params.get("ownProfile") is not None
        active = [] if own else list(node.inbound_uuids)
        added = [u for u in wanted if u not in active]
        if not added:
            return
        change = self.change("self_steal.node", self.item.target, {"domain": self.domain})
        # Journaled before the request: an answer that never comes still leaves the undo to
        # take out what KERBEROS added, and only that (§10.9).
        change["details"] = {"profileUuid": patched.uuid, "before": list(node.inbound_uuids),
                             "added": added}  # fmt: skip
        if own:
            change["details"]["beforeProfile"] = node.profile_uuid
        self.engine.save()
        answer = self.panel_call(
            lambda: self.client.patch_node_inbounds(node.uuid, patched.uuid, active + added)
        )
        if answer.profile_uuid != patched.uuid or any(u not in answer.inbound_uuids
                                                       for u in added):  # fmt: skip
            raise StepFailed("node_mismatch")
        self.node.inbound_uuids = list(answer.inbound_uuids)
        if own:
            self.node.profile_uuid = patched.uuid
            patched.node_uuids = [self.node.uuid]
            if self.start_profile is not None:
                self.start_profile.node_uuids = [u for u in self.start_profile.node_uuids
                                                 if u != self.node.uuid]  # fmt: skip
        self.applied(change)

    def squads(self, patched: Any, tags: dict) -> None:
        """New inbounds of the template go where the node's inbounds were (K24: before the
        node runs them, so its users are there when it restarts); with none, into the
        squads picked in S7, and then every inbound of the template (§10.4)."""
        chosen = self.item.params.get("squads")
        by_tag = {i.tag: i.uuid for i in patched.inbounds}
        template = [by_tag[t] for t in (tags["reality"], tags["hysteria"]) if t in by_tag]
        adds = template if chosen else list(self.new_inbounds)
        if not adds:
            return
        change = self.change("self_steal.squads", "panel", {"inbounds": adds})
        squads = self.panel_call(self.client.squads)
        touched = {}
        for squad in squads:
            hit = squad.uuid in chosen if chosen else bool(set(self.source_map)
                                                          & set(squad.inbound_uuids))  # fmt: skip
            if hit and any(u not in squad.inbound_uuids for u in adds):
                touched[squad.uuid] = list(squad.inbound_uuids)
        change["before"] = save_snapshot(
            self.engine.store, self.engine.run["runId"], f"squads-{self.node.uuid}", touched
        )
        # The uuids KERBEROS adds: a rollback takes out of each squad only those it lacked.
        change["details"] = {"squads": touched, "added": adds}
        self.engine.save()
        for squad_uuid, inbounds in touched.items():
            self.panel_call(
                lambda u=squad_uuid, i=inbounds: self.client.patch_squad(
                    u, i + [a for a in adds if a not in i]
                ),
            )
        self.applied(change)

    def hosts(self, patched: Any, tags: dict) -> None:
        change = self.change("self_steal.hosts", self.item.target, {"domain": self.domain})
        hosts = self.panel_call(self.client.hosts)
        by_tag = {i.tag: i for i in patched.inbounds}
        # §10.4 step 3: hosts of the inbounds the template replaced. Other inbounds of the
        # person (WebSocket, gRPC, a second Reality) keep their hosts and SNI.
        reality = by_tag.get(tags["reality"])
        hysteria = by_tag.get(tags["hysteria"])
        sources = [h for h in hosts
                   if h.inbound_uuid in self.source_map and not h.is_disabled
                   and self.belongs(h)]  # fmt: skip
        change["details"] = {"created": [], "disabled": [], "atEnd": True}
        self.engine.save()
        template = self.template_uuid()
        for source in sources:
            fields = copy_fields(source, self.domain, template_uuid=template)
            target = self.source_map[source.inbound_uuid]
            if target != source.inbound_uuid:  # the node's own profile (K24)
                fields["inbound"] = {"configProfileUuid": patched.uuid,
                                     "configProfileInboundUuid": target}  # fmt: skip
            self.create(change, fields)
        reality_sources = [
            h for h in sources if reality and self.source_map[h.inbound_uuid] == reality.uuid
        ]
        model = reality_sources[0] if reality_sources else None
        base = None
        if reality and model is None:
            # No Reality host to copy: the node gets one of KERBEROS's (K24).
            base = fresh_host(
                fresh_remark(self.node.country, self.node.name),
                self.node.address,
                reality.port or 443,
                self.domain,
                patched.uuid,
                reality.uuid,
            )
            base["xrayJsonTemplateUuid"] = template
            self.create(change, base)
        has_hy2_host = hysteria is not None and any(
            self.source_map[h.inbound_uuid] == hysteria.uuid for h in sources
        )
        if hysteria and (model or base) and not has_hy2_host:
            if model is not None:
                remark = fit_remark(model.remark, " Hysteria2")
                fields = hysteria_host(model, self.domain, patched.uuid, hysteria.uuid, remark)
            else:
                remark = fit_remark(base["remark"], " Hysteria2")
                fields = fresh_host(remark, self.node.address, 443, self.domain, patched.uuid,
                                    hysteria.uuid)  # fmt: skip
            fields["xrayJsonTemplateUuid"] = template
            self.create(change, fields)
        # Old hosts go off only now, after every copy exists and was read back.
        old = [h.uuid for h in sources]
        if old:
            # Journaled first: an answer that never comes still leaves them to switch back on.
            change["details"]["disabled"] = old
            self.engine.save()
            self.panel_call(lambda: self.client.disable_hosts(old))
        self.applied(change)

    def template_uuid(self) -> Any:
        """§10.9: copies get «KERBEROS» in a pair with a reserve, else «KERBEROS single»."""
        paired = self.item.params.get("reserve") or self.item.params.get("reserveOf")
        try:
            templates = self.engine.panel_fixes.templates()
        except PanelError as exc:
            raise StepFailed(exc.code) from exc
        return templates["reserve" if paired else "single"]

    def belongs(self, host: Any) -> bool:
        """On a shared profile a host is the node's when the panel binds it to the node, or
        else when it points at the node: its address, or a domain resolving to its IPv4."""
        if not self.shared:
            return True
        bound = host.raw.get("nodes")
        if isinstance(bound, list) and bound:
            ids = {b.get("uuid") if isinstance(b, dict) else b for b in bound}
            return self.node.uuid in ids
        if host.address == self.node.address:
            return True
        node_data = self.session.data["input"].node_data(self.node.uuid)
        ip = node_data.ipv4 if node_data else None
        if not ip or not host.address or is_ip(host.address):
            return False
        return ip in self.env.prober.resolve(host.address)

    def create(self, change: Change, fields: dict) -> None:
        created = self.panel_call(lambda: self.client.create_host(fields))
        change["details"]["created"].append(created.uuid)
        self.engine.save()
        stored = next(
            (h for h in self.panel_call(self.client.hosts) if h.uuid == created.uuid), None
        )
        if stored is None or mismatches(fields, stored):
            raise StepFailed("host_mismatch")

    def check(self) -> None:
        """§10.4 step 5; what it saw is dropped again when the self-steal is undone."""
        self.engine.event("check", self.item, "running")
        data = self.session.data["input"]
        node_data = data.node_data(self.node.uuid)
        saved = (dict(data.tls), dict(data.pages), dict(data.dns), data.snapshot,
                 node_data.facts if node_data else None)  # fmt: skip
        try:
            self.verify(data, node_data)
        except Exception:
            # The findings after «Исправление» must not show a state that is being undone.
            data.tls, data.pages, data.dns, data.snapshot = saved[:4]
            if node_data is not None:
                node_data.facts = saved[4]
            raise

    def verify(self, data: Any, node_data: Any) -> None:
        """TLS without SNI shows the domain, the site answers, the node is online."""
        ip = node_data.ipv4 if node_data else None
        if not ip:
            raise StepFailed("check_failed")
        self.reach_site(data, ip)
        self.wait_online()
        self.read_facts(node_data)
        self.judge(data)

    def wait_online(self) -> None:
        """The node is back in the panel. After node.letsencrypt_mount the panel first finds
        the recreated container again: on Remnawave 2.8.1 its health check restarted the node
        about 8 s after the profile, while Xray already answered with the site (K19)."""
        for attempt in range(CHECK_ATTEMPTS):
            try:
                online = {n.uuid: n.is_connected for n in self.client.nodes()}
            except PanelError as exc:
                raise StepFailed(exc.code) from exc
            if online.get(self.node.uuid, False):
                return
            if attempt + 1 < CHECK_ATTEMPTS:
                self.env.clock.sleep(CHECK_PAUSE)
        raise StepFailed("node_offline")

    def reach_site(self, data: Any, ip: str) -> None:
        prober = self.env.prober
        for attempt in range(CHECK_ATTEMPTS):
            tls = prober.tls_names(ip, 443, None)
            page = prober.http(ip, 443, self.domain, "/") if self.domain in tls.names else None
            if tls.ok and self.domain in tls.names and page and page.status == 200:
                data.tls[ip] = tls
                data.pages[(ip, 443, self.domain, "/")] = page or HttpResult(None)
                break
            if attempt + 1 < CHECK_ATTEMPTS:
                self.env.clock.sleep(CHECK_PAUSE)
        else:
            raise StepFailed("check_failed")
        data.dns[self.domain] = prober.resolve(self.domain)

    def read_facts(self, node_data: Any) -> None:
        try:
            node_data.facts = schema.facts(self.env.transport.agent(self.target, "facts"))
        except (NodeAgentError, TransportError, schema.BadAnswer):
            pass

    def judge(self, data: Any) -> None:
        """The findings this self-steal fixes are fixed: Reality only where it changed."""
        for check_id in self.item.checks:
            if check_id not in CHECKED:
                continue
            for finding in spec(check_id).rule(data):
                if finding["target"] != self.item.target or finding["ok"]:
                    continue
                inbound = finding["evidence"].get("inbound")
                if check_id == "reality.foreign_sni" and inbound not in self.changed:
                    continue
                raise StepFailed("check_failed")

    # -- the whole -------------------------------------------------------------
    def steps(self) -> Change:
        """Every step up to the check; the change that finalization later works on."""
        self.site()
        self.mount()
        own = self.item.params.get("ownProfile") is not None
        patched, tags = self.own_profile() if own else self.profile()
        profile_change = self.done[-1]
        # The users first, then the node runs the new inbounds (K24).
        self.squads(patched, tags)
        self.activate(patched, tags)
        self.hosts(patched, tags)
        return profile_change

    def pending(self, change: Change) -> dict:
        due = self.env.clock.now() + FINALIZE_AFTER
        return {
            "changeId": change["changeId"],
            "action": "finalize",
            "due": due.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "profileUuid": change["details"]["profileUuid"],
            "domain": self.domain,
            "nodeUuid": self.node.uuid,
            "nodeName": self.node.name,
        }

    def run(self) -> bool:
        try:
            change = self.steps()
            self.engine.event("apply", self.item, "ok")
            self.check()
        except StepFailed as exc:
            self.fail(exc.code)
            return False
        except Exception as exc:  # noqa: BLE001 - a self-steal is never left half done
            self.engine.store.log(self.engine.run, f"self_steal: internal error "
                                                   f"{type(exc).__name__}")  # fmt: skip
            self.fail("internal_error")
            return False
        self.engine.event("check", self.item, "ok")
        self.engine.run["pending"].append(self.pending(change))
        self.engine.save()
        return True

    def fail(self, code: str) -> None:
        self.restore_snapshot()
        rolled = self.undo_all(code)
        self.engine.event("check", self.item, "rolled_back" if rolled else "failed",
                          code if rolled else ROLLBACK_FAILED)  # fmt: skip

    def restore_snapshot(self) -> None:
        """What this run knows of the panel goes back with the undo: the node on its old
        profile, without the profile it got (the score after must not count it)."""
        snapshot = self.session.snapshot
        own = next((c["details"].get("profileUuid") for c in self.done
                    if c["fixId"] == "self_steal.own_profile"), None)  # fmt: skip
        if own is None:
            return
        snapshot.profiles = [p for p in snapshot.profiles if p.uuid != own]
        self.node.profile_uuid = self.start_profile.uuid if self.start_profile else None
        self.node.inbound_uuids = list(self.start_inbounds)
        if self.start_profile is not None and self.node.uuid not in self.start_profile.node_uuids:
            self.start_profile.node_uuids.append(self.node.uuid)

    def undo_all(self, reason: str) -> bool:
        """Everything done goes back in reverse order; False: something stayed in place."""
        half, self.current = self.current, None
        blocked = False
        # The step caught half way (a panel change: agent steps settle themselves) first.
        for change in ([half] if half is not None else []) + list(reversed(self.done)):
            if blocked:
                # A later step stayed in place and may need this one: Reality on a profile
                # that was not put back still points at the site (§11.4, rollback_skipped).
                self.engine.settle(change, reason, "rollback_skipped")
                continue
            if change["fixId"] in AGENT_STEPS:
                error = self.engine.rollback(self.target, change["changeId"])
            else:
                error = undo(self.client, change, ask=self.engine.ask_undo)
            if not self.engine.settle(change, reason, error):
                self.clean = False
                blocked = True
        if self.clean:
            self.engine.failed += 1
        self.engine.save()
        return self.clean
