"""Changes in the panel and their rollback (tech.md §10.4, §10.5, §11.4).

Before KERBEROS changes a panel object it saves the object to
runs/<runId>/panel/. Rollback puts the object back; if the object in the
panel differs from what KERBEROS wrote (someone edited it by hand), rollback
shows the difference and asks first.
"""

from __future__ import annotations

import difflib
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Optional

from kerberos.fixes.journal import RunStore
from kerberos.panel.client import PanelClient
from kerberos.panel.errors import PanelError

PANEL_FIXES = {
    "self_steal.own_profile",
    "self_steal.profile",
    "self_steal.node",
    "self_steal.squads",
    "self_steal.hosts",
    "sub.templates",
    "sub.template",
    "sub.ping_type",
    "host.fingerprint",
    "reserve",
    "xhttp.padding",
    "xhttp.uplink_get",
    "xui.reality",
}


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def save_snapshot(store: RunStore, run_id: str, name: str, value: Any) -> str:
    path = store.path(run_id) / "panel" / f"{name}.json"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    store.state.write_private(path, json.dumps(value, ensure_ascii=False, indent=2))
    return str(path)


def load_snapshot(path: Optional[str]) -> Any:
    if not path:
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def diff_text(written: Any, current: Any) -> str:
    a = json.dumps(written, indent=2, sort_keys=True, ensure_ascii=False).splitlines()
    b = json.dumps(current, indent=2, sort_keys=True, ensure_ascii=False).splitlines()
    return "\n".join(difflib.unified_diff(a, b, "KERBEROS", "panel", lineterm="", n=2))


def undo(client: PanelClient, change: dict,
         ask: Optional[Callable[[str], bool]] = None) -> Optional[str]:  # fmt: skip
    """Roll one panel change back. None: done; otherwise the reason it was not.

    A change cut short ("applying") may have written only part: what is not in
    the panel needs nothing. An object edited after KERBEROS wrote it is shown
    with `ask` first (§10.5, §11.4); without `ask` it is left as it is.
    """
    fix_id, details = change["fixId"], change["details"]
    try:
        if fix_id == "self_steal.hosts":
            current = {h.uuid: h for h in client.hosts()}
            # Only what is off now: a request that never landed leaves nothing to undo.
            off = [
                u for u in details.get("disabled") or [] if u in current and current[u].is_disabled
            ]
            if off:
                client.enable_hosts(off)
            for uuid in details.get("created", []):
                if uuid in current:
                    client.delete_host(uuid)
            return None
        if fix_id == "sub.templates":
            return undo_templates(client, details, ask)
        if fix_id == "sub.template":
            return undo_hosts(client, details, lambda h: h.template_uuid,
                              lambda value: {"xrayJsonTemplateUuid": value}, ask)  # fmt: skip
        if fix_id == "sub.ping_type":
            if "previous" not in details:
                return None  # failed before anything was written
            current = client.sub_settings()
            headers = dict(current.headers)
            previous = details.get("previous") or {}
            if "ping-type" in previous:
                headers["ping-type"] = previous["ping-type"]
            else:
                headers.pop("ping-type", None)
            if headers == dict(current.headers):
                return None  # nothing of KERBEROS is there: the write never landed
            client.patch_sub_settings(current.uuid, headers)
            return None
        if fix_id == "host.fingerprint":
            if "previous" not in details:
                return None
            uuid = change["params"]["host"]
            host = next((h for h in client.hosts() if h.uuid == uuid), None)
            previous = details.get("previous", "") or ""
            if host is None or host.fingerprint == previous:
                return None  # deleted since, or never written: nothing to put back
            client.patch_host(uuid, {"fingerprint": previous})
            return None
        if fix_id == "reserve":
            return undo_hosts(client, details, reserve_fields, dict, ask)
        if fix_id == "self_steal.squads":
            return undo_squads(client, details)
        if fix_id == "self_steal.node":
            return undo_node(client, change)
        if fix_id == "xui.reality":
            return undo_xui_reality(client, change, ask)
        if fix_id == "xhttp.uplink_get":
            return undo_uplink(client, change)
        if fix_id == "xhttp.padding":
            return undo_padding(client, change, ask)
        if fix_id == "self_steal.profile":
            return undo_profile(client, change, ask)
        if fix_id == "self_steal.own_profile":
            return undo_own_profile(client, change, ask)
    except PanelError as exc:
        return exc.code
    return "unknown_change"


def reserve_fields(host: Any) -> dict:
    return {"tags": list(host.tags), "isHidden": host.is_hidden,
            "xrayJsonTemplateUuid": host.template_uuid}  # fmt: skip


def undo_hosts(client: PanelClient, details: dict, read: Callable[[Any], Any],
               write: Callable[[Any], dict],
               ask: Optional[Callable[[str], bool]]) -> Optional[str]:  # fmt: skip
    """Hosts back to details["hosts"]; a host changed since details["written"] is asked about.

    Runs without "written" (journals before v18) put every host back as they did.
    """
    before = details.get("hosts") or {}
    written = details.get("written")
    if not before:
        return None
    current = {h.uuid: h for h in client.hosts()}
    todo, mine, now = {}, {}, {}
    for uuid, old in before.items():
        host = current.get(uuid)
        if host is None:
            continue  # deleted since: nothing to put back
        value = read(host)
        if value == old:
            continue  # never written (a change cut short) or already back
        if written is not None and value != written.get(uuid):
            name = f"{host.remark} ({uuid[:8]})"
            mine[name], now[name] = written.get(uuid), value
        todo[uuid] = old
    if now and (ask is None or not ask(diff_text(mine, now))):
        return "changed_in_panel"
    for uuid, old in todo.items():
        client.patch_host(uuid, write(old))
    return None


def undo_templates(client: PanelClient, details: dict,
                   ask: Optional[Callable[[str], bool]]) -> Optional[str]:  # fmt: skip
    """Templates KERBEROS created stay (the API has no delete); edited ones go back."""
    todo, mine, now = {}, {}, {}
    for uuid, info in (details.get("templates") or {}).items():
        previous = load_snapshot(info.get("previousPath"))
        if previous is None or not info.get("written"):
            continue  # created by KERBEROS, or the person kept their own edits
        current = client.template(uuid)
        if current.json == previous:
            continue  # never written, or already back
        if digest(current.json) != info["written"]:
            mine[current.name] = load_snapshot(info.get("writtenPath"))
            now[current.name] = current.json
        todo[uuid] = previous
    if now and (ask is None or not ask(diff_text(mine, now))):
        return "changed_in_panel"
    for uuid, previous in todo.items():
        client.patch_template(uuid, previous)
    return None


def undo_squads(client: PanelClient, details: dict) -> Optional[str]:
    """Only the inbounds KERBEROS added leave each squad: those it lacked before. What
    others added since stays."""
    added = details.get("added")
    if isinstance(added, str):
        added = [added]  # one uuid in journals before v29
    squads = {s.uuid: s for s in client.squads()} if details.get("squads") else {}
    for uuid, before in (details.get("squads") or {}).items():
        squad = squads.get(uuid)
        if squad is None:
            continue  # deleted since: nothing to put back
        if added is None:
            client.patch_squad(uuid, before)  # a journal before v18 knows only the old list
            continue
        mine = [a for a in added if a not in before and a in squad.inbound_uuids]
        if mine:
            client.patch_squad(uuid, [i for i in squad.inbound_uuids if i not in mine])
    return None


def undo_node(client: PanelClient, change: dict) -> Optional[str]:
    """Only the inbounds KERBEROS switched on leave the node (K20): what the person switched
    on since stays, and a node moved to another profile since is left alone."""
    details = change["details"]
    added = set(details.get("added") or [])
    node = next((n for n in client.nodes() if n.uuid == change["params"].get("node")), None)
    if "beforeProfile" in details:
        return undo_move(client, node, details)
    if node is None or not added & set(node.inbound_uuids):
        return None  # deleted since, or the request never landed: nothing to take out
    if node.profile_uuid != details.get("profileUuid"):
        return None
    client.patch_node_inbounds(node.uuid, node.profile_uuid,
                               [u for u in node.inbound_uuids if u not in added])  # fmt: skip
    return None


def undo_move(client: PanelClient, node: Any, details: dict) -> Optional[str]:
    """K24: the node back on the profile it left, with the inbounds it ran there. A node
    moved elsewhere since, or that never moved, is left alone; one that had no profile
    stays on its own until the undo of that profile deletes it (and so takes it away)."""
    if node is None or node.profile_uuid != details.get("profileUuid"):
        return None
    before = details.get("beforeProfile")
    if before is None:
        return None
    profile = next((p for p in client.profiles() if p.uuid == before), None)
    if profile is None:
        return "gone"
    known = {i.uuid for i in profile.inbounds}
    client.patch_node_inbounds(node.uuid, before,
                               [u for u in details.get("before") or [] if u in known])  # fmt: skip
    return None


def undo_own_profile(client: PanelClient, change: dict,
                     ask: Optional[Callable[[str], bool]]) -> Optional[str]:  # fmt: skip
    """K24: the node's own profile goes, last of the panel steps. Deleting it stops every
    node on it and leaves its hosts without a profile, so a node or a host that is not
    KERBEROS's keeps it there (`profile_in_use`); the node that had no profile may stay on
    it: the delete takes it back to none."""
    details = change["details"]
    uuid = details.get("profileUuid")
    profiles = client.profiles()
    current = next((p for p in profiles
                    if (p.uuid == uuid if uuid else p.name == details.get("name"))),
                   None)  # fmt: skip
    if current is None:
        return None  # never created, or deleted since
    allowed = set() if details.get("sharedUuid") else {change["params"].get("node")}
    if set(current.node_uuids) - allowed:
        return "profile_in_use"
    if any(h.profile_uuid == current.uuid for h in client.hosts()):
        return "profile_in_use"
    if details.get("written") and digest(current.config) != details["written"]:
        written = load_snapshot(details.get("writtenPath"))
        if ask is None or not ask(diff_text(written, current.config)):
            return "changed_in_panel"
    client.delete_profile(current.uuid)
    return None


def undo_profile(client: PanelClient, change: dict,
                 ask: Optional[Callable[[str], bool]]) -> Optional[str]:  # fmt: skip
    details = change["details"]
    before = load_snapshot(change.get("before"))
    if before is None:
        # The snapshot is saved before anything is written: without one, nothing was.
        return "no_snapshot" if details.get("written") else None
    uuid = details.get("profileUuid") or before.get("uuid")
    current = next((p for p in client.profiles() if p.uuid == uuid), None)
    if current is None:
        return "gone"
    if digest(current.config) == digest(before["config"]):
        return None  # the PATCH never landed, or the profile is back already
    if details.get("written") and digest(current.config) != details["written"]:
        # The written config lives in a 0600 snapshot, never in run.json:
        # it holds the Reality private key.
        written = load_snapshot(details.get("writtenPath"))
        if ask is None or not ask(diff_text(written, current.config)):
            return "changed_in_panel"
    client.patch_profile(uuid, before["config"])
    return None


def undo_uplink(client: PanelClient, change: dict) -> Optional[str]:
    """The host's extra as it was, when nobody touched it since; else only the method goes back.

    A host that had no extra of its own gets none again: it follows its inbound once more.
    """
    from kerberos.fixes import xhttp

    details = change["details"]
    if "previous" not in details:
        return None
    uuid = change["params"]["host"]
    host = next((h for h in client.hosts() if h.uuid == uuid), None)
    if host is None:
        return "gone"
    before = load_snapshot(change.get("before"))
    written = load_snapshot(details.get("writtenPath"))
    if isinstance(before, dict) and written is not None and host.xhttp_extra == written:
        client.patch_host(uuid, {"xhttpExtraParams": before.get("extra")})
        return None
    if str((host.xhttp_extra or {}).get("uplinkHTTPMethod", "")).upper() != "GET":
        return None  # changed back meanwhile: nothing of KERBEROS is left
    extra = xhttp.uplink_back(host.xhttp_extra, details["previous"], details.get("extraWasNone"))
    client.patch_host(uuid, {"xhttpExtraParams": extra})
    return None


def undo_padding(client: PanelClient, change: dict,
                 ask: Optional[Callable[[str], bool]]) -> Optional[str]:  # fmt: skip
    """Only the padding keys KERBEROS wrote go, from the inbound and from its hosts."""
    from kerberos.fixes import xhttp

    details = change["details"]
    if not details.get("inbounds") or not details.get("writtenPath"):
        return None
    written = load_snapshot(details["writtenPath"])
    if written is None:
        return "no_snapshot"
    profile = next((p for p in client.profiles() if p.uuid == details["profileUuid"]), None)
    if profile is None:
        return "gone"
    config, changed = xhttp.remove_padding(profile.config, written)
    hosts = {h.uuid: h for h in client.hosts()}
    for uuid, tag in (details.get("hosts") or {}).items():
        host = hosts.get(uuid)
        current = xhttp.padding_of(host.xhttp_extra) if host else {}
        if current and current != written.get(tag) and tag not in changed:
            changed.append(tag)
    if changed:
        mine = {tag: written[tag] for tag in changed}
        now = {tag: xhttp.padding_of(((profile.inbound_config(tag) or {}).get("streamSettings")
                                      or {}).get("xhttpSettings", {}).get("extra"))
               for tag in changed}  # fmt: skip
        if ask is None or not ask(diff_text(mine, now)):
            return "changed_in_panel"
        # Approved: the edited padding goes from the server too, as it goes from every
        # client below. Padding on one side only breaks the tunnel.
        config, _changed = xhttp.remove_padding(profile.config, written, force=changed)
    if config != profile.config:
        client.patch_profile(profile.uuid, config)
    for uuid in details.get("hosts") or {}:
        host = hosts.get(uuid)
        if host is not None and xhttp.padding_of(host.xhttp_extra):
            rest = xhttp.without_padding(host.xhttp_extra)
            client.patch_host(uuid, {"xhttpExtraParams": rest or None})
    return None


def undo_xui_reality(client: Any, change: dict,
                     ask: Optional[Callable[[str], bool]]) -> Optional[str]:  # fmt: skip
    """3x-ui (§7.6): Reality of the inbounds back from the snapshot; asks when edited since."""
    before = load_snapshot(change.get("before"))
    if before is None:
        # The snapshot is saved before anything is written: without one, nothing was.
        return "no_snapshot" if change["details"].get("writtenPath") else None
    written = load_snapshot(change["details"].get("writtenPath")) or {}
    edited, currents = {}, {}
    for ident, stream in before.items():
        current = currents[ident] = client.inbound(int(ident))["streamSettings"]
        mine = written.get(ident)
        if mine is not None and current not in (mine, stream):
            edited[ident] = (mine, current)
    if edited:
        mine = {k: v[0].get("realitySettings") for k, v in edited.items()}
        now = {k: v[1].get("realitySettings") for k, v in edited.items()}
        if ask is None or not ask(diff_text(mine, now)):
            return "changed_in_panel"
    for ident, stream in before.items():
        if currents[ident] != stream:  # an inbound not written yet needs nothing
            client.update_inbound(int(ident), stream)
    return None
