"""Finalization of self-steal after 24 hours (tech.md §10.4 step 6, §7.3).

Old server names leave `serverNames`; clients that did not refresh their
subscription in a day stop connecting through this node. Run by hand
(`kerberos finalize`, reminded on S1) or by a systemd timer on the panel
server that signs in with the API token S2 saved (an API token cannot
create another one, §7.3).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from kerberos.clock import Clock
from kerberos.fixes.journal import RunStore, iso
from kerberos.fixes.profile import finalize_profile
from kerberos.panel.client import PanelClient
from kerberos.panel.errors import PanelError


def parse_time(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def due_items(store: RunStore, now: datetime, run_id: Optional[str] = None) -> list:
    found = []
    for run in store.runs():
        if run_id is not None and run["runId"] != run_id:
            continue
        for item in run.get("pending", []):
            if item.get("action") == "finalize" and parse_time(item["due"]) <= now:
                found.append((run, item))
    return found


def finalize_items(client: PanelClient, store: RunStore, pairs: list) -> list:
    """Remove old names; returns the items that failed. Running twice changes nothing."""
    failed = []
    for run, item in pairs:
        try:
            if item.get("panel") == "3x-ui":
                finalize_xui(client, store, run, item)
            else:
                profile = next((p for p in client.profiles() if p.uuid == item["profileUuid"]),
                               None)  # fmt: skip
                if profile is None:
                    raise PanelError("bad_response", detail="profile is gone")
                config = finalize_profile(profile.config, item["domain"])
                if config != profile.config:
                    # What the panel stored, normalized, is what a rollback compares with.
                    patched = client.patch_profile(profile.uuid, config)
                    remember_final(store, run, item, patched.config)
        except PanelError as exc:
            item["error"] = exc.code
            failed.append(item)
            store.save(run)
            continue
        run["pending"] = [p for p in run["pending"] if p is not item]
        run.setdefault("finalized", []).append({**item, "at": iso(store.clock)})
        store.save(run)
    return failed


def remember_final(store: RunStore, run: dict, item: dict, config: dict) -> None:
    """A later rollback compares the panel with the finalized profile: not a hand edit."""
    from kerberos.fixes.panel_changes import digest, save_snapshot

    change = next((c for c in run["changes"] if c["changeId"] == item["changeId"]), None)
    if change is None:
        return
    # The profile holds the Reality private key: a 0600 snapshot, never run.json.
    change["details"]["writtenPath"] = save_snapshot(
        store, run["runId"], f"profile-{item['profileUuid']}-final", config
    )
    change["details"]["written"] = digest(config)


def finalize_xui(client: Any, store: RunStore, run: dict, item: dict) -> None:
    """3x-ui (§7.6): only the domain stays in serverNames of the inbounds of the run."""
    from kerberos.fixes.panel_changes import load_snapshot, save_snapshot
    from kerberos.fixes.xui_self_steal import without_old_names

    change = next((c for c in run["changes"] if c["changeId"] == item["changeId"]), None)
    written = load_snapshot((change or {}).get("details", {}).get("writtenPath")) or {}
    for ident in item["inbounds"]:
        current = client.inbound(int(ident))["streamSettings"]
        final = without_old_names(current, item["domain"])
        if final != current:
            client.update_inbound(int(ident), final)
        written[ident] = final
    if change is not None and written:
        # A later rollback compares with what the panel holds after finalization.
        change["details"]["writtenPath"] = save_snapshot(
            store, run["runId"], f"xui-reality-{change['changeId'][:8]}-final", written
        )


def schedule(app: Any, run: dict, launcher: str) -> bool:
    """«Сделать автоматически»: a systemd timer for the run, with the saved API token.

    `finalizeTimer` names the timer only when there is one: S9 says «automatic» by it.
    """
    store = RunStore(app.env.state, app.env.clock)
    run["finalizeTimer"] = None
    if store.state.read_panel_token() is None:
        store.save(run)
        return False  # nothing the timer could sign in with
    unit = f"kerberos-finalize-{run['runId']}"
    result = app.env.host.run(["systemd-run", "--on-active=24h", "--unit", unit, launcher,
                               "finalize", run["runId"]])  # fmt: skip
    if result.ok:
        run["finalizeTimer"] = unit
    store.save(run)
    return result.ok


def unattended(store: RunStore, transport: Any, clock: Clock, run_id: Optional[str]) -> int:
    """`kerberos finalize` without a terminal: the timer's call with the saved API token.

    3: no token, the panel refused, or a 3x-ui run (finalized in the terminal, §7.6);
    such runs stay pending and S1 reminds of them.
    """
    pairs = due_items(store, clock.now(), run_id)
    if not pairs:
        return 0
    token = store.state.read_panel_token()
    code = 0
    for run in {id(r): r for r, _i in pairs}.values():
        if run["panel"].get("kind") == "3x-ui" or token is None:
            code = 3
            continue
        client = PanelClient(run["panel"].get("api", ""), transport, clock)
        client.set_token(token)
        if finalize_items(client, store, [(r, i) for r, i in pairs if r is run]):
            code = 3
        if client.refused:
            # Not allowed to change the profile: the next run in the terminal signs in again.
            store.state.forget_panel_token()
            return 3
        if client.wrote:
            store.state.mark_panel_token_writable()
    return code
