"""report.md (tech.md §12.3): what a person reads after the run."""

from __future__ import annotations

import re
from typing import Callable, Optional

from kerberos.copy import TEXT, t
from kerberos.fixes.model import TOPICS, Run
from kerberos.report.view import action, change_target, details, fill, problems, target_label


def render(run: Run, mask: Optional[Callable[[str], str]] = None) -> str:
    masking = mask is not None  # the secret path of a panel link goes too (§10.10)
    mask = mask or (lambda value: value)
    names = {n["uuid"]: n["name"] for n in run["nodes"]}
    lines = [f"# {t('report.title.' + run['mode'])}", ""]
    lines.append(
        t(
            "report.head",
            time=run["startedAt"].replace("T", " ").replace("Z", " UTC"),
            mode=t(f"report.mode.{run['mode']}"),
            panel=t("panel.kind." + run["panel"].get("kind", "remnawave")),
            version=run["panel"].get("version", "?"),
            nodes=len(run["nodes"]),
        )
    )
    lines.append("")
    if run.get("scoreAfter") is not None:
        lines.append(
            "**"
            + t("report.score_before_after", before=run["scoreBefore"], after=run["scoreAfter"])
            + "**"  # fmt: skip
        )
    else:
        lines.append("**" + t("report.score", score=run["scoreBefore"]) + "**")
    # A fix run reports what is left after it, as its score and S9 do; what it changed is in
    # «Изменения» below. Before K19 it listed the findings before, «Исправит KERBEROS» and all.
    findings = run.get("findingsAfter") or run["findings"]
    failing = problems(findings)
    for topic in TOPICS:
        part = [f for f in failing if f["topic"] == topic]
        passed = [f for f in findings if f["topic"] == topic and f["ok"]]
        if not part and not passed:
            continue
        lines += ["", f"## {t('topic.' + topic)}", ""]
        for item in part:
            title = fill(f"check.{item['checkId']}.title", item["evidence"])
            lines.append(f"- ● {t('risk.' + item['risk'])} · {target_label(item, names)} · {title}")
            threat = TEXT.get(f"check.{item['checkId']}.threat", "")
            if threat:
                lines.append("  - " + t("report.threat", text=threat))
            lines.append("  - " + action(item)[0])
            if item["evidence"]:
                lines.append("  - " + t("report.details", text=details(item["evidence"])))
        if passed:
            lines.append(("" if not part else "\n") + "✓ " + t("report.passed", n=len(passed)))
    if run.get("changes"):
        lines += ["", f"## {t('report.changes')}", ""]
        for change in run["changes"]:
            ports = ", ".join(change["params"].get("ports", []))
            # Undo failed too: the change may still be in place, whatever its state says.
            stuck = change.get("error") == "rollback_failed"
            lines.append(
                t(
                    "report.change",
                    state=t("report.rollback_failed") if stuck else t(f"state.{change['state']}"),
                    node=change_target(change["target"], change["params"], names),
                    fix=t(
                        f"fix.{change['fixId']}.label",
                        ports=ports,
                        port=change["params"].get("port", ""),
                        domain=change["params"].get("domain", ""),
                        reserve=names.get(change["params"].get("reserve", ""), ""),
                        profile=change["params"].get("profile", ""),
                    ),
                )
            )
            if stuck:
                failure = change["details"].get("failure") or ""
                reason = TEXT.get(f"error.{failure}", failure)
                lines.append("  - " + t("apply.rollback_failed", reason=reason))
            elif change.get("error"):
                reason = TEXT.get(f"error.{change['error']}", change["error"])
                lines.append(t("report.change_error", reason=reason))
            site = change["details"].get("site")
            if (change["fixId"] == "self_steal.site" and change["state"] == "applied" and site
                    and not stuck):  # fmt: skip
                kind = t(f"site.kind.{site['kind']}")
                colors = {"background": site["background"], "accent": site["accent"]}
                lines.append("  - " + t("report.site", title=site["title"], kind=kind, **colors))
            renewals = change["details"].get("renewals")
            if (change["fixId"] == "self_steal.site" and change["state"] == "applied"
                    and renewals and not stuck):  # fmt: skip
                moved = ", ".join(f"{r['name']} ({r['tool']})" for r in renewals)
                lines.append("  - " + t("report.renewals", names=moved))
            if change["fixId"] == "ssh.port" and change["state"] == "confirmed" and not stuck:
                node = next((n for n in run["nodes"]
                             if change["target"] == f"node:{n['uuid']}"), None)  # fmt: skip
                port = change["details"].get("newPort")
                command = f"ssh -p {port} root@{node['address'] if node else '?'}"
                lines.append("  - **" + t("report.ssh_port", port=port, command=command) + "**")
            if (change["fixId"] in ("panel.portal", "xui.panel_hide")
                    and change["state"] == "confirmed" and not stuck):  # fmt: skip
                from kerberos.fixes.panel_changes import load_snapshot

                saved = load_snapshot(change["details"].get("linkPath")) or {}
                if saved.get("link"):
                    # report.md is 0600 (§12.3): the person finds the new way in here.
                    link = saved["link"]
                    if masking:
                        scheme, _, rest = link.partition("://")
                        link = f"{scheme}://{rest.partition('/')[0]}/…"
                    key = (
                        "report.portal" if change["fixId"] == "panel.portal" else "report.xui_panel"
                    )
                    lines.append("  - **" + t(key, link=link, login=saved.get("login", "")) + "**")
        lines += ["", t("report.backups")]
    lines += ["", f"## {t('report.nodes')}", "", t("report.nodes.head"), "|---|---|---|---|"]
    for node in run["nodes"]:
        access = t(f"access.status.{node.get('access', 'none')}")
        if node.get("accessReason"):
            access += f": {node['accessReason']}"
        lines.append(
            f"| {node['name']} | {node['address']} | {node.get('sshPort', 22)} | {access} |"
        )
    if run["mode"] == "fix" and run.get("changes"):
        from kerberos.screens.fix import rollback_command

        lines += ["", f"## {t('report.rollback')}", "", "`" + rollback_command(run["runId"]) + "`"]
    return mask("\n".join(lines) + "\n")


_BOLD = re.compile(r"\*\*(.+?)\*\*")
_CODE = re.compile(r"`([^`]*)`")


def _table(rows: list[str]) -> list[str]:
    """A Markdown table as aligned columns; the |---| line goes away."""
    cells = [[c.strip() for c in row.strip().strip("|").split("|")] for row in rows
             if not set(row.strip()) <= set("|-: ")]  # fmt: skip
    if not cells:
        return []
    widths = [max(len(r[i]) for r in cells if i < len(r)) for i in range(max(map(len, cells)))]
    return ["  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip() for r in cells]


def plain(text: str) -> str:
    """report.md for the screen: headings underlined, tables aligned, no Markdown signs."""
    out: list[str] = []
    table: list[str] = []
    for raw in text.split("\n"):
        if raw.startswith("|"):
            table.append(raw)
            continue
        if table:
            out += _table(table)
            table = []
        line = _CODE.sub(r"\1", _BOLD.sub(r"\1", raw))
        if line.startswith("## "):
            out += [line[3:], "─" * len(line[3:])]
        elif line.startswith("# "):
            out += [line[2:], "═" * len(line[2:])]
        elif line.startswith("  - "):
            out.append("    " + line[4:])
        elif line.startswith("- "):
            out.append(line[2:] if line.startswith("- ● ") else "• " + line[2:])
        else:
            out.append(line)
    if table:
        out += _table(table)
    return "\n".join(out)
