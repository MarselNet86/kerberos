"""Findings as people read them: titles, threats and actions from copy.py."""

from __future__ import annotations

import ipaddress
import string
from typing import Callable, Optional

from rich.text import Text

from kerberos.checks import spec
from kerberos.copy import TEXT, t
from kerberos.fixes.model import TOPICS, Finding
from kerberos.report.areas import area_of, area_order, area_title, check_short, joined, where
from kerberos.ui.palette import SYMBOL_RISK, risk_style
from kerberos.ui.widgets import Block, BlockRow, Column

RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


class _Values(dict):
    def __missing__(self, key: str) -> str:
        return ""


def evidence_value(key: str, value) -> str:
    if key == "ruShare" and isinstance(value, (int, float)):
        return f"{value * 100:.0f} %"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if value is None:
        return "—"
    return str(value)


def fill(key: str, evidence: dict) -> str:
    template = TEXT.get(key, "")
    values = _Values({k: evidence_value(k, v) for k, v in evidence.items()})
    return string.Formatter().vformat(template, (), values)


def details(evidence: dict) -> str:
    return "; ".join(f"{k}: {evidence_value(k, v)}" for k, v in evidence.items())


def action(finding: Finding) -> tuple[str, str]:
    """Label and style of what happens with the finding."""
    if finding["ok"]:
        return t("action.passed"), "ok"
    item = spec(finding["checkId"])
    how = TEXT.get(f"check.{finding['checkId']}.how", "")
    if item.kind == "fix" and finding["fixId"]:
        return t("action.fix"), "ok"
    if item.kind == "fix":
        # The fix does not apply here (no Caddy of §10.10 for panel.public, padding half set):
        # what to do by hand, in the words of that check (K19).
        manual = TEXT.get(f"check.{finding['checkId']}.manual") or how
        return t("action.manual", how=manual), "risk.medium"
    if item.kind == "explain":
        return t("action.explain", how=how), "muted"
    if item.kind == "plan":
        return t("action.plan", how=how), "accent"
    return t("action.manual", how=how), "risk.medium"


def target_label(finding: Finding, node_names: dict) -> str:
    target = finding["target"]
    kind, _, ref = target.partition(":")
    if kind == "node":
        return node_names.get(ref, ref[:8])
    if kind == "host":
        return t("target.host", name=finding["evidence"].get("host", ref[:8]))
    if kind == "template":
        return t("target.template", name=finding["evidence"].get("template", ref[:8]))
    return t(f"target.{kind}") if f"target.{kind}" in TEXT else target


def change_target(target: str, params: dict, node_names: dict) -> str:
    """Who a change belongs to: a node, a host, a template or the panel, by name."""
    kind, _, ref = target.partition(":")
    if kind != "node" and params.get("node"):
        kind, ref = "node", params["node"]
    if kind == "host":
        return t("target.host", name=params.get("remark") or ref[:8])
    if kind == "template":
        return t("target.template", name=params.get("name") or ref[:8])
    if kind == "node":
        return node_names.get(ref, ref[:8])
    return t("target.panel")


def ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (TOPICS.index(f["topic"]), RISK_ORDER[f["risk"]], f["checkId"]),
    )


def problems(findings: list[Finding]) -> list[Finding]:
    return ordered([f for f in findings if not f["ok"]])


# Checks of the fleet whose findings name the same nodes from every node's side:
# S6 shows one row a group, not one a node (K22). The findings and the score stay.
GROUPED = ("fleet.same_asn", "fleet.same_24", "fleet.shared_hostkey")


def node_name(finding: Finding, node_names: dict) -> str:
    kind, _, ref = finding["target"].partition(":")
    return node_names.get(ref, ref[:8]) if kind == "node" else ""


def _clusters(findings: list[Finding], node_names: dict) -> dict[str, str]:
    """fleet.same_24: nodes in one or neighbouring /24 nets, chained into clusters."""
    parent: dict[str, str] = {}

    def root(name: str) -> str:
        parent.setdefault(name, name)
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    for item in findings:
        if item["checkId"] == "fleet.same_24":
            me = node_name(item, node_names)
            for other in item["evidence"].get("with", []):
                parent[root(other)] = root(me)
    return {name: root(name) for name in list(parent)}


def _group_key(item: Finding, node_names: dict, clusters: dict) -> Optional[tuple]:
    check, evidence = item["checkId"], item["evidence"]
    if check == "fleet.same_asn":
        return (check, evidence.get("asn"), evidence.get("country"))
    if check == "fleet.shared_hostkey":
        return (check, evidence.get("fingerprint"))
    if check == "fleet.same_24":
        name = node_name(item, node_names)
        return (check, clusters.get(name, name))
    return None


def rows(findings: list[Finding], node_names: Optional[dict] = None) -> list[list[Finding]]:
    """Problems as the screens show them (K23): one row a check on all its targets;
    the fleet checks one row a group of nodes (K22)."""
    node_names = node_names or {}
    failing = problems(findings)
    clusters = _clusters(failing, node_names)
    result: list[list[Finding]] = []
    groups: dict[tuple, list[Finding]] = {}
    for item in failing:
        key = _group_key(item, node_names, clusters) or (item["checkId"],)
        if key in groups:
            groups[key].append(item)
        else:
            groups[key] = [item]
            result.append(groups[key])
    return result


def _net_order(net: str) -> tuple:
    try:
        return (0, int(ipaddress.ip_network(net, strict=False).network_address))
    except ValueError:
        return (1, net)


def row_evidence(members: list[Finding]) -> dict:
    """The evidence of a row: the first finding's, widened to the whole row."""
    evidence = dict(members[0]["evidence"])
    if len(members) == 1:
        return evidence
    evidence.pop("with", None)  # the row names every node itself
    if members[0]["checkId"] == "fleet.same_24":
        nets = {m["evidence"].get("net", "") for m in members} - {""}
        evidence["net"] = ", ".join(sorted(nets, key=_net_order))
        return evidence
    for key in list(evidence):
        values: list = []
        for member in members:
            value = member["evidence"].get(key)
            for part in value if isinstance(value, (list, tuple)) else [value]:
                if part is not None and part not in values:
                    values.append(part)
        evidence[key] = values[0] if len(values) == 1 else values
    return evidence


def todo(finding: Finding) -> str:
    """What to do about a problem KERBEROS does not fix itself, as a sentence."""
    item = spec(finding["checkId"])
    how = TEXT.get(f"check.{finding['checkId']}.how", "")
    if item.kind == "fix":
        how = TEXT.get(f"check.{finding['checkId']}.manual") or how
    return how[:1].upper() + how[1:]


def row_where(members: list[Finding], node_names: dict) -> tuple[list[str], list[str]]:
    """Who a row is about: node names, then the panel, hosts and templates by name."""
    nodes, others = [], []
    for member in members:
        if member["target"].startswith("node:"):
            nodes.append(node_name(member, node_names))
        else:
            others.append(target_label(member, node_names))
    return nodes, others


def risk_cell(risk: str) -> Text:
    return Text(f"{SYMBOL_RISK} {t('risk.' + risk)}", style=risk_style(risk))


def worst(members_list: list[list[Finding]]) -> str:
    return min((m[0]["risk"] for m in members_list), key=lambda r: RISK_ORDER[r])


def _title(members: list[Finding], mask: Callable[[str], str]) -> str:
    return mask(fill(f"check.{members[0]['checkId']}.title", row_evidence(members)))


def _problem_line(members: list[Finding], node_names: dict, mask: Callable[[str], str]) -> Text:
    nodes, others = row_where(members, node_names)
    line = Text(f"{SYMBOL_RISK} ", style=risk_style(members[0]["risk"]))
    line.append(_title(members, mask))
    line.append(" · " + mask(where(nodes, others)), style="muted")
    return line


AUTO_COLUMNS = [Column(most=10), Column(most=20), Column(flex=1, least=16),
                Column(most=16, least=6)]  # fmt: skip
MANUAL_COLUMNS = [Column(most=10), Column(flex=1, least=16), Column(most=16, least=6),
                  Column(flex=1, least=12)]  # fmt: skip
INFO_COLUMNS = [Column(most=1), Column(flex=1, least=10)]


def report_blocks(findings: list[Finding], node_names: dict,
                  mask: Optional[Callable[[str], str]] = None,
                  parts: tuple = ("auto", "manual", "info")) -> list[Block]:  # fmt: skip
    """S6 in blocks (K23): what KERBEROS fixes itself, one row an area; what is left
    to the person, one row a problem; the explanations folded into one row. S9 takes
    only the part «manual»: what is left to the person after the run."""
    mask = mask or (lambda value: value)
    by_area: dict[str, list[list[Finding]]] = {}
    manual: list[list[Finding]] = []
    info: list[list[Finding]] = []
    for members in rows(findings, node_names):
        first = members[0]
        if auto_fixable(first):
            by_area.setdefault(area_of(first["fixId"]), []).append(members)
        elif first["risk"] == "info":
            info.append(members)
        else:
            manual.append(members)
    blocks = []
    if by_area and "auto" in parts:
        area_rows = []
        for area in sorted(by_area, key=area_order):
            members_list = sorted(by_area[area], key=lambda m: RISK_ORDER[m[0]["risk"]])
            nodes, others = [], []
            for members in members_list:
                names, rest = row_where(members, node_names)
                nodes += names
                others += rest
            found = [check_short(m[0]["checkId"], _title(m, mask)) for m in members_list]
            shorts = joined(found, 3)
            details = []
            for members in members_list:
                details.append(_problem_line(members, node_names, mask))
                threat = TEXT.get(f"check.{members[0]['checkId']}.threat", "")
                if threat:
                    details.append(Text("  " + threat, style="muted"))
            area_rows.append(BlockRow(
                [risk_cell(worst(members_list)), Text(area_title(area), style="bold"),
                 Text(mask(shorts)), Text(mask(where(nodes, others)), style="muted")],
                details, key=("area", area)))  # fmt: skip
        counted = sum(1 for found in by_area.values() for m in found if m[0]["risk"] != "info")
        blocks.append(
            Block(
                t("s6.block.auto"),
                area_rows,
                AUTO_COLUMNS,
                "ok",
                t("s6.block.auto.note", problems=counted, areas=len(by_area)),
            )
        )
    if manual and "manual" in parts:
        manual.sort(key=lambda m: (RISK_ORDER[m[0]["risk"]], TOPICS.index(m[0]["topic"])))
        manual_rows = []
        for members in manual:
            nodes, others = row_where(members, node_names)
            details = [Text(TEXT.get(f"check.{members[0]['checkId']}.threat", ""), style="muted")]
            evidence = details_text(members)
            if evidence:
                details.append(Text(mask(evidence), style="muted"))
            manual_rows.append(BlockRow(
                [risk_cell(members[0]["risk"]), Text(_title(members, mask)),
                 Text(mask(where(nodes, others)), style="muted"),
                 Text(mask(todo(members[0])), style="risk.medium")],
                [d for d in details if d.plain], key=("row", members[0]["checkId"],
                                                      members[0]["target"])))  # fmt: skip
        blocks.append(
            Block(
                t("s6.block.manual"),
                manual_rows,
                MANUAL_COLUMNS,
                "risk.medium",
                t("s6.block.manual.note", n=len(manual)),
            )
        )
    if info and "info" in parts:
        lines = []
        for members in info:
            lines.append(_problem_line(members, node_names, mask))
            how = todo(members[0])
            if how:
                lines.append(Text("  " + mask(how), style="muted"))
        row = BlockRow([Text("i", style="bold"), Text(t("s6.info.row", n=len(info)))], lines,
                       key=("info",))  # fmt: skip
        blocks.append(Block(t("s6.block.info"), [row], INFO_COLUMNS))
    return blocks


def details_text(members: list[Finding]) -> str:
    """The machine facts of a row: per target when the row covers several."""
    if len(members) == 1:
        return details(members[0]["evidence"])
    return details(row_evidence(members))


def auto_fixable(finding: Finding) -> bool:
    return not finding["ok"] and spec(finding["checkId"]).kind == "fix" and bool(finding["fixId"])


def counts(findings: list[Finding], node_names: Optional[dict] = None) -> dict:
    """Rows as S6 shows them (K22): a group of the fleet checks counts once."""
    failing = [r for r in rows(findings, node_names) if r[0]["risk"] != "info"]
    auto = [r for r in failing if auto_fixable(r[0])]
    high = [r for r in failing if r[0]["risk"] == "high"]
    return {"problems": len(failing), "high": len(high), "auto": len(auto),
            "manual": len(failing) - len(auto)}  # fmt: skip


def projected(findings: list[Finding]) -> int:
    """§12.2 score once every fix KERBEROS can make has passed: «≈», fixes may fail."""
    from kerberos.checks.score import score

    return score([dict(f, ok=True) if auto_fixable(f) else f for f in findings])
