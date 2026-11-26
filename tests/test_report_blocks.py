"""S6 in blocks (tech.md §6 S6, §14.4, K23; K22 before it).

Found on the owner's fleet: a list of findings read as a wall of text, a row a node for
the same problem. Now what KERBEROS fixes itself is a row an area, what is left to the
person a row a problem on all its nodes; the fleet groups of K22 stay a row a group.
"""

from rich.console import Console

from kerberos.checks import REGISTRY, run_checks
from kerberos.checks.score import score
from kerberos.copy import TEXT, t
from kerberos.fixes.plan import NODE_ORDER, PANEL_ORDER
from kerberos.report.areas import AREAS, FIX_AREA, PLAN_GROUPS, area_of, where
from kerberos.report.view import counts, projected, report_blocks, rows
from kerberos.screens.check import check_summary
from kerberos.ui.widgets import BlockList

NAMES = {"u-a": "nl-a", "u-b": "nl-b", "u-c": "nl-c", "u-d": "de-a", "u-e": "de-b"}


def finding(check, uuid, evidence, *, topic="hosting", risk="medium", fix=None, ok=False):
    return {"checkId": check, "topic": topic, "risk": risk, "target": f"node:{uuid}",
            "ok": ok, "evidence": evidence, "fixId": fix}  # fmt: skip


def fleet():
    """nl-a, nl-b and nl-c close to each other, de-a and de-b too; one AS for both
    countries; nl-a and nl-b share a host key; two nodes allow passwords. Which nets
    are neighbours the rule decides (`with`); the row only joins them, so the nets here
    stay in the ranges for documentation."""
    nets = {"u-a": "203.0.113.0/24", "u-b": "203.0.113.0/24", "u-c": "192.0.2.0/24",
            "u-d": "198.51.100.0/24", "u-e": "198.51.100.0/24"}  # fmt: skip
    close = {"u-a": ["nl-b", "nl-c"], "u-b": ["nl-a", "nl-c"], "u-c": ["nl-a", "nl-b"],
             "u-d": ["de-b"], "u-e": ["de-a"]}  # fmt: skip
    found = [finding("fleet.same_24", u, {"net": nets[u], "with": close[u]}) for u in nets]
    nl, de = ["nl-a", "nl-b", "nl-c"], ["de-a", "de-b"]
    for uuid in ("u-a", "u-b", "u-c"):
        found.append(finding("fleet.same_asn", uuid, {"asn": 64500, "country": "NL", "nodes": nl}))
    for uuid in ("u-d", "u-e"):
        found.append(finding("fleet.same_asn", uuid, {"asn": 64500, "country": "DE", "nodes": de}))
    for uuid, other in (("u-a", "nl-b"), ("u-b", "nl-a")):
        found.append(finding("fleet.shared_hostkey", uuid, {"fingerprint": "SHA256:x",
                                                            "with": [other]},
                             fix="hostkeys.regenerate"))  # fmt: skip
    for uuid in ("u-a", "u-d"):
        found.append(finding("ssh.password", uuid, {}, topic="scanning", risk="high",
                             fix="ssh.key_only"))  # fmt: skip
    found.append(finding("ssh.password", "u-b", {}, topic="scanning", risk="high", ok=True))
    return found


def cells(row):
    return [cell.plain for cell in row.cells]


def test_one_problem_on_several_nodes_is_one_row():
    grouped = rows(fleet(), NAMES)
    password = [r for r in grouped if r[0]["checkId"] == "ssh.password"]
    assert len(password) == 1 and [m["target"] for m in password[0]] == ["node:u-a", "node:u-d"]
    # K22 stays: the fleet checks are a row a group of nodes.
    nets = [r for r in grouped if r[0]["checkId"] == "fleet.same_24"]
    assert [[m["target"] for m in r] for r in nets] == [
        ["node:u-a", "node:u-b", "node:u-c"],
        ["node:u-d", "node:u-e"],
    ]
    assert len(grouped) == 6


def test_what_kerberos_fixes_is_a_row_an_area():
    auto = report_blocks(fleet(), NAMES)[0]
    assert auto.title == t("s6.block.auto") and len(auto.rows) == 1
    risk, area, what, where_cell = cells(auto.rows[0])
    assert t("risk.high") in risk, "the worst risk of the area"
    assert area == t("area.access")
    assert t("check.ssh.password.short") in what and t("check.fleet.shared_hostkey.short") in what
    assert where_cell == "nl-a, de-a, nl-b", "the nodes of the worst problem first"
    assert auto.note == t("s6.block.auto.note", problems=2, areas=1)
    details = " ".join(line.plain for line in auto.rows[0].details)
    assert t("check.ssh.password.title") in details and t("check.ssh.password.threat") in details


def test_what_is_left_to_the_person_is_a_row_a_problem_with_what_to_do():
    manual = report_blocks(fleet(), NAMES)[1]
    assert manual.title == t("s6.block.manual") and len(manual.rows) == 4
    first = cells(manual.rows[0])
    assert first[1] == t("check.fleet.same_24.title", net="192.0.2.0/24, 203.0.113.0/24")
    assert first[2] == "nl-a, nl-b, nl-c"
    how = t("check.fleet.same_24.how")
    assert first[3] == how[:1].upper() + how[1:]
    assert [cells(r)[2] for r in manual.rows] == ["nl-a, nl-b, nl-c", "de-a, de-b",
                                                  "nl-a, nl-b, nl-c", "de-a, de-b"]  # fmt: skip


def test_counts_follow_the_rows_and_the_score_stays():
    numbers = counts(fleet(), NAMES)
    assert numbers == {"problems": 6, "high": 1, "auto": 2, "manual": 4}
    before = score(fleet())
    assert score(fleet()) == before  # the blocks change nothing in the model
    fixed = [dict(f, ok=True) if f["fixId"] and not f["ok"] else f for f in fleet()]
    assert projected(fleet()) == score(fixed) > before


def test_the_summary_says_what_kerberos_fixes_and_what_is_left():
    lines = [line.plain for line in check_summary(fleet(), NAMES, hint=True)]
    assert lines[0] == t("s6.found", problems=6, high=1)
    assert lines[1] == t("s6.auto", auto=2) + t("s6.after", score=projected(fleet()))
    assert lines[2] == t("s6.manual", manual=4)
    assert lines[3] == t("s6.fix_hint")
    plain = [line.plain for line in check_summary(fleet(), NAMES, hint=False)]
    assert t("s6.fix_hint") not in plain


def test_explanations_fold_into_one_row_that_space_opens():
    found = fleet() + [finding("node.icmp", u, {}, topic="scanning", risk="info")
                       for u in ("u-a", "u-b")]  # fmt: skip
    info = report_blocks(found, NAMES)[-1]
    assert info.title == t("s6.block.info") and len(info.rows) == 1
    assert cells(info.rows[0])[1] == t("s6.info.row", n=1)
    listing = BlockList([info])
    closed = render(listing, 80)
    assert t("check.node.icmp.title") not in closed
    listing.handle("space")
    assert t("check.node.icmp.title") + " · nl-a, nl-b" in render(listing, 80)


def render(listing, width):
    console = Console(width=width, record=True, color_system=None, force_terminal=False)
    console.print(listing)
    return console.export_text()


def test_every_line_stays_in_its_block_at_80_columns():
    listing = BlockList(report_blocks(fleet(), NAMES))
    listing.expanded = {("area", "access")}
    lines = render(listing, 80).splitlines()
    assert lines and all(line[0] in "╭│╰" and len(line) <= 80 for line in lines if line)
    assert all(line.endswith(("╮", "│", "╯")) for line in lines if line)


def test_where_names_three_nodes_and_counts_more():
    assert where(["a", "b", "c"]) == "a, b, c"
    assert where(["a", "b", "c", "d"]) == t("where.nodes", n=4) == "4 ноды"
    assert where([], ["x", "y", "z", "w", "v"]) == "x, y, z " + t("where.more", n=2)


def test_every_measure_has_an_area_and_words():
    """K23: the same areas on every screen, so no measure is left as «Другое»."""
    from kerberos.fixes.self_steal import AGENT_STEPS

    fixes = set(NODE_ORDER) | set(PANEL_ORDER) | set(AGENT_STEPS) | {
        "self_steal.own_profile", "self_steal.profile", "self_steal.node", "self_steal.squads",
        "self_steal.hosts",
        "sub.templates", "xui.reality"}  # fmt: skip
    for fix_id in fixes:
        assert area_of(fix_id) in AREAS, fix_id
        assert f"fix.{fix_id}.short" in TEXT, fix_id
    for group in (*AREAS, *PLAN_GROUPS):
        assert f"area.{group}" in TEXT, group
    assert set(FIX_AREA) == fixes, "FIX_AREA lists exactly the measures KERBEROS has"


def test_every_problem_kerberos_fixes_has_short_words():
    for item in REGISTRY:
        if item.kind == "fix" and item.fix_id:
            assert f"check.{item.check_id}.short" in TEXT, item.check_id


def test_demo_report_blocks_cover_every_problem():
    from demo_input import demo_input

    _env, data = demo_input()
    findings = run_checks(data)
    names = {n.node.uuid: n.node.name for n in data.nodes}
    blocks = report_blocks(findings, names)
    numbers = counts(findings, names)
    manual = next(b for b in blocks if b.title == t("s6.block.manual"))
    assert len(manual.rows) == numbers["manual"]
    auto = next(b for b in blocks if b.title == t("s6.block.auto"))
    assert auto.note == t("s6.block.auto.note", problems=numbers["auto"], areas=len(auto.rows))
