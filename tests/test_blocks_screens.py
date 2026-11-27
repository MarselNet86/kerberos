"""The plan, consent and S9 in blocks (tech.md §6 S7, S9, §14.4, K23).

The owner on the first screens of K22: «читать сплошным текстом нереально». The plan
is a row a group of measures with a mark for the whole group, opened by node with →;
the own domains a row a node; consent and S9 say what changes by area.
"""

from helpers import S4_KEYS, flat, login_keys, make_app, on, on_group, seen

from kerberos.copy import t
from kerberos.demo.fleet import build_nodes
from kerberos.flow import EXIT_OK

TO_PLAN = login_keys() + ["enter"] + S4_KEYS + ["enter", "enter"]  # S3, S4, admin key
TO_PLAN += ["enter", "enter", "enter"]  # S4 summary, whois, S6 → S7
OUT = ["esc", "q", "enter"]  # S7 → S6 → quit
APPLY = ["enter", "enter"]  # S7 → consent → accept


def fix(keys, *, nodes=None, height=46, width=100):
    app, term = make_app(TO_PLAN + list(keys), nodes=nodes, height=height, width=width)
    return app, term, app.run("fix")


def plans(term):
    return [
        f for f in term.frames if f.splitlines()[0].startswith("/// kerberos  " + t("plan.title"))
    ]


def items(app, fix_id):
    return [i for i in app.session.data["plan"] if i.fix_id == fix_id]


def test_a_group_opens_by_node_and_folds_again():
    _app, term, _code = fix(on_group("scanners", "right", "left") + OUT)
    frames = plans(term)
    label = t("fix.mptcp.guard.label")
    opened = [f for f in frames if label in f]
    assert opened and label not in frames[0] and label not in frames[-1], "folded, opened, folded"
    assert "→ " + t("keys.open_group") in frames[0].splitlines()[-1]
    assert "← " + t("keys.close_group") in opened[0].splitlines()[-1]


def test_space_on_a_group_marks_all_its_rows_and_again_clears_them():
    app, _term, _code = fix(on_group("ssh_port", "space") + OUT)
    assert all(i.selected for i in items(app, "ssh.port")), "the person marks the ports at once"
    app, _term, _code = fix(on_group("ssh_port", "space", "space") + OUT)
    assert not any(i.selected for i in items(app, "ssh.port"))


def test_a_group_marked_in_part_says_how_much():
    app, term, _code = fix(on("nl-1", "ssh.port", "space") + OUT)
    row = next(line for line in plans(term)[-1].splitlines() if t("area.ssh_port") in line)
    assert "[~]" in row and t("plan.partial", n=1, total=4) in row
    assert [i.selected for i in items(app, "ssh.port")] == [True, False, False, False]


def test_e_on_the_cdn_group_confirms_the_nets_of_its_filter():
    app, _term, _code = fix(on_group("cdn", "e", "enter") + OUT)
    edge = items(app, "cdn.edge_only")[0]
    assert edge.selected and edge.params["nets"], "confirmed without opening the group"


def test_space_on_a_group_waiting_for_input_says_what_it_waits_for():
    nodes = build_nodes()
    # Space unmarks the group (its filter waits for nets), Space again marks what it can.
    app, term, _code = fix(on_group("cdn", "space", "space") + OUT, nodes=nodes)
    assert seen(term, t("plan.need_edges"))
    assert not items(app, "cdn.edge_only")[0].selected
    assert items(app, "xhttp.padding")[0].selected


def test_domain_rows_show_the_record_to_make_then_the_reserve():
    _app, term, _code = fix(on("nl-1", "self_steal", "d", *"late.example.com", "enter") + OUT)
    plan = plans(term)[-1]
    row = next(line for line in plan.splitlines() if "late.example.com" in line)
    assert "… " + t("plan.domain.waiting") in row
    assert t("plan.domain.record", record="A late.example.com → 203.0.113.10") in flat(plan)
    assert t("plan.block.domain.need") in plan
    _app, term, _code = fix(on("nl-1", "self_steal", "d", *"nl-1.example.com", "enter") + OUT)
    row = next(line for line in plans(term)[-1].splitlines() if "nl-1.example.com" in line)
    assert "[✓]" in row and t("plan.domain.ok") in row and t("plan.domain.no_reserve") in row


def test_consent_says_what_changes_by_area_and_the_warnings_as_points():
    _app, term, _code = fix(["enter"] + ["esc"] + OUT)
    consent = next(f for f in term.frames if t("consent.title") in f.splitlines()[0])
    text = flat(consent)
    assert t("consent.block.what") in text and t("area.access") in text
    assert t("fix.ssh.key_only.short") + " (nl-1, de-1)" in text
    assert t("consent.block.warnings") in text and "• " + t("fix.key_only.warning") in text


def test_s9_in_blocks_and_an_area_opens_by_node():
    keys = on_group("ssh_port", "space") + APPLY + ["space", "enter"]
    app, term, code = fix(keys)
    assert code == EXIT_OK
    s9 = [
        f for f in term.frames if f.splitlines()[0].startswith("/// kerberos  " + t("done.title"))
    ]
    first, opened = s9[0], s9[-1]
    for key in ("s9.block.save", "s9.block.done", "s9.block.next"):
        assert t(key) in first, key
    assert t("fix.ssh.key_only.label") not in first, "folded: an area a row"
    assert "✓ nl-1: " + t("fix.access.admin_keys.label") in flat(opened)


def test_s9_names_what_did_not_apply_with_its_reason():
    nodes = {n.name: n for n in build_nodes()}
    nodes["nl-2"].state["fail"] = {"mptcp.guard": "mptcp_absent"}
    _app, term, _code = fix(APPLY + ["enter"], nodes=list(nodes.values()))
    s9 = next(
        f for f in term.frames if f.splitlines()[0].startswith("/// kerberos  " + t("done.title"))
    )
    text = flat(s9)
    assert t("s9.block.failed") in text
    assert "↺ nl-2: " + t("fix.mptcp.guard.label") in text
    assert t("apply.rolled_back", reason=t("error.mptcp_absent")) in text


def test_blocks_read_without_colour_at_80_columns():
    _app, term, _code = fix(on("nl-1", "ssh.port", "space") + OUT, width=80, height=30)
    plan = plans(term)[-1]
    assert all(len(line) <= 80 for line in plan.splitlines())
    assert "[~]" in plan and "[✓]" in plan and "[ ]" in plan, "marks are words, not colours"
    assert t("plan.block.auto") in plan
