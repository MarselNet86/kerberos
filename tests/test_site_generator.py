"""Stub sites of self-steal: one of its own per node, previewed in S7 (tech.md §10.4, K10)."""

import random

from demo_input import demo_input
from helpers import flat, login_keys, make_app, on, seen
from hypothesis import given, settings
from hypothesis import strategies as st

from kerberos import agent
from kerberos.checks import run_checks
from kerberos.copy import t
from kerberos.fixes.journal import RunStore
from kerberos.fixes.plan import build_plan, free_site_seed

TO_PLAN = login_keys() + ["enter", "enter"] + ["enter"] * 5 + ["esc"] + ["enter", "enter"]
TO_PLAN += ["enter", "enter", "enter"]
MINE = {"mode": "mine", "keys": ["ssh-ed25519 AAAA admin@laptop"]}


def layout(seed: int) -> str:
    return agent.template_hash(agent.site_html(seed, "example.com"))


@given(st.integers(0, agent.SITE_SEEDS - 1))
@settings(max_examples=60, deadline=None)
def test_any_seed_gives_a_stable_readable_page(seed):
    page = agent.site_html(seed, "node.example.com")
    assert page == agent.site_html(seed, "node.example.com")
    theme = agent.site_spec(seed)["theme"]
    for key in ("text", "muted", "accent"):
        assert agent.contrast(theme[key], theme["background"]) >= 4.5
    assert agent.contrast(theme["onAccent"], theme["accent"]) >= 4.5
    assert page.count("<section") >= 4 and "<h1>" in page


def test_free_seed_avoids_layouts_in_use():
    rng = random.Random(1)
    used = {layout(seed) for seed in range(10)}
    taken = set(used)
    seeds = [free_site_seed(used, rng) for _ in range(20)]
    layouts = {layout(seed) for seed in seeds}
    assert len(layouts) == 20 and not layouts & taken and layouts <= used


def test_plan_gives_each_node_its_own_site():
    _env, data = demo_input()
    items = build_plan(run_checks(data), data, MINE, {}, random.Random(7))
    steal = [item for item in items if item.fix_id == "self_steal"]
    layouts = {layout(item.params["siteSeed"]) for item in steal}
    in_use = {site["template"] for node in data.nodes for site in node.sites.values() if site}
    assert len(steal) >= 2 and len(layouts) == len(steal) and not layouts & in_use


def preview_of(frame: str) -> str:
    text = flat(frame)
    start = text.index(t("plan.site", node="nl-1", title="", kind="")[:12])
    return text[start : text.index(t("plan.site.again"), start)]


def test_preview_g_and_report():
    keys = TO_PLAN + on("nl-1", "self_steal", "g", "d", *"nl-1.example.com", "enter")
    app, term = make_app(keys + ["enter", "enter", "space", "enter"], height=46)  # S9: Space
    app.run("fix")
    frames = [f for f in term.frames if t("plan.site.again") in flat(f)]
    previews = []
    for frame in frames:
        if not previews or preview_of(frame) != previews[-1]:
            previews.append(preview_of(frame))
    assert len(previews) == 2, "g draws another site"
    run = RunStore(app.env.state, app.env.clock).runs()[0]
    change = next(c for c in run["changes"] if c["fixId"] == "self_steal.site")
    site = change["details"]["site"]
    assert site["title"] in previews[-1] and t(f"site.kind.{site['kind']}") in previews[-1]
    assert agent.site_spec(change["params"]["siteSeed"])["title"] == site["title"]
    shown = t("s9.site", title=site["title"], kind=t(f"site.kind.{site['kind']}"),
              background=site["background"], accent=site["accent"])  # fmt: skip
    assert seen(term, shown)
    report = RunStore(app.env.state, app.env.clock).report_text(run["runId"])
    assert t("report.site", title=site["title"], kind=t(f"site.kind.{site['kind']}"),
             background=site["background"], accent=site["accent"]) in report  # fmt: skip


def test_demo_draws_the_same_sites():
    seeds = []
    for _ in range(2):
        app, _term = make_app(TO_PLAN + on("nl-1", "self_steal") + ["esc", "q", "enter"],
                              height=46)  # fmt: skip
        app.run("fix")
        plan = app.session.data["plan"]
        seeds.append(next(i.params["siteSeed"] for i in plan if i.fix_id == "self_steal"))
    assert seeds[0] == seeds[1]
