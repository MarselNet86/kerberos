"""XHTTP padding, uplink GET, the CDN origin filter and the watch end to end (§10.6, K8)."""

import random

from helpers import S4_KEYS, login_keys, make_app, on, seen
from hypothesis import given
from hypothesis import strategies as st

from kerberos.copy import t
from kerberos.demo.fleet import build_nodes, build_panel
from kerberos.fixes import xhttp
from kerberos.fixes.journal import RunStore
from kerberos.flow import EXIT_OK, EXIT_PARTIAL

TO_PLAN = login_keys() + ["enter"] + S4_KEYS + ["enter", "enter"]  # S3, S4, admin key
TO_PLAN += ["enter", "enter", "enter"]  # S4 summary, whois, S6 → S7
APPLY = ["enter", "enter", "enter"]  # S7 → consent → accept → S9 Enter
ROLLBACK = ["enter", "enter", "enter", "x"]  # the panel: the token saved by the fix run
CONFIRM_EDGES = on("fi-1", "cdn.edge_only", "e", "enter")  # the nets, all marked, confirmed
LEAVE = ["esc", "q", "enter"]  # S7 → S6 → quit


def run_fix(extra, panel=None, nodes=None, state=None):
    panel = panel or build_panel()
    nodes = nodes or {n.name: n for n in build_nodes()}
    app, term = make_app(TO_PLAN + list(extra), panel=panel, nodes=list(nodes.values()),
                         height=46, state=state)  # fmt: skip
    return app, term, app.run("fix"), panel, nodes


def last_run(app):
    return RunStore(app.env.state, app.env.clock).runs()[0]


def changes(app, fix_id):
    return [c for c in last_run(app)["changes"] if c["fixId"] == fix_id]


def xhttp_extra(panel):
    profile = next(p for p in panel.profiles if p["name"] == "FI-1")
    inbound = next(i for i in profile["config"]["inbounds"] if i["tag"] == "XHTTP-FI1")
    return inbound["streamSettings"]["xhttpSettings"].get("extra") or {}


def cdn_host(panel):
    return next(h for h in panel.hosts if h["remark"] == "FI CDN")


def test_cdn_filter_padding_and_get_apply_and_roll_back():
    app, term, code, panel, nodes = run_fix(CONFIRM_EDGES + APPLY)
    assert code == EXIT_OK
    assert seen(term, t("plan.edges.title", node="fi-1")) and seen(term, "192.0.2.0/24")
    assert seen(term, t("fix.edge_only.warning")) and seen(term, t("fix.padding.warning"))
    fi1 = nodes["fi-1"]
    assert fi1.state["edge_filter"] == {"paths": ["/api/stream"], "nets": ["192.0.2.0/24"]}
    prober = app.env.prober
    direct = prober.http("198.51.100.77", 8443, "cdn.example.com", "/api/stream")
    missing = prober.http("198.51.100.77", 8443, "cdn.example.com", "/no-such-page")
    assert (direct.status, direct.body) == (missing.status, missing.body)
    assert prober.http("192.0.2.200", 443, "cdn.example.com", "/api/stream").status == 400
    after = [f for f in last_run(app)["findingsAfter"] if f["checkId"] == "cdn.origin_direct"]
    assert after and all(f["ok"] for f in after)
    server = xhttp.padding_of(xhttp_extra(panel))
    assert set(server) == set(xhttp.PADDING_KEYS)
    assert xhttp_extra(panel)["noSSEHeader"] is True, "the rest of extra stays"
    host = cdn_host(panel)["xhttpExtraParams"]
    assert xhttp.padding_of(host) == server, "server and client carry one set"
    assert host["uplinkHTTPMethod"] == "GET" and host["xmux"]["maxConcurrency"] == "16-32"
    assert {c["state"] for c in changes(app, "xhttp.padding")} == {"applied"}
    padding = changes(app, "xhttp.padding")[0]
    assert server["xPaddingKey"] not in str(last_run(app)), "padding values stay out of run.json"
    assert padding["details"]["writtenPath"].endswith(".json")

    app.env.terminal.feed(*ROLLBACK)
    assert app.run("rollback") == EXIT_OK
    assert fi1.state["edge_filter"] is None
    assert xhttp.padding_of(xhttp_extra(panel)) == {} and xhttp_extra(panel)["noSSEHeader"]
    host = cdn_host(panel)["xhttpExtraParams"]
    assert xhttp.padding_of(host) == {} and host["uplinkHTTPMethod"] == "POST"
    assert host["xmux"]["maxConcurrency"] == "16-32"


def test_nets_that_miss_the_edge_are_rolled_back():
    nodes = {n.name: n for n in build_nodes()}
    nodes["fi-1"].state["edges"] = [{"net": "203.0.113.0/24", "count": 7}]
    app, term, code, _panel, _nodes = run_fix(CONFIRM_EDGES + APPLY, nodes=nodes)
    assert code == EXIT_PARTIAL
    edge = changes(app, "cdn.edge_only")[0]
    assert edge["state"] == "rolled_back" and edge["error"] == "recheck_failed"
    assert nodes["fi-1"].state["edge_filter"] is None, "the edge must never stay cut off"


def test_realip_blocks_the_filter():
    nodes = {n.name: n for n in build_nodes()}
    nodes["fi-1"].state["facts"]["nginx"]["realip"] = True
    app, term, _code, _panel, _nodes = run_fix(on("fi-1", "cdn.edge_only", "e", "space") + LEAVE,
                                               nodes=nodes)  # fmt: skip
    assert seen(term, t("plan.blocked.realip_enabled"))
    assert not [cmd for _a, cmd in app.env.transport.log if "edge-sources" in cmd]
    assert nodes["fi-1"].state.get("edge_filter") is None


def test_a_skips_the_filter_and_enter_asks_for_nets():
    app, term, _code, _panel, _nodes = run_fix(["a"] + LEAVE)
    # The CDN filter waits for its nets, `a` leaves the four SSH ports; the four own
    # domains are a block of their own (K23).
    in_groups = [i for i in app.session.data["plan"] if i.fix_id != "self_steal"]
    left = [i for i in in_groups if i.fix_id in ("ssh.port", "ssh.panel_only", "cdn.edge_only")]
    assert seen(term, t("plan.block.auto.note", n=len(in_groups) - len(left), total=len(in_groups)))
    app2, term2, _code, _p, _n = run_fix(on("fi-1", "cdn.edge_only", "space") + ["enter"] + LEAVE)
    assert seen(term2, t("plan.need_edges"))
    assert not [cmd for _a, cmd in app2.env.transport.log if cmd.startswith("apply")]


def test_panel_failure_in_the_middle_of_padding_undoes_it():
    panel = build_panel()
    panel.fail("PATCH", "/hosts", 500, times=4)  # the first try and three retries
    keys = on("template", "sub.template", "space") + APPLY  # no sub.template: padding first
    app, term, code, panel, _nodes = run_fix(keys, panel=panel)
    assert code == EXIT_PARTIAL
    padding = changes(app, "xhttp.padding")[0]
    assert padding["state"] == "rolled_back" and padding["error"] == "server_error"
    assert xhttp.padding_of(xhttp_extra(panel)) == {}, "the server got its padding back out"
    assert xhttp.padding_of(cdn_host(panel)["xhttpExtraParams"]) == {}
    assert changes(app, "xhttp.uplink_get")[0]["state"] == "applied"


def test_watch_is_installed_by_choice_and_rolled_back():
    app, _term, code, _panel, nodes = run_fix(on("nl-1", "watch.install", "space") + APPLY)
    assert code == EXIT_OK
    assert nodes["nl-1"].state["facts"]["watch"]["installed"] is True
    assert changes(app, "watch.install")[0]["state"] == "applied"
    app.env.terminal.feed(*ROLLBACK)
    app.run("rollback")
    assert nodes["nl-1"].state["facts"]["watch"]["installed"] is False


def test_padding_of_a_profile_shared_meanwhile_is_not_written_twice():
    stream = {"network": "xhttp", "xhttpSettings": {"path": "/x"}}
    config = {"inbounds": [{"tag": "X", "streamSettings": stream}]}
    once, written = xhttp.add_padding(config, ["X"], random.Random(1))
    again, second = xhttp.add_padding(once, ["X"], random.Random(2))
    assert written and second == {} and again == once


# -- pure functions of fixes/xhttp.py (Hypothesis) -------------------------------
simple = st.one_of(st.integers(), st.text(max_size=8), st.booleans())
extras = st.dictionaries(st.sampled_from(["noSSEHeader", "xmux", "scMaxEachPostBytes", "mode"]),
                         simple, min_size=1)  # fmt: skip
inbounds = st.builds(
    lambda tag, extra, path: {
        "tag": tag,
        "protocol": "vless",
        "streamSettings": {
            "network": "xhttp",
            "xhttpSettings": {"path": path, **({"extra": extra} if extra else {})},
        },
    },
    st.sampled_from(["A", "B", "C", "D"]),
    st.one_of(st.none(), extras),
    st.sampled_from(["/a", "/b/c"]),
)


@given(st.lists(inbounds, max_size=4, unique_by=lambda i: i["tag"]),
       st.sets(st.sampled_from(["A", "B", "C", "D"])), st.integers(0, 2**32))  # fmt: skip
def test_padding_comes_out_exactly_as_it_went_in(items, tags, seed):
    config = {"inbounds": items, "routing": {"rules": []}}
    padded, written = xhttp.add_padding(config, sorted(tags), random.Random(seed))
    assert set(written) == {i["tag"] for i in items} & tags
    for item in padded["inbounds"]:
        extra = item["streamSettings"]["xhttpSettings"].get("extra")
        assert xhttp.padding_of(extra) == written.get(item["tag"], {})
    again, second = xhttp.add_padding(padded, sorted(tags), random.Random(seed + 1))
    assert second == {} and again == padded, "adding twice writes once"
    back, changed = xhttp.remove_padding(padded, written)
    assert changed == [] and back == config


@given(st.integers(0, 2**32))
def test_padding_fields_shapes(seed):
    fields = xhttp.padding_fields(random.Random(seed))
    assert set(fields) == set(xhttp.PADDING_KEYS)
    low, high = (int(x) for x in fields["xPaddingBytes"].split("-"))
    assert 64 <= low <= 256 and 768 <= high <= 1536, "random per inbound (K26)"
    assert fields["xPaddingObfsMode"] is True
    assert fields["xPaddingPlacement"] == "queryInHeader" and fields["xPaddingMethod"] == "tokenish"
    key, header = fields["xPaddingKey"], fields["xPaddingHeader"]
    assert key.isalpha() and key.islower() and 6 <= len(key) <= 10
    word, suffix = header.split("-")[1:]
    assert header.startswith("X-") and word in xhttp.HEADER_WORDS
    assert len(suffix) == 4 and suffix[0].isupper() and suffix[1:].islower()


host_extras = st.dictionaries(
    st.sampled_from(["uplinkHTTPMethod", "xmux", "a"]), st.sampled_from(["POST", "PUT", "GET", 1])
)


@given(st.one_of(st.none(), host_extras))
def test_uplink_goes_back_to_what_it_was(extra):
    previous = (extra or {}).get("uplinkHTTPMethod")
    changed = xhttp.uplink_get(extra)
    assert changed["uplinkHTTPMethod"] == "GET"
    assert xhttp.uplink_back(changed, previous, extra is None) == extra
