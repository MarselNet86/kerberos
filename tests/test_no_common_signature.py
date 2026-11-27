"""K26: no common signature (tech.md v32, §10.2, §10.5, §10.6, §10.9).

What KERBEROS writes the same on every server of every person who runs it becomes its
own per inbound, per host or per panel: the range of the XHTTP padding, the uTLS
fingerprint of a host and the probe of the reserve. And `host.ru_hoster` finds a node
whose network is registered in Russia.
"""

import copy
import json
import random
import uuid as uuidlib

from demo_input import demo_input
from helpers import S4_KEYS, login_keys, make_app, seen
from hypothesis import given
from hypothesis import strategies as st

from kerberos import templates
from kerberos.checks.rules import probe_interval
from kerberos.copy import t
from kerberos.demo.fleet import build_nodes, build_panel
from kerberos.fixes import subscription, xhttp
from kerberos.fixes.hosts import FINGERPRINTS, fingerprint_of
from kerberos.flow import EXIT_OK
from kerberos.whois import AsInfo

TO_PLAN = login_keys() + ["enter"] + S4_KEYS + ["enter", "enter"]  # S3, S4, admin key
TO_PLAN += ["enter", "enter", "enter"]  # S4 summary, whois, S6 → S7
APPLY = ["enter", "enter", "enter"]  # the marked fixes: sub.template writes the templates


def run_fix(extra, panel=None, nodes=None, state=None):
    panel = panel or build_panel()
    nodes = nodes or build_nodes()
    app, term = make_app(TO_PLAN + list(extra), panel=panel, nodes=nodes, height=46, state=state)
    return app, term, app.run("fix"), panel, nodes


def reserve_template(panel):
    return next(t for t in panel.templates if t["name"] == subscription.RESERVE_NAME)


def ping(template):
    return template["templateJson"]["burstObservatory"]["pingConfig"]


# -- XHTTP padding ------------------------------------------------------------------------
@given(st.integers(0, 2**32))
def test_the_padding_range_is_random_within_its_bounds(seed):
    low, high = (int(x) for x in xhttp.padding_fields(random.Random(seed))["xPaddingBytes"]
                 .split("-"))  # fmt: skip
    assert xhttp.PADDING_LOW[0] <= low <= xhttp.PADDING_LOW[1]
    assert xhttp.PADDING_HIGH[0] <= high <= xhttp.PADDING_HIGH[1]


def test_two_inbounds_get_ranges_of_their_own():
    config = {"inbounds": [
        {"tag": tag, "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/x"}}}
        for tag in ("XHTTP-A", "XHTTP-B")
    ]}  # fmt: skip
    _config, written = xhttp.add_padding(config, ["XHTTP-A", "XHTTP-B"], random.Random(7))
    assert written["XHTTP-A"]["xPaddingBytes"] != written["XHTTP-B"]["xPaddingBytes"]
    seen_ranges = {xhttp.padding_fields(random.SystemRandom())["xPaddingBytes"] for _ in range(40)}
    assert len(seen_ranges) > 30, "not one range for everybody"


# -- uTLS fingerprint ---------------------------------------------------------------------
@given(st.text(min_size=1, max_size=40))
def test_a_host_gets_the_same_fingerprint_every_time(key):
    assert fingerprint_of(key) == fingerprint_of(key) and fingerprint_of(key) in FINGERPRINTS


def test_both_fingerprints_occur():
    chosen = {fingerprint_of(str(uuidlib.UUID(int=n))) for n in range(64)}
    assert chosen == {"chrome", "firefox"}, "not firefox for every host of KERBEROS"


def test_the_fingerprint_fix_writes_the_choice_of_the_host():
    from helpers import on

    app, _term, code, panel, _nodes = run_fix(on("host", "host.fingerprint", "space") + APPLY)
    assert code == EXIT_OK
    host = next(h for h in panel.hosts if h["remark"] == "NL Reality")
    assert host["fingerprint"] == fingerprint_of(host["uuid"])


# -- the probe of the reserve -------------------------------------------------------------
@given(st.integers(0, 2**32))
def test_a_new_probe_is_never_the_old_one(seed):
    probe = subscription.new_probe(random.Random(seed))
    assert probe != subscription.OLD_PROBE
    assert probe["destination"] in subscription.PROBE_URLS
    assert 60 <= int(probe["interval"].rstrip("s")) <= 90
    assert subscription.own_probe({"burstObservatory": {"pingConfig": dict(probe)}}) == probe


def test_panels_get_probes_of_their_own():
    probes = {json.dumps(subscription.new_probe(random.SystemRandom()), sort_keys=True)
              for _ in range(20)}  # fmt: skip
    assert len(probes) > 5


def test_a_probe_is_known_only_from_its_sets():
    def tpl(interval, destination):
        return {"burstObservatory": {"pingConfig": {"interval": interval,
                                                    "destination": destination}}}  # fmt: skip

    url = subscription.PROBE_URLS[3]
    assert subscription.own_probe(tpl("75s", url)) == {"interval": "75s", "destination": url}
    assert subscription.own_probe(tpl("60s", subscription.PROBE_URLS[0])) is None, "before K26"
    assert subscription.probe_of(tpl("60s", subscription.PROBE_URLS[0])) is not None
    for interval, destination in (("45s", url), ("120s", url), ("1m", url),
                                  ("75s", "https://example.com/generate_204")):  # fmt: skip
        assert subscription.probe_of(tpl(interval, destination)) is None
    assert subscription.own_probe(None) is None and subscription.own_probe({}) is None


def test_the_probe_goes_into_the_reserve_only_and_templates_stay():
    probe = {"interval": "83s", "destination": subscription.PROBE_URLS[4]}
    reserve = subscription.build("reserve", ["nl-1.example.com"], probe)
    assert reserve["burstObservatory"]["pingConfig"]["interval"] == "83s"
    assert probe_interval(reserve) == 83, "sub.probe_interval still passes"
    assert subscription.build("single", ["nl-1.example.com"], probe) == subscription.build(
        "single", ["nl-1.example.com"])  # fmt: skip
    raw = templates.load(templates.RESERVE)
    assert raw["burstObservatory"]["pingConfig"]["interval"] == "60s", "the file is as it was"
    assert subscription.own_write("reserve", reserve)
    assert subscription.own_write("reserve", subscription.build("reserve", ["nl-1.example.com"]))


def test_the_fix_writes_a_probe_of_this_panel_and_a_second_run_keeps_it():
    nodes = build_nodes()
    app, _term, code, panel, _nodes = run_fix(APPLY, nodes=nodes)
    assert code == EXIT_OK
    probe = dict(ping(reserve_template(panel)))
    assert subscription.own_probe(reserve_template(panel)["templateJson"]) == {
        "interval": probe["interval"], "destination": probe["destination"]}  # fmt: skip
    # A host added since keeps the person's template: the next run moves it to KERBEROS's.
    model = next(h for h in panel.hosts if h["remark"] == "NL Reality")
    theirs = next(x["uuid"] for x in panel.templates if not x["name"].startswith("KERBEROS"))
    panel.hosts.append({**copy.deepcopy(model), "uuid": str(uuidlib.uuid4()),
                        "remark": "NL Extra", "xrayJsonTemplateUuid": theirs})  # fmt: skip
    written = len([m for m in panel.mutations if "subscription-templates" in m[1]])
    keys = ["enter", "esc", "enter", "enter"] + APPLY  # a later run: S3, kz-1, S4, S6 → S7
    app, _term = make_app(keys, panel=panel, nodes=nodes, state=app.env.state, height=46)
    assert app.run("fix") == EXIT_OK
    extra = next(h for h in panel.hosts if h["remark"] == "NL Extra")
    assert extra["xrayJsonTemplateUuid"] != theirs, "the second run did run sub.template"
    assert ping(reserve_template(panel)) == probe, "kept"
    assert len([m for m in panel.mutations if "subscription-templates" in m[1]]) == written


def test_a_template_with_the_probe_of_before_gets_its_own_without_a_question():
    panel = build_panel()
    old = subscription.build("reserve", [])  # what every KERBEROS wrote before K26
    panel.templates.append(
        {
            "uuid": str(uuidlib.uuid4()),
            "name": subscription.RESERVE_NAME,
            "templateType": "XRAY_JSON",
            "templateJson": copy.deepcopy(old),
        }
    )
    _app, term, code, panel, _nodes = run_fix(APPLY, panel=panel)
    assert code == EXIT_OK
    assert not seen(term, t("tpl.diff.question"))
    assert subscription.own_probe(reserve_template(panel)["templateJson"]) is not None


def test_a_hand_edited_probe_is_asked_about():
    panel = build_panel()
    edited = subscription.build("reserve", [])
    edited["burstObservatory"]["pingConfig"]["interval"] = "30s"
    panel.templates.append(
        {
            "uuid": str(uuidlib.uuid4()),
            "name": subscription.RESERVE_NAME,
            "templateType": "XRAY_JSON",
            "templateJson": edited,
        }
    )
    _app, term, _code, _panel, _nodes = run_fix(APPLY + ["esc", "enter"], panel=panel)
    assert seen(term, t("tpl.diff.question"))


# -- host.ru_hoster -----------------------------------------------------------------------
def ru_hoster(data):
    from kerberos.checks.rules import ru_hoster as rule

    return rule(data)


def node_ip(data, name):
    return next(n.ipv4 for n in data.nodes if n.node.name == name)


def test_a_node_on_a_network_of_russia_is_found():
    _env, data = demo_input()
    assert ru_hoster(data) == [], "the demo fleet has none: its score stays"
    data.asn[node_ip(data, "nl-1")] = AsInfo("64510", "EXAMPLE-RU-VDS", "RU")
    found = ru_hoster(data)
    assert [f["target"] for f in found] == [
        "node:" + next(n.node.uuid for n in data.nodes if n.node.name == "nl-1")
    ]
    assert found[0]["ok"] is False and found[0]["evidence"] == {
        "asn": "64510",
        "name": "EXAMPLE-RU-VDS",
    }


def test_a_node_the_panel_puts_in_russia_and_no_whois_say_nothing():
    _env, data = demo_input()
    item = next(n for n in data.nodes if n.node.name == "nl-1")
    data.asn[item.ipv4] = AsInfo("64510", "EXAMPLE-RU-VDS", "RU")
    item.node.country = "RU"  # the entry of a cascade is meant to be in Russia
    assert ru_hoster(data) == []
    _env, data = demo_input(whois=False)
    assert data.asn is None and ru_hoster(data) == []


def test_s6_tells_what_to_do_with_a_russian_hoster():
    from kerberos.demo.nodes import build_whois

    whois = build_whois()
    whois.table["203.0.113.10"] = AsInfo("64510", "EXAMPLE-RU-VDS", "RU")
    keys = login_keys() + ["enter"] + S4_KEYS + ["enter", "enter", "end", "x", "q", "enter"]
    app, term = make_app(keys, height=46)
    app.env.whois = whois
    app.run("check")
    assert seen(term, "Сеть ноды зарегистрирована в") and seen(term, "Перенесите ноду к хостеру")
