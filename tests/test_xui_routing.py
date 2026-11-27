"""Russian sites directly in the subscription of 3x-ui (tech.md §7.6, §10.2, K29)."""

import base64
import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

import kerberos.checks.rules  # noqa: F401  (registers the checks)
from kerberos.checks import spec
from kerberos.copy import t
from kerberos.fixes import xui_routing
from kerberos.host import CommandResult, FakeHost
from kerberos.panel.discover import XUI_BIN, XUI_DB, discover_xui


def deeplink(profile: dict) -> str:
    return "happ://routing/onadd/" + base64.b64encode(json.dumps(profile).encode()).decode()


def test_the_link_of_kerberos_is_a_happ_profile_with_russia_directly():
    link = xui_routing.routing_link()
    assert link.startswith("happ://routing/onadd/") and "\n" not in link
    profile = xui_routing.parse_routing(link)
    assert profile == xui_routing.PROFILE
    assert xui_routing.profile_ru_direct(profile)
    assert "domain:max.ru" in profile["BlockSites"], "as the KERBEROS templates (§10.9)"


@pytest.mark.parametrize("value", [
    deeplink({"DirectSites": ["geosite:category-ru"], "DirectIp": ["geoip:ru"]}),
    deeplink({"DirectSites": "geosite:ru,geosite:private", "DirectIp": "geoip:ru"}),
    "happ://routing/add/" + base64.b64encode(
        b'{"DirectSites":["geosite:category-ru"],"DirectIp":["geoip:ru"]}').decode().rstrip("="),
    '{"DirectSites":["geosite:category-ru"],"DirectIp":["geoip:ru"]}',
])  # fmt: skip
def test_profiles_with_russia_directly_are_read_in_every_form(value):
    profile = xui_routing.parse_routing(value)
    assert isinstance(profile, dict) and xui_routing.profile_ru_direct(profile)


@pytest.mark.parametrize("value", [
    "", "happ://routing/off", "happ://routing/onadd/%%%", "not a profile", "[1, 2]",
    deeplink({"DirectSites": ["geosite:category-ru"]}),  # no geoip:ru
    deeplink({"DirectIp": ["geoip:ru"], "ProxySites": ["geosite:category-ru"]}),
])  # fmt: skip
def test_other_profiles_do_not_count(value):
    profile = xui_routing.parse_routing(value)
    assert not (isinstance(profile, dict) and xui_routing.profile_ru_direct(profile))


def test_a_profile_at_a_url_is_not_judged():
    assert xui_routing.parse_routing("https://example.com/routing.json") == xui_routing.REMOTE


@given(st.text(max_size=200))
def test_any_text_is_read_without_an_error(value):
    xui_routing.parse_routing(value)
    xui_routing.json_rules_ru_direct(value)


def test_json_rules_of_v2():
    rules = [{"type": "field", "outboundTag": "direct", "domain": ["geosite:category-ru"]},
             {"type": "field", "outboundTag": "direct", "ip": ["geoip:ru"]}]  # fmt: skip
    assert xui_routing.json_rules_ru_direct(json.dumps(rules))
    rules[1]["outboundTag"] = "proxy"
    assert not xui_routing.json_rules_ru_direct(json.dumps(rules))
    assert not xui_routing.json_rules_ru_direct("")


def test_routing_comes_with_v3_and_unknown_versions_count_by_keys():
    assert xui_routing.routing_supported("3.0.0", {})
    assert not xui_routing.routing_supported("2.8.3", {"subRoutingRules": "x"})
    assert xui_routing.routing_supported("?", {"subEnableRouting": "false"})
    assert not xui_routing.routing_supported("?", {})


def discovered(version: str, **settings) -> dict:
    host = FakeHost(databases={XUI_DB: {"webPort": "2053", "webBasePath": "/", **settings}})
    host.on([XUI_BIN, "-v"], CommandResult(0, version + "\n"))
    return discover_xui(host).info


class Snapshot:
    def __init__(self, info):
        self.panel_info = info


class Data:
    def __init__(self, info):
        self.snapshot = Snapshot(info)


def findings(info):
    return spec("xui.sub_ru_direct").rule(Data(info))


def test_v3_without_routing_gets_the_line_to_paste():
    info = discovered("3.11.0")
    [found] = findings(info)
    assert found["ok"] is False and found["target"] == "panel"
    assert found["evidence"]["routing"] == xui_routing.routing_link()


def test_v3_with_a_good_profile_passes_and_a_switched_off_one_does_not():
    good = xui_routing.routing_link()
    assert findings(discovered("3.11.0", subEnableRouting="true", subRoutingRules=good))[0]["ok"]
    off = findings(discovered("3.11.0", subEnableRouting="false", subRoutingRules=good))[0]
    assert off["ok"] is False, "Routing-Enable: false and Happ ignores the profile"


def test_v3_with_a_profile_at_a_url_says_nothing():
    info = discovered("3.11.0", subEnableRouting="true",
                      subRoutingRules="https://example.com/routing.json")  # fmt: skip
    assert findings(info) == []


def test_v2_asks_for_json_rules_or_an_update():
    [found] = findings(discovered("2.6.2"))
    assert found["ok"] is False and found["evidence"] == {"version": "2"}
    rules = json.dumps([{"outboundTag": "direct", "domain": ["geosite:category-ru"]},
                        {"outboundTag": "direct", "ip": ["geoip:ru"]}])  # fmt: skip
    assert findings(discovered("2.6.2", subJsonEnable="true", subJsonRules=rules))[0]["ok"]


def test_no_settings_no_finding():
    assert findings({}) == []
    assert spec("xui.sub_ru_direct").panels == ("3x-ui",)


def test_the_check_runs_on_the_demo_3xui_server_and_tells_what_to_do():
    from helpers import make_app, seen, typed

    keys = ["down", "enter"] + typed("admin") + ["enter"] + typed("pw") + ["enter"]
    keys += ["enter", "enter", "end", "x", "q", "enter"]  # S4 intro and summary, S6
    app, term = make_app(keys, panel_kind=None, height=44)
    app.run("check")
    assert seen(term, "Подписка 3x-ui ведёт российские") or seen(
        term, t("check.xui.sub_ru_direct.short")
    )
