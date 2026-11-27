"""Profile from the template and host copies (tech.md §10.9, §10.4, §17 properties)."""

import base64
import random

from hypothesis import given
from hypothesis import strategies as st

from kerberos.fixes.hosts import CHANGED, copy_fields, fingerprint_of, hysteria_host, mismatches
from kerberos.fixes.profile import (
    build_profile,
    finalize_profile,
    is_hysteria,
    is_reality,
    latin_upper,
    new_private_key,
    remaining,
    server_names,
)
from kerberos.panel import schema
from kerberos.templates import PROFILE, load

DOMAIN = "nl-1.example.com"
tags = st.from_regex(r"[A-Z][A-Z0-9-]{2,12}", fullmatch=True)
names = st.lists(st.from_regex(r"[a-z]{2,8}\.example\.(com|net)", fullmatch=True), max_size=3)
short_ids = st.lists(st.from_regex(r"[0-9a-f]{2,16}", fullmatch=True), max_size=3)


def reality(tag, key, sids, server_names_):
    return {
        "tag": tag,
        "port": 443,
        "protocol": "vless",
        "settings": {"clients": []},
        "streamSettings": {
            "network": "raw",
            "security": "reality",
            "realitySettings": {
                "dest": "www.example.net:443",
                "privateKey": key,
                "shortIds": ["", *sids],
                "serverNames": server_names_,
            },
        },
    }


@st.composite
def profiles(draw):
    inbounds = []
    if draw(st.booleans()):
        inbounds.append(
            reality(
                draw(tags),
                draw(st.from_regex(r"[A-Za-z0-9_-]{43}", fullmatch=True)),
                draw(short_ids),
                draw(names),
            )
        )
    if draw(st.booleans()):
        inbounds.append(
            {
                "tag": draw(tags) + "-HY",
                "port": 443,
                "protocol": "hysteria",
                "streamSettings": {"network": "hysteria", "security": "tls"},
            }
        )
    others = draw(st.lists(tags, max_size=3, unique=True))
    for tag in others:
        inbounds.append(
            {
                "tag": tag + "-X",
                "port": 8443,
                "protocol": "vless",
                "streamSettings": {"network": "xhttp", "security": "none"},
            }
        )
    rules = [{"type": "field", "inboundTag": [t + "-X"], "outboundTag": "WARP"} for t in others]
    rules.append({"type": "field", "ip": ["geoip:private"], "outboundTag": "DIRECT"})
    outbounds = [{"tag": "DIRECT", "protocol": "freedom"}, {"tag": "WARP", "protocol": "wireguard"}]
    return {"inbounds": inbounds, "outbounds": outbounds, "routing": {"rules": rules}}


@given(profiles(), st.integers(0, 2**31))
def test_template_is_filled_and_the_node_keeps_its_own(current, seed):
    built = build_profile(current, "nl-1", DOMAIN, random.Random(seed))
    assert remaining(built) == []
    old = next((i for i in current["inbounds"] if is_reality(i)), None)
    new = next(i for i in built["inbounds"] if is_reality(i))
    settings = new["streamSettings"]["realitySettings"]
    assert settings["dest"] == "127.0.0.1:8445"
    if old:
        old_settings = old["streamSettings"]["realitySettings"]
        assert new["tag"] == old["tag"]
        assert settings["privateKey"] == old_settings["privateKey"]
        assert [s for s in settings["shortIds"] if s] == [s for s in old_settings["shortIds"] if s]
        assert settings["serverNames"] == [DOMAIN] + [
            n for n in old_settings["serverNames"] if n != DOMAIN
        ]
    old_hy = next((i for i in current["inbounds"] if is_hysteria(i)), None)
    new_hy = next(i for i in built["inbounds"] if is_hysteria(i))
    if old_hy:
        assert new_hy["tag"] == old_hy["tag"]
    assert new_hy["streamSettings"]["hysteriaSettings"]["masquerade"]["url"] == f"https://{DOMAIN}"
    others = [i for i in current["inbounds"] if not is_reality(i) and not is_hysteria(i)]
    assert all(i in built["inbounds"] for i in others), "inbounds of the person stay"
    theirs = [r for r in current["routing"]["rules"] if "inboundTag" in r]
    assert built["routing"]["rules"][: len(theirs)] == theirs, "their rules go first"
    if theirs:
        assert {"tag": "WARP", "protocol": "wireguard"} in built["outbounds"]


@given(profiles(), st.integers(0, 2**31))
def test_building_twice_changes_nothing(current, seed):
    once = build_profile(current, "nl-1", DOMAIN, random.Random(seed))
    twice = build_profile(once, "nl-1", DOMAIN, random.Random(seed + 1))
    assert twice == once


@given(profiles(), st.integers(0, 2**31))
def test_finalization_leaves_the_own_domain_only(current, seed):
    built = build_profile(current, "nl-1", DOMAIN, random.Random(seed))
    final = finalize_profile(built, DOMAIN)
    assert server_names(final) == [DOMAIN]
    assert finalize_profile(final, DOMAIN) == final
    assert build_profile(current, "nl-1", DOMAIN, random.Random(seed), finalized=True) == final


def test_new_node_gets_new_tags_and_a_valid_key():
    built = build_profile({"inbounds": []}, "Нидерланды 1", DOMAIN, random.Random(1))
    assert [i["tag"] for i in built["inbounds"]] == [
        "VLESS-REALITY-NIDERLANDY-1",
        "HY2-NIDERLANDY-1",
    ]
    key = built["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"]
    raw = base64.urlsafe_b64decode(key + "=")
    assert len(raw) == 32 and raw[0] & 7 == 0 and raw[31] & 0x80 == 0 and raw[31] & 0x40
    assert len(built["inbounds"][0]["streamSettings"]["realitySettings"]["shortIds"][1]) == 16


def test_template_file_is_not_changed_by_building():
    before = load(PROFILE)
    build_profile({"inbounds": []}, "x", DOMAIN, random.Random(1))
    assert load(PROFILE) == before


def test_latin_upper():
    assert latin_upper("de-1") == "DE-1" and latin_upper("Москва") == "MOSKVA"
    assert latin_upper("!!!") == "NODE"
    assert len(new_private_key(random.Random(3))) == 43


hosts = st.fixed_dictionaries(
    {
        "uuid": st.uuids().map(str),
        "viewPosition": st.integers(0, 50),
        "remark": st.text(max_size=10),
        "address": st.from_regex(r"203\.0\.113\.\d{1,2}", fullmatch=True),
        "port": st.integers(1, 65535),
        "path": st.text(max_size=5),
        "sni": st.text(max_size=10),
        "fingerprint": st.sampled_from(["", "chrome", "firefox"]),
        "isDisabled": st.booleans(),
        "isHidden": st.booleans(),
        "overrideSniFromAddress": st.booleans(),
        "tags": st.lists(st.from_regex(r"[A-Z0-9_]{2,6}", fullmatch=True), max_size=2),
        "xhttpExtraParams": st.none(),
        "xrayJsonTemplateUuid": st.none(),
        "inbound": st.just({"configProfileUuid": "p", "configProfileInboundUuid": "i"}),
    }
)


@given(hosts)
def test_copy_differs_only_in_the_fields_of_10_4(raw):
    source = schema.host(raw, "tags")
    copy_ = copy_fields(source, DOMAIN, template_uuid="t", tags=["KRB_NL_1_VLESS"], hidden=True)
    changed = {k for k in set(raw) | set(copy_) if raw.get(k) != copy_.get(k)}
    assert changed <= CHANGED | {"uuid", "viewPosition"}
    assert copy_["sni"] == DOMAIN and copy_["overrideSniFromAddress"] is False
    assert copy_["fingerprint"] == (raw["fingerprint"] or fingerprint_of(raw["uuid"]))
    assert "uuid" not in copy_ and "viewPosition" not in copy_


def test_hysteria_host_and_read_back_check():
    raw = {
        "uuid": "h",
        "remark": "NL",
        "address": "203.0.113.10",
        "port": 443,
        "sni": "x",
        "fingerprint": "",
        "tags": [],
        "inbound": {"configProfileUuid": "p", "configProfileInboundUuid": "r"},
    }
    source = schema.host(raw, "tags")
    fields = hysteria_host(source, DOMAIN, "p", "hy", "NL Hysteria2")
    assert fields["inbound"]["configProfileInboundUuid"] == "hy" and fields["port"] == 443
    stored = schema.host({**fields, "uuid": "new", "sni": "wrong"}, "tags")
    assert mismatches(fields, stored) == ["sni"]
