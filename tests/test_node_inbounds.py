"""K20: the inbound self-steal adds runs on the node (tech.md §10.4, §10.9, §23 Q11).

Remnawave 2.8.1 and 3.4.11 run on a node only its `configProfile.activeInbounds`; a new
inbound of the profile is active nowhere. Found on the stand: after self-steal no node
listened on UDP 443 while the subscription handed out the Hysteria2 hosts.
"""

import json

import pytest
from helpers import TOKEN, login_keys, make_app, token_keys
from test_review_logic import (
    APPLY,
    DONE,
    NL1,
    ROLLBACK,
    TO_PLAN,
    changes_of,
    domain_keys,
    fix,
    fix_run,
    fleet,
    profile_of,
    raw_node,
)

from kerberos.clock import FakeClock
from kerberos.fixes.panel_changes import undo
from kerberos.flow import EXIT_OK, EXIT_PARTIAL
from kerberos.panel.client import SCOPES_FIX, PanelClient
from kerberos.panel.errors import PanelError
from kerberos.panel.fake import ContractError

OLD_SCOPES = ["nodes:read"] + [s for s in SCOPES_FIX if s.endswith(":*")]  # the K14–K19 list
API = "http://127.0.0.1:3000/api"


def active_tags(panel, name):
    return [i["tag"] for i in raw_node(panel, name)["configProfile"]["activeInbounds"]]


def hysteria_tag(panel, name):
    profile = profile_of(panel, name)
    return next(i["tag"] for i in profile["inbounds"] if i["type"] == "hysteria")


def client_of(panel, scopes=("*",)):
    client = PanelClient(API, panel, FakeClock())
    client.set_token(panel.add_api_token(scopes=tuple(scopes)))
    return client


# -- the fake panel answers PATCH /nodes like 2.8.1 and 3.4.11 -------------------------------
def test_a_new_profile_inbound_is_active_on_no_node():
    panel, _nodes = fleet()
    client = client_of(panel)
    profile = profile_of(panel, "nl-1")
    config = json.loads(json.dumps(profile["config"]))
    extra = json.loads(json.dumps(config["inbounds"][0]))
    extra.update(tag="EXTRA-NL1", port=8443)
    config["inbounds"].append(extra)
    client.patch_profile(profile["uuid"], config)
    before = active_tags(panel, "nl-1")
    assert "EXTRA-NL1" not in before
    node = raw_node(panel, "nl-1")
    client.patch_node_inbounds(node["uuid"], profile["uuid"],
                               [i["uuid"] for i in profile["inbounds"]])  # fmt: skip
    assert active_tags(panel, "nl-1") == before + ["EXTRA-NL1"]
    config["inbounds"] = config["inbounds"][:-1]
    client.patch_profile(profile["uuid"], config)  # gone from the profile, gone from the node
    assert active_tags(panel, "nl-1") == before


def test_patch_nodes_replaces_the_list_with_inbounds_of_the_profile():
    panel, _nodes = fleet()
    client = client_of(panel)
    node, mine = raw_node(panel, "nl-1"), profile_of(panel, "nl-1")
    answer = client.patch_node_inbounds(node["uuid"], mine["uuid"], [])
    assert answer.inbound_uuids == [] and active_tags(panel, "nl-1") == []
    foreign = profile_of(panel, "nl-2")["inbounds"][0]["uuid"]
    with pytest.raises(PanelError):
        client.patch_node_inbounds(node["uuid"], mine["uuid"], [foreign])  # 404 A124
    with pytest.raises(ContractError):  # KERBEROS sends uuid and configProfile, nothing else
        panel._patch_node({"uuid": node["uuid"], "configProfile": {}, "name": "x"})
    with pytest.raises(ContractError):
        panel._patch_node({"uuid": node["uuid"], "configProfile": {"activeInbounds": []}})


def test_nodes_update_is_the_right_patch_nodes_needs():
    panel, _nodes = fleet()
    node, mine = raw_node(panel, "nl-1"), profile_of(panel, "nl-1")
    inbounds = [i["uuid"] for i in mine["inbounds"]]
    with pytest.raises(PanelError) as refused:
        client_of(panel, OLD_SCOPES).patch_node_inbounds(node["uuid"], mine["uuid"], inbounds)
    assert refused.value.code == "forbidden"
    client_of(panel, SCOPES_FIX).patch_node_inbounds(node["uuid"], mine["uuid"], inbounds)
    assert "nodes:update" in SCOPES_FIX


# -- self-steal switches the new inbound on and only that ------------------------------------
def test_self_steal_switches_hysteria2_on_at_the_node():
    panel, nodes = fleet()
    reality = active_tags(panel, "nl-1")
    app, _term, code = fix(domain_keys(NL1, "nl-1.example.com") + APPLY + DONE, panel, nodes)
    assert code == EXIT_OK
    hysteria = hysteria_tag(panel, "nl-1")
    # Before K20: only the Reality inbound, Hysteria2 hosts in the subscription and no one
    # listening on UDP 443.
    assert active_tags(panel, "nl-1") == reality + [hysteria]
    change = changes_of(fix_run(app), "self_steal.node")[0]
    assert change["state"] == "applied"
    hy2 = next(i["uuid"] for i in profile_of(panel, "nl-1")["inbounds"] if i["tag"] == hysteria)
    assert change["details"]["added"] == [hy2]
    assert change["details"]["before"] == [
        i["uuid"] for i in profile_of(panel, "nl-1")["inbounds"] if i["tag"] in reality
    ]


def test_undo_takes_out_only_what_kerberos_switched_on():
    panel, nodes = fleet()
    app, _term, code = fix(domain_keys(NL1, "nl-1.example.com") + APPLY + DONE, panel, nodes)
    assert code == EXIT_OK
    change = changes_of(fix_run(app), "self_steal.node")[0]
    client = client_of(panel)
    profile = profile_of(panel, "nl-1")
    config = json.loads(json.dumps(profile["config"]))
    extra = json.loads(json.dumps(config["inbounds"][0]))
    extra.update(tag="EXTRA-NL1", port=8443)
    config["inbounds"].append(extra)
    client.patch_profile(profile["uuid"], config)  # the person adds an inbound later
    later = next(i["uuid"] for i in profile_of(panel, "nl-1")["inbounds"]
                 if i["tag"] == "EXTRA-NL1")  # fmt: skip
    node = raw_node(panel, "nl-1")
    mine = [i["uuid"] for i in node["configProfile"]["activeInbounds"]]
    client.patch_node_inbounds(node["uuid"], profile["uuid"], mine + [later])
    assert undo(client, change) is None
    left = [i["uuid"] for i in raw_node(panel, "nl-1")["configProfile"]["activeInbounds"]]
    assert left == [u for u in mine + [later] if u not in change["details"]["added"]]
    assert later in left


def test_rollback_puts_the_node_back_as_it_was():
    panel, nodes = fleet()
    reality = active_tags(panel, "nl-1")
    app, term, code = fix(domain_keys(NL1, "nl-1.example.com") + APPLY + DONE, panel, nodes)
    assert code == EXIT_OK
    term.feed(*ROLLBACK, "x")  # the run, all changes, consent, the notice
    assert app.run("rollback") == EXIT_OK
    assert active_tags(panel, "nl-1") == reality
    rolled = changes_of(fix_run(app), "self_steal.node")[0]
    assert rolled["state"] == "rolled_back"


def test_undo_leaves_a_node_moved_to_another_profile():
    panel, nodes = fleet()
    app, _term, code = fix(domain_keys(NL1, "nl-1.example.com") + APPLY + DONE, panel, nodes)
    assert code == EXIT_OK
    change = changes_of(fix_run(app), "self_steal.node")[0]
    client = client_of(panel)
    other = profile_of(panel, "nl-2")
    node = raw_node(panel, "nl-1")
    client.patch_node_inbounds(node["uuid"], other["uuid"], [other["inbounds"][0]["uuid"]])
    before = json.loads(json.dumps(raw_node(panel, "nl-1")["configProfile"]))
    assert undo(client, change) is None
    assert raw_node(panel, "nl-1")["configProfile"] == before


def test_a_token_without_nodes_update_undoes_the_self_steal():
    panel, nodes = fleet()
    panel.accept_any_token = False
    panel.add_api_token(TOKEN, scopes=tuple(OLD_SCOPES))
    profile = json.loads(json.dumps(profile_of(panel, "nl-1")["config"]))
    reality = active_tags(panel, "nl-1")
    # The person pastes this token of their own (K30): «У меня есть API-токен».
    keys = token_keys() + TO_PLAN[len(login_keys()) :] + domain_keys(NL1, "nl-1.example.com")
    app, _term = make_app(keys + APPLY + DONE, panel=panel, nodes=list(nodes.values()),
                          height=46)  # fmt: skip
    code = app.run("fix")
    assert code == EXIT_PARTIAL
    run = fix_run(app)
    node_change = changes_of(run, "self_steal.node")[0]
    assert (node_change["state"], node_change["error"]) == ("rolled_back", "forbidden")
    assert profile_of(panel, "nl-1")["config"] == profile  # the profile went back
    assert active_tags(panel, "nl-1") == reality
    assert not [h for h in panel.hosts if h.get("sni") == "nl-1.example.com"]
    # §7.3: the panel refused the token in «Исправление»: the next run asks for a new one.
    assert app.env.state.read_panel_token() is None
