"""Property tests of agent parsers (tech.md §17); here, not on the stand (needs Hypothesis)."""

from hypothesis import given
from hypothesis import strategies as st

from kerberos import agent

text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=400)


@given(text)
def test_ss_parsers_never_crash(value):
    for item in agent.parse_ss_listen(value):
        assert set(item) == {"proto", "address", "port", "process"}
    for item in agent.parse_ss_connections(value):
        assert item["received"] >= 0


@given(text)
def test_other_parsers_never_crash(value):
    agent.parse_sshd_t(value)
    agent.parse_ufw(value)
    agent.parse_nginx({"f": value})
    agent.parse_xray_log(value, 0)
    agent.parse_access_log(value, "/")
    agent.Ruleset(value).dropped("tcp")
    agent.parse_ip_addr(value)
    agent.parse_remnanode(value)
    agent.template_hash(value)


@given(text)
def test_dpkg_status_parser_never_crashes(value):
    for name in agent.unfinished_packages(value):
        assert name


STATES = ["installed", "config-files", "not-installed", "half-installed", "unpacked",
          "half-configured", "triggers-awaited", "triggers-pending"]  # fmt: skip
names = st.from_regex(r"[a-z0-9][a-z0-9+.-]{0,20}", fullmatch=True)


@given(st.lists(st.tuples(names, st.sampled_from(STATES)), max_size=12))
def test_dpkg_status_finds_exactly_the_unconfigured(packages):
    """`dpkg -l` iU, iF, iW, iT and nothing else, whatever the other fields say."""
    status = "\n".join(
        f"Package: {name}\nStatus: install ok {state}\nPriority: optional\n"
        f"Description: {state} package\n continued line: Status: install ok unpacked\n"
        for name, state in packages
    )
    unconfigured = ("unpacked", "half-configured", "triggers-awaited", "triggers-pending")
    expected = [name for name, state in packages if state in unconfigured]
    assert agent.unfinished_packages(status) == expected
