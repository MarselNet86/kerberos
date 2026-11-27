"""The watch sign «frozen after the first 16 KB» (tech.md §9.2, §10.2, K27).

Viewers of the owner's video report that TSPU lets a connection to a foreign server through
for its first ~16 KB and then drops what the server sends: the client acknowledged about that
much and nothing since, while the server still has data in flight.
"""

from kerberos import agent


def conn(peer: str, info: str) -> str:
    return f"0      0      203.0.113.10:443       {peer}:51234\n\t cubic rto:204 {info}\n"


STALLED = ("bytes_sent:30000 bytes_acked:16385 bytes_received:517 unacked:9 "
           "lastsnd:200 lastrcv:9000 lastack:6400")  # fmt: skip
IDLE = (
    "bytes_sent:90000 bytes_acked:90001 bytes_received:3000 lastsnd:9000 lastrcv:9000 lastack:9000"
)
GONE = ("bytes_sent:900000 bytes_acked:812345 bytes_received:40000 unacked:20 "
        "lastsnd:100 lastrcv:20000 lastack:20000")  # fmt: skip
FRESH = "bytes_sent:30000 bytes_acked:16385 bytes_received:517 unacked:9 lastack:120"


def test_ss_gives_what_the_client_acknowledged_and_what_is_in_flight():
    parsed = agent.parse_ss_connections(conn("198.51.100.7", STALLED))
    assert parsed == [{"peer": "198.51.100.7", "local": "203.0.113.10", "port": 443,
                       "received": 517, "lastrcv": 9000, "acked": 16385, "unacked": 9,
                       "lastack": 6400}]  # fmt: skip


def test_a_connection_frozen_after_16_kb_is_stalled():
    rows = [conn("198.51.100.7", STALLED), conn("198.51.100.8", IDLE),
            conn("192.0.2.9", GONE), conn("192.0.2.10", FRESH)]  # fmt: skip
    family = agent.watch_family(agent.parse_ss_connections("".join(rows)))
    assert family["stalled"] == 1, "idle, gone far beyond 16 KB and still acked are not"
    assert family["stalledNets"] == [{"net": "198.51.0.0/16", "count": 1}]


def test_the_bounds_of_the_sign():
    low, high = agent.STALL_ACKED
    base = {"unacked": 1, "lastack": agent.STALL_MS + 1}
    assert agent.stalled({**base, "acked": low}) and agent.stalled({**base, "acked": high})
    assert not agent.stalled({**base, "acked": low - 1})
    assert not agent.stalled({**base, "acked": high + 1})
    assert not agent.stalled({**base, "acked": 16000, "unacked": 0})
    assert not agent.stalled({**base, "acked": 16000, "lastack": agent.STALL_MS})


def test_an_old_line_of_ss_without_the_new_fields_is_not_stalled():
    old = "bytes_sent:120 bytes_received:517 lastsnd:5000 lastrcv:5200"
    family = agent.watch_family(agent.parse_ss_connections(conn("198.51.100.7", old)))
    assert family["stalled"] == 0 and family["cut"] == 1


def test_the_watch_script_writes_the_stalled_count():
    assert "stall=%d" in agent.WATCH_SCRIPT
    assert 'V4["stalled"] + V6["stalled"]' in agent.WATCH_SCRIPT
