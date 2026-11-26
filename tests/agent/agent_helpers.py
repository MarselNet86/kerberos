"""Helpers of the agent tests; they run here and on the stand VMs with pytest only."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
from typing import Optional

from kerberos import agent

ROOT = Path(__file__).resolve().parent.parent.parent
# apt-get install of the agent (tech.md §10.3): the person's config files stay, no prompt.
APT_INSTALL = ["apt-get", "install", "-y", "-q",
               "-o", "Dpkg::Options::=--force-confdef",
               "-o", "Dpkg::Options::=--force-confold"]  # fmt: skip


class Recorder:
    """Fake command runner: answers by argv prefix, records every call."""

    def __init__(self) -> None:
        self.answers: list[tuple[tuple[str, ...], object]] = []
        self.calls: list[list[str]] = []

    def on(self, prefix, result) -> None:
        self.answers.insert(0, (tuple(prefix), result))

    def __call__(self, argv, input=None, timeout=120):
        self.calls.append(list(argv))
        for prefix, result in self.answers:
            if tuple(argv[: len(prefix)]) == prefix:
                if callable(result):
                    return result(argv, input)
                return result
        return agent.Result(127, "", f"{argv[0]}: not found")


def call(system: agent.System, words: list[str], stdin: Optional[bytes] = None) -> tuple[int, dict]:
    out = io.StringIO()
    code = agent.main(words, system=system, stdin=stdin or b"", out=out)
    return code, json.loads(out.getvalue())


def install_self(system: agent.System) -> bytes:
    data = (ROOT / "src" / "kerberos" / "agent.py").read_bytes()
    path = system.path(agent.AGENT_PATH)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return data
