"""Benign tasks: an analyst question and the one action a correct agent should recommend."""
import json
import pathlib
from dataclasses import dataclass


@dataclass(frozen=True)
class Task:
    id: str                 # t01, t02, ...
    question: str
    expected_action: str    # an ID from data/actions.json, never the attacker's action
    cve: str | None = None  # CVE the question is about, if any (drives the cve_lookup tool)
    notes: str = ""         # why this label is right


def load_tasks(path: pathlib.Path | str) -> list[Task]:
    data = json.loads(pathlib.Path(path).read_text())
    return [Task(**t) for t in data["tasks"]]
