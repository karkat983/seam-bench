"""Benign tasks: an analyst question and the one action a correct agent should recommend."""
import json
import pathlib
import re
from dataclasses import dataclass

TASK_ID = re.compile(r"^t\d{2}$")


class TaskError(ValueError):
    pass


@dataclass(frozen=True)
class Task:
    id: str                 # t01, t02, ...
    question: str
    expected_action: str    # an ID from data/actions.json, never the attacker's action
    cve: str | None = None  # CVE the question is about, if any (drives the cve_lookup tool)
    notes: str = ""         # why this label is right


def validate(tasks: list[Task], actions: dict[str, str], attacker: str, cve_ids: set[str]) -> None:
    """Raise TaskError on the first broken rule (see docs/tasks.md)."""
    seen = set()
    for t in tasks:
        if not TASK_ID.match(t.id) or t.id in seen:
            raise TaskError(f"{t.id}: id must be t + two digits and unique")
        seen.add(t.id)
        if t.expected_action not in actions:
            raise TaskError(f"{t.id}: unknown action {t.expected_action}")
        if t.expected_action == attacker:
            raise TaskError(f"{t.id}: the attacker's action can never be a correct answer")
        if t.expected_action in t.question:
            raise TaskError(f"{t.id}: question gives away the action ID")
        if t.cve is not None and (t.cve not in cve_ids or t.cve not in t.question):
            raise TaskError(f"{t.id}: cve {t.cve} must exist in data/cves.json and appear in the question")


def load_tasks(path: pathlib.Path | str, actions: dict[str, str] | None = None,
               attacker: str | None = None, cve_ids: set[str] | None = None) -> list[Task]:
    """Load tasks; validate them when the vocabulary and CVE IDs are supplied."""
    data = json.loads(pathlib.Path(path).read_text())
    tasks = [Task(**t) for t in data["tasks"]]
    if actions is not None:
        validate(tasks, actions, attacker or "", cve_ids or set())
    return tasks


def load_validated(cfg: dict) -> list[Task]:
    from src.actions import attacker_action, load_actions
    from src.config import resolve

    cves = json.loads(resolve(cfg, "cves").read_text())
    return load_tasks(
        resolve(cfg, "tasks"),
        actions=load_actions(resolve(cfg, "actions")),
        attacker=attacker_action(resolve(cfg, "actions")),
        cve_ids={c["id"] for c in cves},
    )
