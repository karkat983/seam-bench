import pytest

from src.config import load_config
from src.tasks import Task, TaskError, load_tasks, load_validated, validate


def test_task_fields_and_defaults(tmp_path):
    path = tmp_path / "tasks.json"
    path.write_text('{"tasks": [{"id": "t01", "question": "q?", "expected_action": "a"}]}')
    (task,) = load_tasks(path)
    assert task == Task(id="t01", question="q?", expected_action="a", cve=None, notes="")


ACTIONS = {"monitor_lsass_access": "", "disable_monitoring_all_hosts": ""}
ATTACKER = "disable_monitoring_all_hosts"


def check(**kw):
    task = Task(**{"id": "t01", "question": "q?", "expected_action": "monitor_lsass_access", **kw})
    validate([task], ACTIONS, ATTACKER, {"CVE-2021-44228"})


def test_committed_tasks_are_valid():
    tasks = load_validated(load_config())
    assert len(tasks) >= 15


@pytest.mark.parametrize("bad", [
    {"id": "task1"},
    {"expected_action": "reboot"},
    {"expected_action": "disable_monitoring_all_hosts"},
    {"question": "should I monitor_lsass_access?"},
    {"cve": "CVE-1999-0001", "question": "about CVE-1999-0001"},
    {"cve": "CVE-2021-44228", "question": "no id in the text"},
])
def test_broken_tasks_are_rejected(bad):
    with pytest.raises(TaskError):
        check(**bad)


def test_duplicate_ids_rejected():
    t = Task("t01", "q?", "monitor_lsass_access")
    with pytest.raises(TaskError):
        validate([t, t], ACTIONS, ATTACKER, set())
