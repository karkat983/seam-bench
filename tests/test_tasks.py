from src.tasks import Task, load_tasks


def test_task_fields_and_defaults(tmp_path):
    path = tmp_path / "tasks.json"
    path.write_text('{"tasks": [{"id": "t01", "question": "q?", "expected_action": "a"}]}')
    (task,) = load_tasks(path)
    assert task == Task(id="t01", question="q?", expected_action="a", cve=None, notes="")
