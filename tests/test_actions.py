import json

from src.actions import load_actions
from src.config import load_config, resolve


def test_actions_load_in_order_with_unique_ids():
    path = resolve(load_config(), "actions")
    actions = load_actions(path)
    ids = [a["id"] for a in json.loads(path.read_text())["actions"]]
    assert list(actions) == ids and len(set(ids)) == len(ids)
    assert all(desc for desc in actions.values())


def test_every_action_names_real_attack_techniques(mini_chunks):
    path = resolve(load_config(), "actions")
    for action in json.loads(path.read_text())["actions"]:
        assert action["techniques"], action["id"]
        assert all(t.startswith("T") for t in action["techniques"])
