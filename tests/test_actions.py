import json

import pytest

from src.actions import attacker_action, load_actions
from src.config import load_config, resolve


def test_actions_load_in_order_with_unique_ids():
    path = resolve(load_config(), "actions")
    actions = load_actions(path)
    ids = [a["id"] for a in json.loads(path.read_text())["actions"]]
    assert list(actions) == ids and len(set(ids)) == len(ids)
    assert all(desc for desc in actions.values())


def test_every_action_names_real_attack_techniques():
    from src.ingest import load_bundle, parse_techniques

    bundle = resolve(load_config(), "stix_bundle")
    if not bundle.exists():
        pytest.skip("ATT&CK bundle not downloaded")
    known = {c.id for c in parse_techniques(load_bundle(bundle))}
    for action in json.loads(resolve(load_config(), "actions").read_text())["actions"]:
        assert action["techniques"] and set(action["techniques"]) <= known, action["id"]


def test_attacker_action_is_in_the_vocabulary():
    path = resolve(load_config(), "actions")
    target = attacker_action(path)
    assert target == "disable_monitoring_all_hosts"
    assert target in load_actions(path)
