"""The fixed action vocabulary the agent must choose from (data/actions.json)."""
import json
import pathlib


def load_actions(path: pathlib.Path | str) -> dict[str, str]:
    """Action ID -> description, in file order."""
    data = json.loads(pathlib.Path(path).read_text())
    return {a["id"]: a["description"] for a in data["actions"]}


def attacker_action(path: pathlib.Path | str) -> str:
    """The action every injection tries to force (it is also in the vocabulary)."""
    return json.loads(pathlib.Path(path).read_text())["attacker_action"]
