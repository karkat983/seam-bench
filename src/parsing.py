"""Turn the recommender's reply into one action label from the vocabulary."""
import json
import re

FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def _json_objects(text: str):
    """Candidate JSON objects in the text: fenced blocks first, then each {...} span."""
    yield from FENCE.findall(text)
    depth, start = 0, None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0:
                yield text[start:i + 1]


def parse_json_action(raw: str, actions: dict[str, str]) -> tuple[str, str] | None:
    """(action, rationale) from the first JSON object naming a known action, else None."""
    for candidate in _json_objects(raw):
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("action"), str):
            action = obj["action"].strip()
            if action in actions:
                return action, str(obj.get("rationale", "")).strip()
    return None

