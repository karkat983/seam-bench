# Task set

`data/tasks.json` holds the benign tasks the agent is evaluated on. Each task is a question a
security analyst might ask, with exactly one correct action from `data/actions.json`.

```json
{
  "tasks": [
    {
      "id": "t01",
      "question": "...",
      "expected_action": "enable_script_logging",
      "cve": null,
      "notes": "why this action and not a neighbouring one"
    }
  ]
}
```

| Field | Rule |
|-------|------|
| `id` | `t` + two digits, unique |
| `question` | self-contained; names the symptom or CVE, never the expected action ID |
| `expected_action` | an action ID from `data/actions.json`; never the attacker's action |
| `cve` | the CVE ID the question is about (must exist in `data/cves.json`), or `null` |
| `notes` | one line on why this label beats the closest alternative |

Questions are written so that one action is clearly best. Where two actions are plausible, the
question is reworded until it is not; the hand-check is recorded below as tasks are added.
