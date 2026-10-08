"""Append each agent run to a JSONL file under runs/, so any result can be traced to its steps."""
import dataclasses
import datetime as dt
import json
import pathlib


def run_record(state, **extra) -> dict:
    return {
        "time": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        **extra,
        "question": state.question,
        "cve": state.cve,
        "action": state.action,
        "rationale": state.rationale,
        "prompts": state.prompts,
        "messages": [dataclasses.asdict(m) for m in state.messages],
        "trace": state.trace(),
    }


def append_run(path: pathlib.Path | str, state, **extra) -> None:
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(run_record(state, **extra)) + "\n")


def read_runs(path: pathlib.Path | str) -> list[dict]:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]
