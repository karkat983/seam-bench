"""Wire the agent together from config: retriever, tool, sub-agents, parser, plan."""
from src.actions import load_actions
from src.agent import Orchestrator
from src.cache import CachedClient
from src.config import load_config, resolve
from src.llm import make_client
from src.parsing import parse_action
from src.retriever import Retriever
from src.runlog import append_run
from src.steps import ToolRegistry, make_analyze, make_lookup, make_recommend, make_retrieve
from src.subagents import Recommender, Summarizer, prompt_hash
from src.tools import CveLookup
from src.usage import MeteredClient


def build_llm(cfg: dict):
    """Raw client -> usage meter -> disk cache (cache outermost, so hits are free and uncounted)."""
    meter = MeteredClient(make_client(cfg["llm"]))
    return CachedClient(meter, resolve(cfg, "llm_cache")), meter


def build_agent(cfg: dict | None = None, llm=None, retriever=None) -> Orchestrator:
    cfg = cfg or load_config()
    if llm is None:
        llm, _ = build_llm(cfg)
    retriever = retriever or Retriever.from_config(cfg)
    actions = load_actions(resolve(cfg, "actions"))
    summarizer = Summarizer(llm)
    recommender = Recommender(llm, actions)
    steps = {
        "retrieve": make_retrieve(retriever),
        "lookup": make_lookup(ToolRegistry(CveLookup(resolve(cfg, "cves")))),
        "analyze": make_analyze(summarizer),
        "recommend": make_recommend(recommender, parse_action),
    }
    prompts = {"summarizer": prompt_hash(summarizer.system), "recommender": prompt_hash(recommender.system)}
    return Orchestrator(steps, prompts=prompts)


def format_trace(state) -> str:
    """Human-readable trace: one block per step, long text shortened."""
    def short(text: str, n: int = 300) -> str:
        text = " ".join(text.split())
        return text if len(text) <= n else text[:n] + " ..."

    lines = []
    for i, step in enumerate(state.steps, 1):
        lines.append(f"[{i}] {step.name}  (source: {step.source}, {step.seconds:.1f}s)")
        lines.append(f"    in : {short(step.input)}")
        lines.append(f"    out: {short(step.output)}")
    return "\n".join(lines)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Ask the security assistant one question.")
    parser.add_argument("question")
    parser.add_argument("--cve", help="CVE ID to look up (otherwise taken from the question)")
    parser.add_argument("--trace", action="store_true", help="print every step's input and output")
    parser.add_argument("--save", default="runs/cli.jsonl", help="JSONL file the run is appended to")
    args = parser.parse_args()

    state = build_agent().run(args.question, cve=args.cve)
    append_run(args.save, state, origin="cli")
    if args.trace:
        print(format_trace(state))
    print(f"action: {state.action}")
    if state.rationale:
        print(f"why:    {state.rationale}")


if __name__ == "__main__":
    main()
