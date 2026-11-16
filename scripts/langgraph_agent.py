"""A small LangGraph agent whose every tool call must pass through AEGIS.

    pip install langgraph
    python scripts/langgraph_agent.py

Graph:   plan --> guard --> execute --> (next step) --> plan ...
                     |
                     +--> skip  (BLOCK / REVIEW: the action is never executed)

The planner here is a fixed list, so no API key is needed. To use a real LLM, replace
plan_node() so that it asks the model for the next action and puts it in state["current"].
"""
import sys
import tempfile
from pathlib import Path
from typing import TypedDict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis.engine import Engine, verdict_name

try:
    from langgraph.graph import END, StateGraph
except ImportError:
    print("LangGraph is not installed.  Run:  pip install langgraph")
    sys.exit(1)

TASKS = [
    ("shell", "git status"),
    ("sql", "SELECT * FROM orders"),
    ("shell", "cat .env"),
    ("shell", "rm -rf ./*"),
    ("soc", '{"action":"block_ip","target":"203.0.113.9","alert_id":"A-1","severity":"high"}'),
    ("sql", "DROP TABLE orders"),
]

engine = Engine(audit_path=Path(tempfile.gettempdir()) / "aegis_langgraph.jsonl")


class State(TypedDict):
    step: int
    current: dict
    decision: dict
    done: list


def plan_node(state: State) -> dict:
    kind, action = TASKS[state["step"]]
    return {"current": {"kind": kind, "action": action}}


def guard_node(state: State) -> dict:
    cur = state["current"]
    decision = engine.evaluate(cur["action"], kind=cur["kind"], agent="langgraph-agent")
    return {"decision": decision.to_dict()}


def route_after_guard(state: State) -> str:
    return "execute" if state["decision"]["verdict"] in ("ALLOW", "CORRECT") else "skip"


def execute_node(state: State) -> dict:
    d = state["decision"]
    to_run = d["corrected"] or d["original"]
    print(f"  RUN     [{state['current']['kind']}] {to_run[:70]}")          # a real agent would run the tool here
    return {"done": state["done"] + [to_run], "step": state["step"] + 1}


def skip_node(state: State) -> dict:
    d = state["decision"]
    print(f"  STOPPED [{d['verdict']}] {d['original'][:50]}  ({d['rule']}: {d['reason'][:60]})")
    return {"step": state["step"] + 1}


def route_next(state: State) -> str:
    return "plan" if state["step"] < len(TASKS) else END


def build_graph():
    g = StateGraph(State)
    g.add_node("plan", plan_node)
    g.add_node("guard", guard_node)
    g.add_node("execute", execute_node)
    g.add_node("skip", skip_node)
    g.set_entry_point("plan")
    g.add_edge("plan", "guard")
    g.add_conditional_edges("guard", route_after_guard, {"execute": "execute", "skip": "skip"})
    g.add_conditional_edges("execute", route_next, {"plan": "plan", END: END})
    g.add_conditional_edges("skip", route_next, {"plan": "plan", END: END})
    return g.compile()


if __name__ == "__main__":
    print("LangGraph agent running behind AEGIS\n")
    final = build_graph().invoke({"step": 0, "current": {}, "decision": {}, "done": []})
    print(f"\n{len(final['done'])} of {len(TASKS)} actions were allowed to run.")
    print("Audit log:", engine.audit.verify()[1])
