
"""api.py - the AEGIS web API (FastAPI) and dashboard server.

Run it:
    uvicorn aegis.api:app --reload
Then open http://127.0.0.1:8000 (dashboard)
or http://127.0.0.1:8000/docs (API documentation).

Settings (environment variables, all optional):
    AEGIS_AUDIT   path of the audit log
    AEGIS_DB      SQLite file for SQL dry-runs
"""

import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, learn, policy
from .chat import handle_message
from .engine import Engine


ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = Path(__file__).parent / "dashboard" / "index.html"


def build_engine() -> Engine:
    """Create an Engine from environment variables and policies/general.yaml."""

    general = policy.load("general")

    db_path = os.environ.get("AEGIS_DB")

    if not db_path and (ROOT / "data" / "demo.db").exists():
        db_path = str(ROOT / "data" / "demo.db")

    return Engine(
        audit_path=os.environ.get("AEGIS_AUDIT", "aegis_audit.jsonl"),
        db_path=db_path,
        use_ai_risk=bool(general.get("use_ai_risk", False)),
        block_at=general.get("block_at", "CRITICAL"),
        **(general.get("behaviour") or {}),
    )


# ---------- application setup ----------

engine = build_engine()

app = FastAPI(
    title="AEGIS",
    version=__version__,
    description="The accountability layer for AI agents.",
)

app.mount(
    "/dashboard",
    StaticFiles(directory=str(DASHBOARD.parent)),
    name="dashboard",
)

# Temporary conversation memory, separated by browser session.
# This memory is cleared when the API server restarts.
conversation_histories = {}


# ---------- request shapes ----------

class ActionIn(BaseModel):
    action: str = Field(
        ...,
        description="SQL text, a shell command, or a SOC action as JSON text",
    )
    kind: str = Field("sql", description="sql | shell | soc")
    agent: str = "default"
    tokens: int = 0
    cost: float = 0.0


class ChatIn(BaseModel):
    message: str
    agent: str = "chat"
    session_id: str = Field(
        "default",
        min_length=1,
        max_length=128,
    )


class ApproveIn(BaseModel):
    action: str
    kind: str = "other"
    agent: str = "default"


class RuleIn(BaseModel):
    pattern: str
    reason: str


# ---------- routes ----------

@app.get("/", include_in_schema=False)
def dashboard():
    if DASHBOARD.exists():
        return FileResponse(DASHBOARD)

    return {
        "name": "AEGIS",
        "version": __version__,
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": __version__,
    }


@app.post("/evaluate")
def evaluate(body: ActionIn):
    """Send an agent action through the AEGIS security engine."""

    decision = engine.evaluate(
        body.action,
        kind=body.kind,
        agent=body.agent,
        tokens=body.tokens,
        cost=body.cost,
    )

    return decision.to_dict()


@app.post("/chat")
def chat(body: ChatIn):
    """Conversational endpoint with session-based conversation history."""

    history = conversation_histories.setdefault(
        body.session_id,
        [],
    )

    response = handle_message(
        engine,
        body.message,
        agent=body.agent,
        history=history,
    )

    # Do not store built-in commands or security actions as ordinary chat.
    excluded = {
        "help",
        "?",
        "stats",
        "verify",
        "pending",
        "quit",
        "exit",
    }

    if (
        response.get("decision") is None
        and body.message.strip().lower() not in excluded
    ):
        history.append({
            "role": "user",
            "content": body.message,
        })

        history.append({
            "role": "assistant",
            "content": response["reply"],
        })

        # Keep only the latest 10 conversation exchanges.
        del history[:-20]

    return response


@app.get("/audit")
def audit(limit: int = 100, verdict: Optional[str] = None):
    """Return newest audit entries first."""

    entries = engine.audit.read_all()

    if verdict:
        entries = [
            entry
            for entry in entries
            if str(entry.get("verdict", "")).upper() == verdict.upper()
        ]

    return {
        "count": len(entries),
        "entries": list(reversed(entries))[:limit],
    }


@app.get("/audit/verify")
def audit_verify():
    ok, message = engine.audit.verify()

    return {
        "intact": ok,
        "message": message,
    }


@app.get("/stats")
def stats():
    entries = engine.audit.read_all()

    verdicts = {}
    kinds = {}
    risks = {}
    agents = {}

    for entry in entries:
        for table, key in (
            (verdicts, "verdict"),
            (kinds, "kind"),
            (risks, "risk"),
            (agents, "agent"),
        ):
            value = str(entry.get(key, "unknown"))
            table[value] = table.get(value, 0) + 1

    ok, message = engine.audit.verify()

    return {
        "total": len(entries),
        "verdicts": verdicts,
        "kinds": kinds,
        "risks": risks,
        "agents": agents,
        "log_intact": ok,
        "integrity_message": message,
    }


@app.get("/pending")
def pending():
    """Return REVIEW decisions awaiting human approval."""

    entries = engine.audit.read_all()

    resolved = {
        (entry.get("original"), entry.get("kind"), entry.get("agent"))
        for entry in entries
        if entry.get("verdict") in ("HUMAN_APPROVED", "HUMAN_REJECTED")
    }

    waiting = [
        entry
        for entry in entries
        if (
            entry.get("verdict") == "REVIEW"
            and (
                entry.get("original"),
                entry.get("kind"),
                entry.get("agent"),
            ) not in resolved
        )
    ]

    return {
        "count": len(waiting),
        "entries": list(reversed(waiting)),
    }


@app.post("/approve")
def approve(body: ApproveIn):
    """Record a human approval."""

    entry = learn.record_approval(
        engine.audit,
        body.action,
        body.agent,
        body.kind,
    )

    return {
        "recorded": True,
        "seq": entry["seq"],
    }


@app.post("/reject")
def reject(body: ApproveIn):
    """Record a human rejection without executing the action."""
    entry = engine.audit.append({
        "verdict": "HUMAN_REJECTED",
        "agent": body.agent,
        "kind": body.kind,
        "original": body.action,
        "rule": "HUMAN",
        "reason": "rejected by a person",
    })
    return {"recorded": True, "seq": entry["seq"]}


@app.get("/learn/suggestions")
def learn_suggestions():
    return {
        "suggestions": learn.suggest_rules(engine.audit),
    }


@app.post("/learn/rules")
def learn_add_rule(body: RuleIn):
    try:
        rule = learn.add_rule(
            body.pattern,
            body.reason,
        )

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    engine.learned = learn.load_rules()

    return rule


@app.post("/agents/{agent}/reset")
def reset_agent(agent: str):
    """Clear the loop and budget counters of one agent."""

    engine.behaviour.reset(agent)

    return {
        "reset": agent,
    }
