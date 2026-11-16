"""api.py - the AEGIS web API (FastAPI) and dashboard server.

Run it:
    uvicorn aegis.api:app --reload
Then open http://127.0.0.1:8000  (dashboard)  or  http://127.0.0.1:8000/docs  (API docs)

Settings (environment variables, all optional):
    AEGIS_AUDIT   path of the audit log        (default: aegis_audit.jsonl)
    AEGIS_DB      SQLite file for SQL dry-runs (default: data/demo.db if it exists)
"""
import os
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
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


engine = build_engine()
app = FastAPI(title="AEGIS", version=__version__,
              description="The accountability layer for AI agents.")


# ---------- request shapes ----------
class ActionIn(BaseModel):
    action: str = Field(..., description="SQL text, a shell command, or a SOC action as JSON text")
    kind: str = Field("sql", description="sql | shell | soc")
    agent: str = "default"
    tokens: int = 0
    cost: float = 0.0


class ChatIn(BaseModel):
    message: str
    agent: str = "chat"


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
    return {"name": "AEGIS", "version": __version__, "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok", "version": __version__}


@app.post("/evaluate")
def evaluate(body: ActionIn):
    """Send one agent action through AEGIS and get the decision back."""
    decision = engine.evaluate(body.action, kind=body.kind, agent=body.agent,
                               tokens=body.tokens, cost=body.cost)
    return decision.to_dict()


@app.post("/chat")
def chat(body: ChatIn):
    """Plain-language entry point. See aegis/chat.py for what it understands."""
    return handle_message(engine, body.message, agent=body.agent)


@app.get("/audit")
def audit(limit: int = 100, verdict: Optional[str] = None):
    """Newest entries first."""
    entries = engine.audit.read_all()
    if verdict:
        entries = [e for e in entries if str(e.get("verdict", "")).upper() == verdict.upper()]
    return {"count": len(entries), "entries": list(reversed(entries))[:limit]}


@app.get("/audit/verify")
def audit_verify():
    ok, message = engine.audit.verify()
    return {"intact": ok, "message": message}


@app.get("/stats")
def stats():
    entries = engine.audit.read_all()
    verdicts, kinds, risks, agents = {}, {}, {}, {}
    for e in entries:
        for table, key in ((verdicts, "verdict"), (kinds, "kind"), (risks, "risk"), (agents, "agent")):
            value = str(e.get(key, "unknown"))
            table[value] = table.get(value, 0) + 1
    ok, message = engine.audit.verify()
    return {"total": len(entries), "verdicts": verdicts, "kinds": kinds, "risks": risks,
            "agents": agents, "log_intact": ok, "integrity_message": message}


@app.get("/pending")
def pending():
    """REVIEW decisions that a human has not approved yet."""
    entries = engine.audit.read_all()
    approved = {e.get("original") for e in entries if e.get("verdict") == "HUMAN_APPROVED"}
    waiting = [e for e in entries if e.get("verdict") == "REVIEW" and e.get("original") not in approved]
    return {"count": len(waiting), "entries": list(reversed(waiting))}


@app.post("/approve")
def approve(body: ApproveIn):
    """A human says 'yes, this action is fine'. It is recorded, and counts toward learned rules."""
    entry = learn.record_approval(engine.audit, body.action, body.agent, body.kind)
    return {"recorded": True, "seq": entry["seq"]}


@app.get("/learn/suggestions")
def learn_suggestions():
    return {"suggestions": learn.suggest_rules(engine.audit)}


@app.post("/learn/rules")
def learn_add_rule(body: RuleIn):
    try:
        rule = learn.add_rule(body.pattern, body.reason)
    except Exception as error:               # bad regex, unwritable file ...
        raise HTTPException(status_code=400, detail=str(error))
    engine.learned = learn.load_rules()      # take effect immediately
    return rule


@app.post("/agents/{agent}/reset")
def reset_agent(agent: str):
    """Clear the loop/budget counters of one agent."""
    engine.behaviour.reset(agent)
    return {"reset": agent}