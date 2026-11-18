
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
import secrets
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.security import HTTPBearer
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, learn, policy
from .approvals import ApprovalError, ApprovalStore
from .chat import handle_message
from .engine import Engine
from .sandbox import Sandbox, SandboxError
import json
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parent.parent
DASHBOARD = Path(__file__).parent / "dashboard" / "operations.html"


def build_engine() -> Engine:
    """Create an Engine from environment variables and policies/general.yaml."""

    general = policy.load("general")

    db_path = os.environ.get("AEGIS_DB")

    if not db_path and (ROOT / "data" / "demo.db").exists():
        db_path = str(ROOT / "data" / "demo.db")

    configured_audit = os.environ.get("AEGIS_AUDIT")
    recovered_audit = ROOT / "aegis_audit.recovered.jsonl"
    default_audit = recovered_audit if recovered_audit.exists() else ROOT / "aegis_audit.jsonl"
    audit_path = configured_audit or str(default_audit)

    return Engine(
        audit_path=audit_path,
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

reviewer_bearer = HTTPBearer(auto_error=False)

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


class ReviewIn(BaseModel):
    review_seq: int = Field(..., ge=1)


class ApprovalConsumeIn(BaseModel):
    approval_id: str = Field(..., min_length=1, max_length=64)
    action: str = Field(..., min_length=1, max_length=10000)
    kind: str = Field(..., min_length=1, max_length=32)
    agent: str = Field(..., min_length=1, max_length=128)


class RuleIn(BaseModel):
    pattern: str
    reason: str


class SandboxExecuteIn(BaseModel):
    operation: str = Field(..., min_length=1, max_length=32)
    path: str = Field(".", min_length=1, max_length=1024)
    content: Optional[str] = Field(None, max_length=1048576)
    approval_id: Optional[str] = Field(None, min_length=1, max_length=64)
    agent: str = Field("default", min_length=1, max_length=128)



def get_approval_store() -> ApprovalStore:
    """Use an approval database associated with the active audit log."""
    configured = os.environ.get("AEGIS_APPROVALS")
    if configured:
        path = configured
    else:
        audit_path = Path(engine.audit.path)
        path = audit_path.with_name(
            audit_path.stem + ".approvals.sqlite3"
        )
    return ApprovalStore(path)


def get_review_entry(review_seq: int) -> dict:
    """Find one genuine REVIEW event in the current audit log."""
    intact, message = engine.audit.verify()
    if not intact:
        raise HTTPException(
            status_code=409,
            detail=f"Audit log integrity check failed: {message}",
        )

    matches = [
        entry
        for entry in engine.audit.read_all()
        if entry.get("seq") == review_seq
        and entry.get("verdict") == "REVIEW"
    ]

    if len(matches) != 1:
        raise HTTPException(
            status_code=404,
            detail="Review event not found.",
        )

    return matches[0]


def require_reviewer(authorization: Optional[str]):
    """Require a configured reviewer token for approval operations."""
    expected = os.environ.get("AEGIS_REVIEW_TOKEN", "")

    if len(expected) < 32:
        raise HTTPException(
            status_code=503,
            detail="Reviewer authentication is not configured. Set AEGIS_REVIEW_TOKEN to a secret of at least 32 characters.",
        )

    supplied = ""
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()

    if not supplied or not secrets.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=401,
            detail="Valid reviewer authentication is required.",
        )


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



AGENT_MONITORING = {
    "database-agent": {
        "name": "Database Agent",
        "description": "Read-only queries against the isolated demo database.",
    },
    "soc-agent": {
        "name": "SOC Agent",
        "description": "Synthetic security-event monitoring and response simulation.",
    },
    "devops-agent": {
        "name": "DevOps Agent",
        "description": "Simulated infrastructure and deployment proposals.",
    },
}


@app.get("/agents/status")
def agent_status():
    """Read-only status and recent event history for simulated agents."""

    data_dir = ROOT / "agents" / "data"
    runtime_dir = data_dir / "runtime"
    logs_dir = data_dir / "logs"

    now = datetime.now(timezone.utc)
    agents = []

    for agent_id, metadata in AGENT_MONITORING.items():
        runtime_path = runtime_dir / f"{agent_id}.json"
        log_path = logs_dir / f"{agent_id}.jsonl"

        state = {}
        if runtime_path.is_file():
            try:
                state = json.loads(runtime_path.read_text(encoding="utf-8"))
                if not isinstance(state, dict):
                    state = {}
            except (OSError, json.JSONDecodeError):
                state = {"status": "error", "last_error": "Runtime state could not be read."}

        recent_events = []
        if log_path.is_file():
            try:
                lines = log_path.read_text(encoding="utf-8").splitlines()
                for line in lines[-8:]:
                    try:
                        event = json.loads(line)
                        if isinstance(event, dict):
                            recent_events.append(event)
                    except json.JSONDecodeError:
                        continue
            except OSError:
                pass

        status = state.get("status", "not_started")
        last_seen = state.get("last_seen")

        if status == "running":
            try:
                heartbeat = datetime.fromisoformat(last_seen)
                if heartbeat.tzinfo is None:
                    heartbeat = heartbeat.replace(tzinfo=timezone.utc)
                age = (now - heartbeat).total_seconds()
                if age > 45:
                    status = "stale"
            except (TypeError, ValueError):
                status = "stale"

        agents.append({
            "agent_id": agent_id,
            "name": metadata["name"],
            "description": metadata["description"],
            "status": status,
            "last_seen": last_seen,
            "last_action": state.get("last_action"),
            "last_verdict": state.get("last_verdict"),
            "last_rule": state.get("last_rule"),
            "last_reason": state.get("last_reason"),
            "last_error": state.get("last_error"),
            "last_simulation": state.get("last_simulation"),
            "recent_events": list(reversed(recent_events)),
        })

    return {
        "agents": agents,
        "connected_count": sum(
            1 for agent in agents if agent["status"] == "running"
        ),
        "total_agents": len(agents),
        "updated_at": now.isoformat(),
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
    """Return REVIEW events that have not been resolved."""
    store = get_approval_store()
    entries = engine.audit.read_all()

    waiting = []
    for entry in entries:
        if entry.get("verdict") != "REVIEW":
            continue

        record = store.get_for_review(entry["seq"])
        if record is None:
            waiting.append(entry)

    return {
        "count": len(waiting),
        "entries": list(reversed(waiting)),
    }


@app.post("/approve")
def approve(body: ReviewIn, credentials=Depends(reviewer_bearer)):
    """Approve one exact REVIEW event. This does not execute it."""
    require_reviewer(
        f"Bearer {credentials.credentials}" if credentials else None
    )
    review = get_review_entry(body.review_seq)
    store = get_approval_store()

    try:
        grant = store.approve(
            review_seq=review["seq"],
            action=review["original"],
            kind=review.get("kind", "other"),
            agent=review.get("agent", "default"),
        )
    except ApprovalError as error:
        raise HTTPException(status_code=409, detail=str(error))

    try:
        entry = engine.audit.append({
            "verdict": "APPROVAL_GRANTED",
            "agent": review.get("agent", "default"),
            "kind": review.get("kind", "other"),
            "original": review["original"],
            "rule": "HUMAN",
            "reason": "human approval recorded; no action executed",
            "review_seq": review["seq"],
            "approval_id": grant["approval_id"],
            "expires_at": grant["expires_at"],
        })
    except Exception:
        store.rollback_resolution(review["seq"], grant["approval_id"])
        raise HTTPException(
            status_code=503,
            detail="Audit recording failed. The approval grant was rolled back.",
        )

    return {
        "recorded": True,
        "status": grant["status"],
        "approval_id": grant["approval_id"],
        "review_seq": grant["review_seq"],
        "expires_at": grant["expires_at"],
        "audit_seq": entry["seq"],
        "executed": False,
    }


@app.post("/reject")
def reject(body: ReviewIn, authorization: Optional[str] = Header(None)):
    """Reject one exact REVIEW event. No grant or execution is created."""
    require_reviewer(authorization)
    review = get_review_entry(body.review_seq)
    store = get_approval_store()

    try:
        result = store.reject(
            review_seq=review["seq"],
            action=review["original"],
            kind=review.get("kind", "other"),
            agent=review.get("agent", "default"),
        )
    except ApprovalError as error:
        raise HTTPException(status_code=409, detail=str(error))

    try:
        entry = engine.audit.append({
            "verdict": "APPROVAL_REJECTED",
            "agent": review.get("agent", "default"),
            "kind": review.get("kind", "other"),
            "original": review["original"],
            "rule": "HUMAN",
            "reason": "rejected by a person; no action executed",
            "review_seq": review["seq"],
        })
    except Exception:
        store.rollback_resolution(review["seq"])
        raise HTTPException(
            status_code=503,
            detail="Audit recording failed. The rejection record was rolled back.",
        )

    return {
        "recorded": True,
        "status": result["status"],
        "review_seq": result["review_seq"],
        "audit_seq": entry["seq"],
        "executed": False,
    }


@app.get("/approvals")
def approvals(authorization: Optional[str] = Header(None)):
    """Return recent approval and rejection history to authenticated reviewers."""
    require_reviewer(authorization)
    return {"entries": get_approval_store().list_recent()}


@app.post("/consume")
def consume_approval(
    body: ApprovalConsumeIn,
    authorization: Optional[str] = Header(None),
):
    """Consume a one-time grant after a fresh independent security evaluation.

    This endpoint authorizes only. It never executes shell commands.
    """
    require_reviewer(authorization)

    store = get_approval_store()
    grant = store.get_by_approval(body.approval_id)

    if grant is None:
        raise HTTPException(status_code=404, detail="Approval not found.")

    review = get_review_entry(grant["review_seq"])

    if (
        body.action != review.get("original")
        or body.kind != review.get("kind", "other")
        or body.agent != review.get("agent", "default")
    ):
        raise HTTPException(
            status_code=409,
            detail="The submitted action does not match the original reviewed event.",
        )

    # Re-evaluate from scratch. Approval cannot override BLOCK, REVIEW or CORRECT.
    decision = engine.evaluate(
        body.action,
        kind=body.kind,
        agent=body.agent,
    )
    fresh = decision.to_dict()
    verdict = str(fresh.get("verdict", "")).upper()

    if verdict != "ALLOW":
        raise HTTPException(
            status_code=409,
            detail=f"Fresh AEGIS evaluation returned {verdict or 'an unknown verdict'}. Authorization denied.",
        )

    try:
        result = store.consume(
            body.approval_id,
            body.action,
            body.kind,
            body.agent,
        )
    except ApprovalError as error:
        raise HTTPException(status_code=409, detail=str(error))

    try:
        entry = engine.audit.append({
            "verdict": "APPROVAL_CONSUMED",
            "agent": body.agent,
            "kind": body.kind,
            "original": body.action,
            "rule": "HUMAN",
            "reason": "one-time grant consumed after fresh ALLOW evaluation; no action executed",
            "review_seq": result["review_seq"],
            "approval_id": result["approval_id"],
        })
    except Exception:
        # The grant remains consumed. Fail closed rather than risk reuse.
        raise HTTPException(
            status_code=503,
            detail="Grant consumed, but the final audit event could not be written. No action was executed.",
        )

    return {
        "authorized": True,
        "status": "CONSUMED",
        "approval_id": result["approval_id"],
        "review_seq": result["review_seq"],
        "audit_seq": entry["seq"],
        "executed": False,
        "message": "Authorization consumed. No command or external action was executed.",
    }




@app.post("/sandbox/execute")
def sandbox_execute(
    body: SandboxExecuteIn,
    credentials = Depends(reviewer_bearer),
):
    """Execute only registered sandbox operations after fresh AEGIS evaluation."""
    require_reviewer(f"Bearer {credentials.credentials}" if credentials else None)

    if body.operation not in {
        "list_files", "read_file", "write_file", "delete_file"
    }:
        raise HTTPException(status_code=400, detail="Unregistered sandbox operation.")

    if body.operation == "write_file" and body.content is None:
        raise HTTPException(status_code=400, detail="write_file requires content.")

    if body.operation != "write_file" and body.content is not None:
        raise HTTPException(
            status_code=400,
            detail="content is accepted only for write_file."
        )

    request = {"operation": body.operation, "path": body.path}
    if body.operation == "write_file":
        request["content"] = body.content

    action = json.dumps(request, sort_keys=True, separators=(",", ":"))
    kind = "sandbox"
    agent = body.agent

    # Fresh evaluation immediately before any execution.
    decision = engine.evaluate(action, kind=kind, agent=agent)
    verdict = str(
        getattr(decision.verdict, "value", decision.verdict)
    ).upper()

    if verdict == "BLOCK":
        raise HTTPException(
            status_code=403,
            detail="AEGIS BLOCK: sandbox operation was not executed."
        )

    approval_result = None

    if verdict == "REVIEW":
        if not body.approval_id:
            raise HTTPException(
                status_code=409,
                detail=(
                    "Human approval required. Approve the matching REVIEW "
                    "audit event, then submit its approval_id."
                )
            )

        store = get_approval_store()
        grant = store.get_by_approval(body.approval_id)

        if grant is None:
            raise HTTPException(status_code=404, detail="Approval not found.")

        review = get_review_entry(grant["review_seq"])

        if (
            review.get("original") != action
            or review.get("kind") != kind
            or review.get("agent") != agent
        ):
            raise HTTPException(
                status_code=409,
                detail="Approval does not match this exact sandbox request."
            )

        try:
            approval_result = store.consume(
                body.approval_id, action, kind, agent
            )
        except ApprovalError as error:
            raise HTTPException(status_code=409, detail=str(error))

    elif verdict != "ALLOW":
        raise HTTPException(
            status_code=409,
            detail=f"AEGIS returned {verdict}; execution denied."
        )

    # Record authorization before touching the filesystem.
    try:
        engine.audit.append({
            "verdict": "SANDBOX_EXECUTION_AUTHORIZED",
            "agent": agent,
            "kind": kind,
            "original": action,
            "rule": "AEGIS",
            "reason": "Fresh evaluation passed; registered sandbox operation only.",
            "approval_id": (
                approval_result["approval_id"] if approval_result else None
            ),
            "review_seq": (
                approval_result["review_seq"] if approval_result else None
            ),
        })
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Authorization audit failed. No operation was executed."
        )

    sandbox = Sandbox()

    try:
        if body.operation == "list_files":
            result = sandbox.list_files(body.path)
        elif body.operation == "read_file":
            result = sandbox.read_file(body.path)
        elif body.operation == "write_file":
            result = sandbox.write_file(body.path, body.content)
        else:
            result = sandbox.delete_file(body.path)

    except SandboxError as error:
        try:
            engine.audit.append({
                "verdict": "SANDBOX_EXECUTION_FAILED",
                "agent": agent,
                "kind": kind,
                "original": action,
                "rule": "SANDBOX",
                "reason": str(error),
            })
        except Exception:
            pass

        raise HTTPException(status_code=400, detail=str(error))

    except Exception:
        try:
            engine.audit.append({
                "verdict": "SANDBOX_EXECUTION_FAILED",
                "agent": agent,
                "kind": kind,
                "original": action,
                "rule": "SANDBOX",
                "reason": "Unexpected execution error.",
            })
        except Exception:
            pass

        raise HTTPException(status_code=500, detail="Sandbox operation failed.")

    try:
        entry = engine.audit.append({
            "verdict": "SANDBOX_EXECUTED",
            "agent": agent,
            "kind": kind,
            "original": action,
            "rule": "SANDBOX",
            "reason": "Registered sandbox operation completed.",
            "result": result if body.operation != "read_file" else {
                "read": True, "characters": len(result)
            },
        })
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Operation completed, but its outcome audit could not be recorded."
        )

    return {
        "executed": True,
        "operation": body.operation,
        "result": result,
        "audit_seq": entry["seq"],
        "approval_id": (
            approval_result["approval_id"] if approval_result else None
        ),
    }


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
