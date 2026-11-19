"""Shared fail-closed runtime for local AEGIS demonstration agents."""
import json
import os
import time
import urllib.request
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "agents" / "data"
RUNTIME = DATA / "runtime"
LOGS = DATA / "logs"
API = os.getenv("AEGIS_API_URL", "http://127.0.0.1:8000").rstrip("/")

for folder in (DATA, RUNTIME, LOGS):
    folder.mkdir(parents=True, exist_ok=True)


def now():
    return datetime.now(timezone.utc).isoformat()


def write_state(agent, **fields):
    path = RUNTIME / f"{agent}.json"
    old = {}
    if path.exists():
        try:
            old = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    old.update(fields)
    old["agent_id"] = agent
    old["last_seen"] = now()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(old, indent=2), encoding="utf-8")
    tmp.replace(path)


def log_event(agent, event):
    path = LOGS / f"{agent}.jsonl"
    record = {"timestamp": now(), "agent_id": agent, **event}
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def evaluate(agent, action, kind):
    payload = {
        "agent": agent,
        "action": json.dumps(action) if isinstance(action, dict) else action,
        "kind": kind,
        "tokens": 0,
        "cost": 0.0,
    }
    request = urllib.request.Request(
        API + "/evaluate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            decision = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        write_state(
            agent,
            status="disconnected",
            last_error=str(exc),
            last_action=str(action),
        )
        log_event(agent, {
            "event": "evaluation_failed",
            "error": str(exc),
        })
        raise RuntimeError("AEGIS unavailable; action not simulated.") from exc

    verdict = decision.get("verdict", "BLOCK")
    write_state(
        agent,
        status="running",
        last_action=str(action),
        last_verdict=verdict,
        last_rule=decision.get("rule"),
        last_reason=decision.get("reason"),
        last_error=None,
    )
    log_event(agent, {
        "event": "proposal_evaluated",
        "action": action,
        "verdict": verdict,
        "rule": decision.get("rule"),
        "reason": decision.get("reason"),
    })
    return decision


def record_simulation(agent, description):
    write_state(agent, last_simulation=description)
    log_event(agent, {
        "event": "local_simulation",
        "description": description,
    })


def run_loop(agent, cycle, interval=12):
    print(f"[{agent}] Starting. AEGIS API: {API}", flush=True)
    write_state(agent, status="running", last_error=None)
    count = 0
    try:
        while True:
            count += 1
            try:
                cycle(count)
            except RuntimeError as exc:
                print(f"[{agent}] FAIL-CLOSED: {exc}", flush=True)
            except Exception as exc:
                write_state(agent, status="error", last_error=str(exc))
                log_event(agent, {"event": "agent_error", "error": str(exc)})
                print(f"[{agent}] ERROR: {exc}", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        write_state(agent, status="stopped")
        log_event(agent, {"event": "agent_stopped"})
        print(f"[{agent}] Stopped.", flush=True)
