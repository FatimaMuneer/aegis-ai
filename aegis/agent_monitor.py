"""Shared live status registry for AEGIS simulated agents."""

import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

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


def get_agent_status():
    """Return registered agents and their latest runtime status."""

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
                state = {
                    "status": "error",
                    "last_error": "Runtime state could not be read.",
                }

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
