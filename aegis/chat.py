
"""AEGIS conversational interface.

Groq handles conversation and interprets natural-language intent.
The deterministic Engine makes all security decisions.
"""

import json
import re

from .assistant import ask_ai
from .engine import Engine, verdict_name
from .intent import interpret_intent


SQL_START = re.compile(
    r"^\s*(select|insert|update|delete|drop|truncate|alter|create|"
    r"grant|revoke|with|pragma|attach)\b",
    re.IGNORECASE
)

SHELL_START = re.compile(
    r"^\s*(sudo|ls|cat|rm|mv|cp|cd|pwd|echo|curl|wget|chmod|"
    r"chown|git|docker|kubectl|terraform|helm|pip|npm|printenv|"
    r"kill|ssh|dd|mkfs|shutdown|reboot|head|tail|grep|"
    r"python|python3|pytest|whoami|date|df)\b",
    re.IGNORECASE
)

SAYS = {
    "ALLOW": "Allowed. The security checks found no blocking issue.",
    "CORRECT": "A safer version is available.",
    "REVIEW": "This action requires human review. Do not execute it until approved.",
    "BLOCK": "Blocked. This action must not be executed.",
}

HELP = """I am AEGIS, an accountability and security layer for AI agents.

I can evaluate proposed actions before they are executed.

Try these examples:

SQL:
  SELECT * FROM orders
  DELETE FROM orders

Shell:
  ls
  rm -rf ./

SOC:
  soc: {"action": "isolate_host", "target": "laptop-17", "alert_id": "A-1", "severity": "high"}

Commands:
  stats    Show audit statistics
  verify   Verify audit log integrity
  pending  Show actions waiting for review
  help     Show this help
  quit     Exit AEGIS
"""


def detect_kind(text: str):
    """Identify supported action types without treating conversation as shell."""

    stripped = text.strip()

    if not stripped:
        return None

    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)

            if isinstance(data, dict) and "action" in data:
                return "soc"

        except (ValueError, TypeError):
            return "shell"

    if SQL_START.match(stripped):
        return "sql"

    if SHELL_START.match(stripped):
        return "shell"

    if any(operator in stripped for operator in ("&&", "||", "|")):
        return "shell"

    return None


def split_prefix(message: str):
    """Recognise explicit action prefixes."""

    match = re.match(
        r"^\s*(sql|shell|soc)\s*:\s*(.*)$",
        message,
        re.IGNORECASE | re.DOTALL
    )

    if match:
        return match.group(1).lower(), match.group(2).strip()

    return None, message.strip()


def explain(decision) -> str:
    """Convert a security decision into a readable response."""

    name = verdict_name(decision)

    lines = [
        f"{name}: {SAYS.get(name, 'Security decision returned.')}",
        f"Why: {decision.reason}",
        f"Rule: {decision.rule}   Risk: {decision.risk}",
    ]

    if decision.corrected:
        lines.append(f"Safe version: {decision.corrected}")

    return "\n".join(lines)


def general_response(message: str, history: list | None = None) -> str:
    """Generate a natural-language response using Groq."""

    return ask_ai(message, history=history)


def evaluate_action(engine, action, kind, agent):
    """Send a concrete action to the deterministic security engine."""

    decision = engine.evaluate(
        action,
        kind=kind,
        agent=agent
    )

    return {
        "reply": explain(decision),
        "decision": decision.to_dict()
    }


def interpret_natural_language(
    engine,
    message,
    agent,
    history=None
):
    """Interpret natural language without allowing AI to approve actions."""

    result = interpret_intent(message)

    if not isinstance(result, dict):
        return {
            "reply": (
                "I couldn't reliably interpret that request. "
                "Please clarify what you want AEGIS to evaluate."
            ),
            "decision": None
        }

    intent = result.get("intent")
    action = result.get("action")
    kind = result.get("kind")
    confidence = result.get("confidence", 0)

    # Do not rely on uncertain or failed AI interpretation.
    if (
        not isinstance(confidence, (int, float))
        or confidence < 0.6
    ):
        return {
            "reply": (
                "I couldn't confidently determine your intention. "
                "If you want me to check an action, please provide "
                "the exact command."
            ),
            "decision": None
        }

    if result.get("needs_clarification"):
        return {
            "reply": (
                result.get("clarification")
                or "Could you clarify exactly what action you mean?"
            ),
            "decision": None
        }

    # A natural-language request is not an executable command.
    if intent == "proposed_action":
        return {
            "reply": (
                "I understand that you want to perform an action"
                + (f": {action}" if action else "")
                + ".\n\n"
                "Before I can evaluate it, please provide the exact "
                "shell command, SQL statement, or SOC action. "
                "I won't invent or execute commands on your behalf."
            ),
            "decision": None
        }

    # A safety question can be evaluated only when the AI extracted
    # a concrete command that our existing detector recognises.
    if intent == "action_question":

        if not isinstance(action, str) or not action.strip():
            return {
                "reply": (
                    "Please provide the exact command you want me "
                    "to check. I need it to perform a meaningful "
                    "security evaluation."
                ),
                "decision": None
            }
        original_normalized = re.sub(
            r"\s+", " ", message
        ).casefold()

        action_normalized = re.sub(
            r"\s+", " ", action.strip()
        ).casefold()

        if action_normalized not in original_normalized:
            return {
                "reply": (
                    "I couldn't verify that the extracted command "
                    "was actually included in your message. "
                    "Please provide the exact command directly."
                ),
                "decision": None
            }
        detected_kind = detect_kind(action)

        if detected_kind is None or detected_kind != kind:
            return {
                "reply": (
                    "I couldn't verify the extracted action as a "
                    "supported command. Please provide the exact "
                    "command directly."
                ),
                "decision": None
            }

        return evaluate_action(
            engine,
            action.strip(),
            detected_kind,
            agent
        )

    if intent == "conversation":
        return {
            "reply": general_response(message, history),
            "decision": None
        }

    return {
        "reply": (
            "I couldn't determine the request type. "
            "Please rephrase your message or provide an exact command."
        ),
        "decision": None
    }


def handle_message(
    engine: Engine,
    message: str,
    agent: str = "chat",
    history: list | None = None
) -> dict:
    """Process a message and return {'reply': str, 'decision': dict | None}."""

    text = message.strip()
    lowered = text.lower()

    if not text or lowered in ("help", "?"):
        return {"reply": HELP, "decision": None}

    if lowered == "stats":
        entries = engine.audit.read_all()
        counts = {}

        for entry in entries:
            verdict = entry.get("verdict", "?")
            counts[verdict] = counts.get(verdict, 0) + 1

        summary = (
            ", ".join(
                f"{key}: {value}"
                for key, value in sorted(counts.items())
            )
            or "nothing logged yet"
        )

        return {
            "reply": f"{len(entries)} entries logged ({summary}).",
            "decision": None
        }

    if lowered in (
        "verify",
        "verify audit integrity",
        "verify the audit integrity",
        "check audit integrity",
        "check audit log integrity",
        "verify audit log",
    ):
        ok, msg = engine.audit.verify()

        return {
            "reply": "Log is intact." if ok else f"WARNING: {msg}",
            "decision": None
        }

    if lowered in (
    "pending",
    "show pending",
    "show pending actions",
    "show all pending human reviews",
    "show actions awaiting review",
    "list pending reviews",
    "what actions need human approval",
):
        entries = engine.audit.read_all()

        approved = {
            entry.get("original")
            for entry in entries
            if entry.get("verdict") == "HUMAN_APPROVED"
        }

        waiting = [
            entry for entry in entries
            if (
                entry.get("verdict") == "REVIEW"
                and entry.get("original") not in approved
            )
        ]

        if not waiting:
            return {
                "reply": "Nothing is waiting for a human.",
                "decision": None
            }

        return {
            "reply": (
                "Waiting for a human:\n"
                + "\n".join(
                    f"  #{entry['seq']} {entry['original']}"
                    for entry in waiting
                )
            ),
            "decision": None
        }

    # Explicit prefixes take priority.
    kind, action = split_prefix(text)

    if kind is None:
        kind = detect_kind(action)

    # Existing direct commands retain their original security path.
    if kind is not None:
        return evaluate_action(
            engine,
            action,
            kind,
            agent
        )

    # Natural-language messages are interpreted by Groq.
    return interpret_natural_language(
        engine,
        text,
        agent,
        history
    )


def run_chat(engine: Engine = None) -> None:
    """Run the command-line chat interface."""

    engine = engine or Engine()
    history = []

    print("AEGIS chat. Type 'help' for examples, 'quit' to leave.\n")

    while True:
        try:
            message = input("you > ")

        except (EOFError, KeyboardInterrupt):
            print()
            break

        if message.strip().lower() in ("quit", "exit"):
            break

        response = handle_message(
            engine,
            message,
            history=history
        )

        print(response["reply"], "\n")

        if response["decision"] is None and message.strip().lower() not in (
            "help", "?", "stats", "verify", "pending"
        ):
            history.append({"role": "user", "content": message})
            history.append({
                "role": "assistant",
                "content": response["reply"]
            })

            del history[:-20]


if __name__ == "__main__":
    run_chat()
