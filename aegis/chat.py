"""chat.py - talk to AEGIS in plain language.

You type an action, AEGIS works out what kind it is, runs it through the Engine
and answers in a friendly sentence. It works fully offline (no AI needed).

  sql: DELETE FROM orders                 force the kind with a prefix
  shell: rm -rf ./build
  soc: {"action": "block_ip", ...}
  SELECT * FROM orders                    or let AEGIS guess the kind

Special commands:  help | stats | verify | pending | quit

Run it:  python -m aegis.chat
"""
import json
import re

from .engine import Engine, verdict_name

SQL_START = re.compile(r"^\s*(select|insert|update|delete|drop|truncate|alter|create|grant|revoke|with|pragma|attach)\b",
                       re.IGNORECASE)
SHELL_START = re.compile(r"^\s*(sudo|ls|cat|rm|mv|cp|cd|pwd|echo|curl|wget|chmod|chown|git|docker|kubectl|"
                         r"terraform|helm|pip|npm|printenv|kill|ssh|dd|mkfs|shutdown|reboot|head|tail|grep)\b")

HELP = ("I check what an AI agent wants to do before it does it.\n"
        "Type an SQL query, a shell command, or a SOC action (JSON). Examples:\n"
        "  SELECT * FROM orders\n"
        "  rm -rf ./*\n"
        '  soc: {"action": "isolate_host", "target": "laptop-17", "alert_id": "A-1", "severity": "high"}\n'
        "Commands: stats, verify, pending, help, quit.")

SAYS = {
    "ALLOW": "Allowed. It is safe to run.",
    "CORRECT": "Fixed. I changed it into a safe version.",
    "REVIEW": "Needs a human. Do not run it until a person approves.",
    "BLOCK": "Blocked. This must never run.",
}


def detect_kind(text: str) -> str:
    """Guess whether text is sql, shell or soc."""
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            if "action" in json.loads(stripped):
                return "soc"
        except ValueError:
            pass
    if SQL_START.match(stripped):
        return "sql"
    if SHELL_START.match(stripped) or "|" in stripped or "&&" in stripped:
        return "shell"
    return "shell"      # unknown text is treated as a command, and the guard will fail closed


def split_prefix(message: str):
    """'sql: SELECT 1' -> ('sql', 'SELECT 1'). No prefix -> (None, message)."""
    match = re.match(r"^\s*(sql|shell|soc)\s*:\s*(.*)$", message, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).lower(), match.group(2).strip()
    return None, message.strip()


def explain(decision) -> str:
    name = verdict_name(decision)
    lines = [f"{name}: {SAYS.get(name, '')}", f"Why: {decision.reason}",
             f"Rule: {decision.rule}   Risk: {decision.risk}"]
    if decision.corrected:
        lines.append(f"Safe version: {decision.corrected}")
    return "\n".join(lines)


def handle_message(engine: Engine, message: str, agent: str = "chat") -> dict:
    """Returns {"reply": str, "decision": dict | None}. Used by the CLI and the /chat API route."""
    text = message.strip()
    lowered = text.lower()

    if not text or lowered in ("help", "?"):
        return {"reply": HELP, "decision": None}

    if lowered == "stats":
        entries = engine.audit.read_all()
        counts = {}
        for e in entries:
            counts[e.get("verdict", "?")] = counts.get(e.get("verdict", "?"), 0) + 1
        summary = ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "nothing logged yet"
        return {"reply": f"{len(entries)} entries logged ({summary}).", "decision": None}

    if lowered == "verify":
        ok, msg = engine.audit.verify()
        return {"reply": ("Log is intact." if ok else "WARNING: ") + ("" if ok else msg), "decision": None}

    if lowered == "pending":
        entries = engine.audit.read_all()
        approved = {e.get("original") for e in entries if e.get("verdict") == "HUMAN_APPROVED"}
        waiting = [e for e in entries if e.get("verdict") == "REVIEW" and e.get("original") not in approved]
        if not waiting:
            return {"reply": "Nothing is waiting for a human.", "decision": None}
        return {"reply": "Waiting for a human:\n" + "\n".join(f"  #{e['seq']} {e['original']}" for e in waiting),
                "decision": None}

    kind, action = split_prefix(text)
    kind = kind or detect_kind(action)
    decision = engine.evaluate(action, kind=kind, agent=agent)
    return {"reply": explain(decision), "decision": decision.to_dict()}


def run_chat(engine: Engine = None) -> None:
    engine = engine or Engine()
    print("AEGIS chat. Type 'help' for examples, 'quit' to leave.\n")
    while True:
        try:
            message = input("you > ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if message.strip().lower() in ("quit", "exit"):
            break
        print(handle_message(engine, message)["reply"], "\n")


if __name__ == "__main__":
    run_chat()