"""mcp_proxy.py - puts AEGIS in front of any MCP server.

An AI agent talks to an MCP server using JSON-RPC messages, one per line, over
stdin/stdout. This proxy sits in the middle:

    agent  <-->  AEGIS proxy  <-->  real MCP server

Every "tools/call" request is checked by the Engine first:
    ALLOW    forwarded unchanged
    CORRECT  forwarded with the safe, corrected version of the action
    REVIEW   NOT forwarded. The agent gets an error saying a human must approve
    BLOCK    NOT forwarded. The agent gets an error
Everything else (initialize, tools/list, notifications ...) passes straight through.

Use it (point your agent's MCP config at this command instead of the real server):
    python -m aegis.cli proxy -- npx -y some-mcp-server
"""
import json
import subprocess
import sys
import threading

from .engine import Engine, verdict_name

ERROR_NEEDS_HUMAN = -32001
ERROR_BLOCKED = -32002

SQL_TOOLS = ("sql", "query", "database", "db_")
SHELL_TOOLS = ("shell", "bash", "exec", "command", "terminal", "run_")
SQL_ARGS = ("query", "sql", "statement")
SHELL_ARGS = ("command", "cmd", "script")


def classify(tool: str, arguments: dict):
    """Work out (kind, action_text, argument_name) for one tool call.
    argument_name is the argument that holds the action, so a corrected version can be put back."""
    name = (tool or "").lower()
    arguments = arguments or {}
    if any(k in arguments for k in SQL_ARGS) or any(w in name for w in SQL_TOOLS):
        for key in SQL_ARGS:
            if key in arguments:
                return "sql", str(arguments[key]), key
    if any(k in arguments for k in SHELL_ARGS) or any(w in name for w in SHELL_TOOLS):
        for key in SHELL_ARGS:
            if key in arguments:
                return "shell", str(arguments[key]), key
    # anything else is treated as a SOC-style action: {"action": <tool name>, ...arguments}
    return "soc", json.dumps({"action": name, **arguments}, sort_keys=True), None


def inspect_request(engine: Engine, message: dict, agent: str = "mcp"):
    """Look at one JSON-RPC message.

    Returns (forward, reply):
      forward  the message to send on to the real server (or None if it was stopped)
      reply    a JSON-RPC error to send back to the agent (or None)
    """
    if message.get("method") != "tools/call":
        return message, None

    params = message.get("params") or {}
    tool, arguments = params.get("name", ""), params.get("arguments") or {}
    kind, action, arg_name = classify(tool, arguments)
    decision = engine.evaluate(action, kind=kind, agent=agent)
    verdict = verdict_name(decision)

    if verdict == "ALLOW":
        return message, None

    if verdict == "CORRECT" and decision.corrected:
        fixed = json.loads(json.dumps(message))          # deep copy
        if arg_name:                                      # sql / shell: replace the one argument
            fixed["params"]["arguments"][arg_name] = decision.corrected
        else:                                             # soc: corrected text is the whole action as JSON
            new_action = json.loads(decision.corrected)
            new_action.pop("action", None)
            fixed["params"]["name"] = json.loads(decision.corrected).get("action", tool)
            fixed["params"]["arguments"] = new_action
        return fixed, None

    code = ERROR_BLOCKED if verdict == "BLOCK" else ERROR_NEEDS_HUMAN
    text = (f"AEGIS {verdict}: {decision.reason} (rule {decision.rule})"
            + ("" if verdict == "BLOCK" else " A human must approve this action first."))
    error = {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": code, "message": text}}
    return None, error


def run_proxy(command: list, engine: Engine, agent: str = "mcp") -> int:
    """Start the real MCP server and relay messages in both directions."""
    server = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              text=True, bufsize=1)
    write_lock = threading.Lock()

    def to_agent(text: str):
        with write_lock:
            sys.stdout.write(text if text.endswith("\n") else text + "\n")
            sys.stdout.flush()

    def pump_server_to_agent():
        for line in server.stdout:
            to_agent(line)

    threading.Thread(target=pump_server_to_agent, daemon=True).start()

    for line in sys.stdin:                                # agent -> server
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except ValueError:
            server.stdin.write(line)                      # not JSON: not ours to judge
            server.stdin.flush()
            continue
        forward, reply = inspect_request(engine, message, agent) if isinstance(message, dict) else (message, None)
        if reply is not None:
            to_agent(json.dumps(reply))
        if forward is not None:
            server.stdin.write(json.dumps(forward) + "\n")
            server.stdin.flush()

    server.stdin.close()
    return server.wait()