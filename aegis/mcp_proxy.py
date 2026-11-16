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
import queue
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

    def reject_invalid_request(reason):
        return None, {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {
                "code": -32602,
                "message": f"Invalid MCP tool request: {reason}",
            },
        }

    params = message.get("params")
    if not isinstance(params, dict):
        return reject_invalid_request("params must be an object")

    tool = params.get("name")
    if not isinstance(tool, str) or not tool.strip():
        return reject_invalid_request("tool name must be a non-empty string")

    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        return reject_invalid_request("arguments must be an object")

    for key in SQL_ARGS + SHELL_ARGS:
        if key in arguments and not isinstance(arguments[key], str):
            return reject_invalid_request(
                f"argument '{key}' must be a string"
            )

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
    """Start an MCP server and safely relay messages in both directions."""
    server = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    write_lock = threading.Lock()
    incoming = queue.Queue()
    stopped = object()

    def to_agent(text: str):
        with write_lock:
            sys.stdout.write(text if text.endswith("\\n") else text + "\\n")
            sys.stdout.flush()

    def pump_server_to_agent():
        try:
            for line in server.stdout:
                to_agent(line)
        except (BrokenPipeError, OSError):
            pass

    def read_agent_input():
        try:
            for line in sys.stdin:
                incoming.put(line)
        finally:
            incoming.put(stopped)

    output_thread = threading.Thread(target=pump_server_to_agent, daemon=True)
    input_thread = threading.Thread(target=read_agent_input, daemon=True)
    output_thread.start()
    input_thread.start()

    return_code = 1

    try:
        while server.poll() is None:
            try:
                line = incoming.get(timeout=0.1)
            except queue.Empty:
                continue

            if line is stopped:
                break
            if not line.strip():
                continue

            try:
                message = json.loads(line)
            except (ValueError, TypeError):
                to_agent(json.dumps({
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": "Parse error: invalid JSON",
                    },
                }))
                continue

            if not isinstance(message, dict):
                to_agent(json.dumps({
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32600,
                        "message": "Invalid JSON-RPC request: expected an object",
                    },
                }))
                continue

            forward, reply = inspect_request(engine, message, agent)

            if reply is not None:
                to_agent(json.dumps(reply))

            if forward is not None:
                try:
                    server.stdin.write(json.dumps(forward) + "\\n")
                    server.stdin.flush()
                except (BrokenPipeError, OSError, ValueError):
                    break

    except KeyboardInterrupt:
        pass
    finally:
        try:
            server.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            pass

        try:
            return_code = server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.terminate()
            try:
                return_code = server.wait(timeout=2)
            except subprocess.TimeoutExpired:
                server.kill()
                return_code = server.wait()

        output_thread.join(timeout=1)

    return return_code
