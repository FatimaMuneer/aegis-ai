import json

from aegis.mcp_proxy import inspect_request


def make_message(command):
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "shell",
            "arguments": {"command": command},
        },
    }


def test_allow_forwards_request_unchanged(engine):
    message = make_message("ls")

    forward, reply = inspect_request(engine, message)

    assert forward == message
    assert reply is None


def test_correct_forwards_corrected_request(engine):
    message = make_message("rm -rf ./*")

    forward, reply = inspect_request(engine, message)

    assert reply is None
    assert forward is not None
    assert forward["params"]["arguments"]["command"] == "ls ./*"


def test_review_stops_request(engine):
    message = make_message("python my_script.py")

    forward, reply = inspect_request(engine, message)

    assert forward is None
    assert reply["error"]["code"] == -32001
    assert "REVIEW" in reply["error"]["message"]


def test_block_stops_request(engine):
    message = make_message("terraform destroy")

    forward, reply = inspect_request(engine, message)

    assert forward is None
    assert reply["error"]["code"] == -32002
    assert "BLOCK" in reply["error"]["message"]


def test_non_tool_request_passes_through(engine):
    message = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "initialize",
        "params": {},
    }

    forward, reply = inspect_request(engine, message)

    assert forward == message
    assert reply is None


def test_review_response_is_not_forwarded(engine):
    message = make_message("git push origin main")

    forward, reply = inspect_request(engine, message)

    assert forward is None
    assert reply is not None


def test_non_object_arguments_are_rejected(engine):
    message = make_message("ls")
    message["params"]["arguments"] = ["ls"]

    forward, reply = inspect_request(engine, message)

    assert forward is None
    assert reply is not None


def test_non_string_shell_command_is_rejected(engine):
    message = make_message("ls")
    message["params"]["arguments"]["command"] = {"cmd": "ls"}

    forward, reply = inspect_request(engine, message)

    assert forward is None
    assert reply is not None


def test_missing_tool_name_is_rejected(engine):
    message = make_message("ls")
    message["params"].pop("name")

    forward, reply = inspect_request(engine, message)

    assert forward is None
    assert reply is not None


class RecordingPipe:
    def __init__(self):
        self.data = ""
        self.closed = False

    def write(self, value):
        self.data += value

    def flush(self):
        pass

    def close(self):
        self.closed = True


class FakeServer:
    def __init__(self):
        import io
        self.stdin = RecordingPipe()
        self.stdout = io.StringIO("")

    def poll(self):
        return None

    def wait(self, timeout=None):
        return 0

    def terminate(self):
        pass

    def kill(self):
        pass


def test_run_proxy_does_not_forward_invalid_json(engine, monkeypatch):
    import io
    import sys
    import aegis.mcp_proxy as proxy

    server = FakeServer()
    monkeypatch.setattr(proxy.subprocess, "Popen", lambda *a, **k: server)
    monkeypatch.setattr(sys, "stdin", io.StringIO("{not json\n"))

    proxy.run_proxy(["fake-server"], engine)

    assert server.stdin.data == ""


def test_run_proxy_does_not_forward_non_object_json(engine, monkeypatch):
    import io
    import sys
    import aegis.mcp_proxy as proxy

    server = FakeServer()
    monkeypatch.setattr(proxy.subprocess, "Popen", lambda *a, **k: server)
    monkeypatch.setattr(sys, "stdin", io.StringIO('["not", "an", "object"]\n'))

    proxy.run_proxy(["fake-server"], engine)

    assert server.stdin.data == ""
