"""Security guard for registered AEGIS sandbox operations."""
import json

from .models import Decision, Verdict
from .sandbox import Sandbox, SandboxError


def check_sandbox(action: str, policy: dict = None) -> Decision:
    try:
        request = json.loads(action)
        if not isinstance(request, dict):
            raise ValueError("Request must be a JSON object.")

        operation = request.get("operation")
        path = request.get("path")

        allowed = {
            "list_files": {"operation", "path"},
            "read_file": {"operation", "path"},
            "write_file": {"operation", "path", "content"},
            "delete_file": {"operation", "path"},
        }

        if operation not in allowed:
            return Decision(
                Verdict.BLOCK, "SBX-01", "Unregistered sandbox operation.",
                action, None, "HIGH"
            )

        if set(request) != allowed[operation]:
            return Decision(
                Verdict.BLOCK, "SBX-02", "Invalid operation arguments.",
                action, None, "HIGH"
            )

        if not isinstance(path, str) or not path.strip():
            raise ValueError("A valid relative path is required.")

        if operation == "write_file" and not isinstance(request.get("content"), str):
            raise ValueError("File content must be text.")

        # Validate confinement before the request can be approved or executed.
        Sandbox()._safe_path(path)

        if operation in ("list_files", "read_file"):
            return Decision(
                Verdict.ALLOW, "SBX-00",
                "Registered read-only sandbox operation.",
                action, None, "LOW"
            )

        return Decision(
            Verdict.REVIEW, "SBX-03",
            "Sandbox file modification requires human approval.",
            action, None, "MEDIUM"
        )

    except (ValueError, TypeError, SandboxError) as error:
        return Decision(
            Verdict.BLOCK, "SBX-04",
            f"Invalid or unsafe sandbox request: {error}",
            action, None, "HIGH"
        )
    except Exception:
        return Decision(
            Verdict.BLOCK, "SBX-05",
            "Sandbox request validation failed closed.",
            action, None, "HIGH"
        )
