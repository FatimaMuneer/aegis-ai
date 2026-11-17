
"""sandbox.py - restricted file operations for the AEGIS sandbox.

This module deliberately does not execute shell commands or subprocesses.
All file operations are confined to the configured workspace.
"""

from pathlib import Path
import os


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORKSPACE = PROJECT_ROOT / ".aegis_sandbox" / "workspace"


class SandboxError(Exception):
    """Raised when a sandbox operation is unsafe or invalid."""


class Sandbox:
    def __init__(self, workspace=DEFAULT_WORKSPACE):
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _is_reparse_point(path):
        """Detect Windows reparse points and symbolic links."""

        import stat

        try:
            info = path.lstat()
        except FileNotFoundError:
            return False
        except OSError as error:
            raise SandboxError(
                f"Could not inspect filesystem entry: {error}"
            ) from error

        attributes = getattr(info, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)

        return bool(attributes & reparse_flag)

    def _safe_path(self, relative_path):
        """Resolve a relative path and reject traversal and symlinks."""

        if not isinstance(relative_path, str) or not relative_path.strip():
            raise SandboxError("A non-empty relative path is required.")

            # Reject Windows drive paths and rooted paths on every platform.
        windows_path = relative_path.replace("/", "\\")

        if windows_path.startswith("\\") or (
            len(windows_path) >= 2 and windows_path[1] == ":"
        ):
            raise SandboxError("Absolute or drive-relative paths are not allowed.")

        # Reject traversal using either slash convention.
        parts = relative_path.replace("\\", "/").split("/")

        if ".." in parts:
            raise SandboxError("Path traversal is not allowed.")

        candidate = Path(*parts)

        if candidate.is_absolute() or candidate.drive:
            raise SandboxError("Absolute paths are not allowed.")

        current = self.workspace

        for part in candidate.parts:
            if part in ("", "."):
                continue

            current = current / part

            if current.is_symlink() or self._is_reparse_point(current):
                raise SandboxError(
                    "Symlinks and Windows reparse points are not allowed."
                )

        resolved = current.resolve(strict=False)

        try:
            resolved.relative_to(self.workspace)
        except ValueError:
            raise SandboxError("Path escapes the sandbox workspace.")

        return resolved

    def list_files(self, path="."):
        """List files and directories inside the workspace."""

        target = self._safe_path(path)

        if not target.exists():
            raise SandboxError("Directory does not exist.")

        if not target.is_dir():
            raise SandboxError("The requested path is not a directory.")

        results = []

        for item in sorted(target.iterdir()):
            if item.is_symlink():
                continue

            results.append({
                "name": item.name,
                "type": "directory" if item.is_dir() else "file",
            })

        return results

    def read_file(self, path):
        """Read a UTF-8 text file from the workspace."""

        target = self._safe_path(path)

        if not target.exists() or not target.is_file():
            raise SandboxError("File does not exist.")

        if target.is_symlink():
            raise SandboxError("Symlinks are not allowed.")

        try:
            with target.open("rb") as file:
                content = file.read(1024 * 1024 + 1)

            if len(content) > 1024 * 1024:
                raise SandboxError("Files larger than 1 MB cannot be read.")

            return content.decode("utf-8")

        except UnicodeDecodeError:
            raise SandboxError("Only UTF-8 text files can be read.")
        except OSError as error:
            raise SandboxError(f"Could not read file: {error}")

    def write_file(self, path, content):
        """Create or overwrite a UTF-8 text file inside the workspace."""

        if not isinstance(content, str):
            raise SandboxError("File content must be text.")

        encoded = content.encode("utf-8")

        if len(encoded) > 1024 * 1024:
            raise SandboxError("Files larger than 1 MB cannot be written.")

        target = self._safe_path(path)
        parent = target.parent

        # Validate the parent before creating directories.
        safe_parent = self._safe_path(str(parent.relative_to(self.workspace)))

        safe_parent.mkdir(parents=True, exist_ok=True)

        # Validate the complete path again after directory creation.
        target = self._safe_path(path)

        if target.exists() and not target.is_file():
            raise SandboxError("The target is not a regular file.")

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC

        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        descriptor = None

        try:
            descriptor = os.open(target, flags, 0o600)

            with os.fdopen(descriptor, "wb") as file:
                descriptor = None
                file.write(encoded)

        except OSError as error:
            raise SandboxError(f"Could not write file: {error}")

        finally:
            if descriptor is not None:
                os.close(descriptor)

        return {
            "written": True,
            "path": str(target.relative_to(self.workspace)),
            "bytes": len(encoded),
        }

    def delete_file(self, path):
        """Delete a regular file, never a directory."""

        target = self._safe_path(path)

        if not target.exists() or not target.is_file():
            raise SandboxError("File does not exist or is not a regular file.")

        if target.is_symlink():
            raise SandboxError("Symlinks are not allowed.")

        target.unlink()

        return {
            "deleted": True,
            "path": str(target.relative_to(self.workspace)),
        }
