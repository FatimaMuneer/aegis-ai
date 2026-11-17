import pytest

from aegis.sandbox import Sandbox, SandboxError


def test_write_read_list_and_delete(tmp_path):
    sandbox = Sandbox(tmp_path / "workspace")

    result = sandbox.write_file("hello.txt", "Hello AEGIS")

    assert result["written"] is True
    assert sandbox.read_file("hello.txt") == "Hello AEGIS"
    assert {"name": "hello.txt", "type": "file"} in sandbox.list_files()

    assert sandbox.delete_file("hello.txt")["deleted"] is True


@pytest.mark.parametrize(
    "path",
    [
        "../outside.txt",
        "../../aegis/engine.py",
        r"..\outside.txt",
        r"..\..\aegis\engine.py",
        "C:outside.txt",
        r"\Windows\win.ini",
        r"C:\Windows\win.ini",
        r"C:Windows\win.ini",
    ],
)
def test_reject_unsafe_paths(tmp_path, path):
    sandbox = Sandbox(tmp_path / "workspace")

    with pytest.raises(SandboxError):
        sandbox.read_file(path)

def test_reject_empty_path(tmp_path):
    sandbox = Sandbox(tmp_path / "workspace")

    with pytest.raises(SandboxError):
        sandbox.read_file("")


def test_reject_non_text_content(tmp_path):
    sandbox = Sandbox(tmp_path / "workspace")

    with pytest.raises(SandboxError):
        sandbox.write_file("bad.txt", 123)


def test_reject_oversized_write(tmp_path):
    sandbox = Sandbox(tmp_path / "workspace")

    with pytest.raises(SandboxError):
        sandbox.write_file("large.txt", "A" * (1024 * 1024 + 1))


def test_reject_missing_file_read(tmp_path):
    sandbox = Sandbox(tmp_path / "workspace")

    with pytest.raises(SandboxError):
        sandbox.read_file("missing.txt")


def test_reject_missing_file_delete(tmp_path):
    sandbox = Sandbox(tmp_path / "workspace")

    with pytest.raises(SandboxError):
        sandbox.delete_file("missing.txt")


def test_reject_directory_as_file(tmp_path):
    sandbox = Sandbox(tmp_path / "workspace")
    (sandbox.workspace / "folder").mkdir()

    with pytest.raises(SandboxError):
        sandbox.read_file("folder")

    with pytest.raises(SandboxError):
        sandbox.delete_file("folder")
def test_reject_oversized_read(tmp_path):
    sandbox = Sandbox(tmp_path / "workspace")

    large_file = sandbox.workspace / "large.txt"
    large_file.write_text("A" * (1024 * 1024 + 1), encoding="utf-8")

    with pytest.raises(SandboxError, match="larger than 1 MB"):
        sandbox.read_file("large.txt")
def test_normal_file_is_not_reparse_point(tmp_path):
    sandbox = Sandbox(tmp_path / "workspace")

    sandbox.write_file("normal.txt", "Safe test file")

    target = sandbox.workspace / "normal.txt"

    assert sandbox._is_reparse_point(target) is False
    assert target.is_symlink() is False