"""Tamper-evident JSONL audit log with cross-process append locking."""

import errno
import hashlib
import json
import os
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64

# Also serialize threads that share this Python process.
_THREAD_LOCK = threading.RLock()


def _fingerprint(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    text = json.dumps(body, sort_keys=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path="aegis_audit.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self.lock_path = Path(str(self.path) + ".lock")

    @contextmanager
    def _locked(self):
        """Lock this audit file across threads and separate processes."""
        with _THREAD_LOCK:
            with self.lock_path.open("a+b") as lock_file:
                if os.name == "nt":
                    import msvcrt

                    lock_file.seek(0, os.SEEK_END)
                    if lock_file.tell() == 0:
                        lock_file.write(b"\0")
                        lock_file.flush()

                    while True:
                        try:
                            lock_file.seek(0)
                            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                            break
                        except OSError as exc:
                            if exc.errno not in (
                                errno.EACCES,
                                errno.EDEADLK,
                                errno.EAGAIN,
                                13,
                                36,
                            ):
                                raise
                            time.sleep(0.05)

                    try:
                        yield
                    finally:
                        lock_file.seek(0)
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                    try:
                        yield
                    finally:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _read_all_unlocked(self) -> list:
        entries = []
        with self.path.open(encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Malformed audit JSON at line {line_number}: {exc}"
                    ) from exc
        return entries

    def read_all(self) -> list:
        with self._locked():
            return self._read_all_unlocked()

    def append(self, record: dict) -> dict:
        # The entire read -> sequence -> hash -> write operation is locked.
        with self._locked():
            entries = self._read_all_unlocked()

            entry = dict(record)
            entry["seq"] = len(entries) + 1
            entry["ts"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            entry["prev_hash"] = entries[-1]["hash"] if entries else GENESIS
            entry["hash"] = _fingerprint(entry)

            line = json.dumps(entry, default=str) + "\n"
            with self.path.open("a", encoding="utf-8", newline="\n") as file:
                file.write(line)
                file.flush()
                os.fsync(file.fileno())

            return entry

    def verify(self):
        """Return (ok, message) after checking sequence and hash continuity."""
        entries = self.read_all()
        previous = GENESIS

        for index, entry in enumerate(entries, start=1):
            if entry.get("seq") != index or entry.get("prev_hash") != previous:
                return False, f"chain broken at entry {index} (line removed or reordered)"
            if entry.get("hash") != _fingerprint(entry):
                return False, f"entry {index} was modified"
            previous = entry["hash"]

        return True, "log is intact"
