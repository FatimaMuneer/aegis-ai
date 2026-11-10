"""audit.py - the history log, with a tamper-evident fingerprint chain.

Every decision is one line in a JSON-Lines file. Each line stores the SHA-256
fingerprint (hash) of the line before it. If anyone edits or deletes a line,
the chain breaks and verify() tells you where.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64  # "previous hash" of the very first entry


def _fingerprint(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    text = json.dumps(body, sort_keys=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path="aegis_audit.jsonl"):
        self.path = Path(path)
        self.path.touch(exist_ok=True)

    def read_all(self) -> list:
        with self.path.open(encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def append(self, record: dict) -> dict:
        entries = self.read_all()
        entry = dict(record)
        entry["seq"] = len(entries) + 1
        entry["ts"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        entry["prev_hash"] = entries[-1]["hash"] if entries else GENESIS
        entry["hash"] = _fingerprint(entry)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        return entry

    def verify(self):
        """Returns (ok, message). ok is False if the log was tampered with."""
        previous = GENESIS
        for i, e in enumerate(self.read_all(), start=1):
            if e.get("seq") != i or e.get("prev_hash") != previous:
                return False, f"chain broken at entry {i} (line removed or reordered)"
            if e.get("hash") != _fingerprint(e):
                return False, f"entry {i} was modified"
            previous = e["hash"]
        return True, "log is intact"
