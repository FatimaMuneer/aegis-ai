"""Shared test setup. Every test gets its own empty audit log, so tests never affect each other."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # lets tests import the aegis folder

from aegis.audit import AuditLog
from aegis.engine import Engine


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path / "audit.jsonl")


@pytest.fixture
def engine(tmp_path):
    # learned_path points at a file that does not exist, so the real learned.yaml is never used
    return Engine(audit_path=tmp_path / "audit.jsonl", learned_path=tmp_path / "learned.yaml")
