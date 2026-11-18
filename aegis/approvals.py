"""One-time, time-limited human approval grants.

Approval records are separate from the audit log and learning system.
This module grants permission only; it never executes actions.
"""

import hashlib
from contextlib import closing
import json
import sqlite3
import time
import uuid
from pathlib import Path


class ApprovalError(Exception):
    """Raised when an approval cannot be created or consumed."""


def _fingerprint(review_seq, action, kind, agent):
    payload = {
        "review_seq": review_seq,
        "action": action,
        "kind": kind,
        "agent": agent,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ApprovalStore:
    def __init__(self, path="aegis_approvals.sqlite3", ttl_seconds=900):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds

        with closing(self._connect()) as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS approvals (
                    review_seq INTEGER PRIMARY KEY,
                    approval_id TEXT UNIQUE NOT NULL,
                    action TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )
            """)

    def _connect(self):
        connection = sqlite3.connect(
            str(self.path),
            timeout=10,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _as_dict(row):
        return dict(row) if row is not None else None

    def approve(self, review_seq, action, kind, agent):
        """Create a time-limited grant for one exact REVIEW event."""
        if not isinstance(review_seq, int) or review_seq < 1:
            raise ApprovalError("Invalid review event ID.")

        now = time.time()
        approval_id = str(uuid.uuid4())
        fingerprint = _fingerprint(review_seq, action, kind, agent)

        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT status FROM approvals WHERE review_seq = ?",
                    (review_seq,),
                ).fetchone()

                if existing:
                    raise ApprovalError(
                        "This review event has already been resolved."
                    )

                connection.execute("""
                    INSERT INTO approvals (
                        review_seq, approval_id, action, kind, agent,
                        fingerprint, status, created_at, expires_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 'APPROVED', ?, ?)
                """, (
                    review_seq,
                    approval_id,
                    action,
                    kind,
                    agent,
                    fingerprint,
                    now,
                    now + self.ttl_seconds,
                ))

                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise

        return {
            "approval_id": approval_id,
            "review_seq": review_seq,
            "status": "APPROVED",
            "created_at": now,
            "expires_at": now + self.ttl_seconds,
        }

    def reject(self, review_seq, action, kind, agent):
        """Resolve a REVIEW event as rejected. No grant is created."""
        if not isinstance(review_seq, int) or review_seq < 1:
            raise ApprovalError("Invalid review event ID.")

        now = time.time()

        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT status FROM approvals WHERE review_seq = ?",
                    (review_seq,),
                ).fetchone()

                if existing:
                    raise ApprovalError(
                        "This review event has already been resolved."
                    )

                connection.execute("""
                    INSERT INTO approvals (
                        review_seq, approval_id, action, kind, agent,
                        fingerprint, status, created_at, expires_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 'REJECTED', ?, ?)
                """, (
                    review_seq,
                    str(uuid.uuid4()),
                    action,
                    kind,
                    agent,
                    _fingerprint(review_seq, action, kind, agent),
                    now,
                    now,
                ))

                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise

        return {"review_seq": review_seq, "status": "REJECTED"}

    def get_for_review(self, review_seq):
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE review_seq = ?",
                (review_seq,),
            ).fetchone()
        return self._as_dict(row)

    def get_by_approval(self, approval_id):
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        return self._as_dict(row)

    def list_recent(self, limit=100):
        limit = max(1, min(int(limit), 500))
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT review_seq, approval_id, status, kind, agent,
                       created_at, expires_at
                FROM approvals
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def rollback_resolution(self, review_seq, approval_id=None):
        """Remove a resolution if its audit event could not be recorded."""
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if approval_id:
                    connection.execute(
                        """
                        DELETE FROM approvals
                        WHERE review_seq = ? AND approval_id = ?
                        """,
                        (review_seq, approval_id),
                    )
                else:
                    connection.execute(
                        "DELETE FROM approvals WHERE review_seq = ?",
                        (review_seq,),
                    )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def consume(self, approval_id, action, kind, agent):
        """Atomically consume a matching, unexpired approval exactly once.

        This method does not execute the approved action.
        The caller must independently re-evaluate the action before any
        future execution layer is allowed to proceed.
        """
        now = time.time()

        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM approvals WHERE approval_id = ?",
                    (approval_id,),
                ).fetchone()

                if row is None:
                    raise ApprovalError("Approval not found.")

                expected = _fingerprint(
                    row["review_seq"], action, kind, agent
                )

                if expected != row["fingerprint"]:
                    raise ApprovalError(
                        "Action does not match the approved request."
                    )

                if row["status"] != "APPROVED":
                    raise ApprovalError(
                        "Approval is not available for use."
                    )

                if row["expires_at"] <= now:
                    connection.execute("""
                        UPDATE approvals
                        SET status = 'EXPIRED'
                        WHERE approval_id = ? AND status = 'APPROVED'
                    """, (approval_id,))
                    connection.execute("COMMIT")
                    raise ApprovalError("Approval has expired.")

                updated = connection.execute("""
                    UPDATE approvals
                    SET status = 'CONSUMED'
                    WHERE approval_id = ?
                      AND status = 'APPROVED'
                      AND expires_at > ?
                """, (approval_id, now))

                if updated.rowcount != 1:
                    raise ApprovalError(
                        "Approval has already been used or expired."
                    )

                connection.execute("COMMIT")
                return {
                    "approval_id": approval_id,
                    "review_seq": row["review_seq"],
                    "status": "CONSUMED",
                }

            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
