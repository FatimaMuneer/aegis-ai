"""Database checker. Uses sqlglot to really parse SQL (no fragile text matching)."""
import sqlglot
from sqlglot import exp

from .models import Decision, Verdict

DDL = {"Drop", "TruncateTable", "Alter", "AlterTable", "Command", "Create",
       "Grant", "Revoke", "Attach", "Detach", "Pragma"}


def _d(v, rule, reason, original, corrected=None, risk="LOW"):
    return Decision(v, rule, reason, original, corrected, risk)


def check_sql(sql: str, policy: dict, _recheck: bool = False) -> Decision:
    original = sql.strip()
    try:
        statements = [s for s in sqlglot.parse(original) if s is not None]
    except Exception:
        return _d(Verdict.REVIEW, "DB-00", "Could not understand this SQL, so a human must look.", original, risk="MEDIUM")

    if not statements:
        return _d(Verdict.REVIEW, "DB-00", "Empty query.", original)
    if len(statements) > 1:
        return _d(Verdict.BLOCK, "DB-02", "Several statements in one request (a classic trick).", original, risk="HIGH")

    stmt = statements[0]

    blocked_tables = {t.lower() for t in policy.get("blocked_tables", [])}
    blocked_cols = {c.lower() for c in policy.get("blocked_columns", [])}
    for t in stmt.find_all(exp.Table):
        if t.name.lower() in blocked_tables:
            return _d(Verdict.BLOCK, "DB-05", f"Table '{t.name}' is private.", original, risk="HIGH")
    for c in stmt.find_all(exp.Column):
        if c.name.lower() in blocked_cols:
            return _d(Verdict.BLOCK, "DB-05", f"Column '{c.name}' is private.", original, risk="HIGH")

    kind = type(stmt).__name__
    if kind in DDL:
        return _d(Verdict.BLOCK, "DB-03", f"{kind.upper()} changes the database structure. Never allowed.", original, risk="HIGH")

    if isinstance(stmt, (exp.Delete, exp.Update)):
        verb = "DELETE" if isinstance(stmt, exp.Delete) else "UPDATE"
        if stmt.args.get("where") is None:
            return _d(Verdict.BLOCK, "DB-03", f"{verb} without WHERE would hit every row.", original, risk="HIGH")
        return _d(Verdict.REVIEW, "DB-04", f"{verb} changes data, so a human must approve.", original, risk="MEDIUM")
    if isinstance(stmt, exp.Insert):
        return _d(Verdict.REVIEW, "DB-01", "INSERT changes data, so a human must approve.", original, risk="MEDIUM")

    if isinstance(stmt, (exp.Select, exp.Union)):
        if stmt.args.get("into") is not None:
            return _d(Verdict.BLOCK, "DB-03", "SELECT ... INTO creates a table.", original, risk="HIGH")
        default = int(policy.get("default_limit", 100))
        maximum = int(policy.get("max_limit", 1000))
        limit = stmt.args.get("limit")
        too_big = False
        if limit is not None:
            try:
                too_big = int(limit.expression.name) > maximum
            except (ValueError, AttributeError):
                too_big = False
        if limit is None or too_big:
            fixed = stmt.limit(default, copy=True).sql()
            if _recheck:
                return _d(Verdict.REVIEW, "DB-07", "Could not fix the query safely.", original)
            again = check_sql(fixed, policy, _recheck=True)   # verified correction
            if again.verdict != Verdict.ALLOW:
                return _d(Verdict.REVIEW, "DB-07", "The fixed query failed its re-check.", original)
            why = "No row limit." if limit is None else f"Limit above {maximum}."
            return _d(Verdict.CORRECT, "DB-07", f"{why} Rewritten with LIMIT {default}.", original, fixed, risk="LOW")
        return _d(Verdict.ALLOW, "DB-00", "Read-only query within limits.", original)

    return _d(Verdict.REVIEW, "DB-00", f"Unknown statement type '{kind}', so a human must look.", original, risk="MEDIUM")
