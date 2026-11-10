"""dryrun.py - the "this would change N rows" preview.

The SQL runs on an in-memory COPY of the SQLite database and is rolled back,
so the real database is never touched.
"""
import sqlite3
from pathlib import Path


def dry_run_sql(sql: str, db_path) -> dict:
    if not db_path or not Path(db_path).exists():
        return {"ok": False, "rows_affected": None,
                "message": "No database available for a preview."}

    # copy the real database into memory (read-only access to the original)
    source = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    copy = sqlite3.connect(":memory:")
    source.backup(copy)
    source.close()

    copy.isolation_level = None  # we control the transaction ourselves
    rows = 0
    try:
        copy.execute("BEGIN")
        for statement in sql.split(";"):
            if statement.strip():
                cursor = copy.execute(statement)
                if cursor.rowcount and cursor.rowcount > 0:
                    rows += cursor.rowcount
        return {"ok": True, "rows_affected": rows,
                "message": f"This would change {rows} row(s)."}
    except sqlite3.Error as error:
        return {"ok": False, "rows_affected": None,
                "message": f"Preview failed: {error}"}
    finally:
        try:
            copy.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        copy.close()
