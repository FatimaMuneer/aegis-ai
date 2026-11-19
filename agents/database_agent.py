"""Database agent: bounded SELECTs against its own disposable SQLite DB."""
import sqlite3
from pathlib import Path
import sqlglot
from sqlglot import exp
from agents.common import DATA, evaluate, record_simulation, run_loop

AGENT = "database-agent"
DB = DATA / "database_demo.sqlite3"

QUERIES = [
    "SELECT id, name, plan FROM demo_customers",
    "SELECT id, customer_id, total FROM demo_orders",
]


def initialize():
    with sqlite3.connect(DB) as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS demo_customers (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            plan TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS demo_orders (
            id INTEGER PRIMARY KEY,
            customer_id INTEGER NOT NULL,
            total REAL NOT NULL
        );
        """)
        if con.execute("SELECT COUNT(*) FROM demo_customers").fetchone()[0] == 0:
            con.executemany(
                "INSERT INTO demo_customers(name, plan) VALUES (?, ?)",
                [("Demo Alice", "Basic"), ("Demo Bilal", "Pro"),
                 ("Demo Sara", "Enterprise")]
            )
            con.executemany(
                "INSERT INTO demo_orders(customer_id, total) VALUES (?, ?)",
                [(1, 25.50), (2, 80.00), (3, 120.00)]
            )


def safe_local_select(sql):
    """Allow only one SELECT over the two hardcoded demo tables."""
    statements = [s for s in sqlglot.parse(sql) if s is not None]
    if len(statements) != 1 or not isinstance(statements[0], exp.Select):
        raise ValueError("Only one SELECT statement is permitted.")
    tables = {t.name.lower() for t in statements[0].find_all(exp.Table)}
    if not tables or not tables.issubset({"demo_customers", "demo_orders"}):
        raise ValueError("Query references a table outside the demo database.")
    if statements[0].find(exp.Subquery) or statements[0].find(exp.Func):
        raise ValueError("Complex SQL is not supported by this demo executor.")
    return sql


def cycle(count):
    query = QUERIES[(count - 1) % len(QUERIES)]
    decision = evaluate(AGENT, query, "sql")
    verdict = decision.get("verdict")

    if verdict in ("ALLOW", "CORRECT"):
        candidate = decision.get("corrected") if verdict == "CORRECT" else query
        if not candidate:
            raise RuntimeError("No corrected query supplied.")
        candidate = safe_local_select(candidate)
        with sqlite3.connect(DB) as con:
            rows = con.execute(candidate).fetchmany(20)
        record_simulation(
            AGENT,
            f"Executed approved read-only query on demo SQLite; {len(rows)} row(s) returned."
        )
        print(f"[{AGENT}] {verdict}: {len(rows)} demo row(s) returned.", flush=True)
    else:
        print(f"[{AGENT}] {verdict}: query not executed.", flush=True)


def main():
    initialize()
    run_loop(AGENT, cycle)


if __name__ == "__main__":
    main()
