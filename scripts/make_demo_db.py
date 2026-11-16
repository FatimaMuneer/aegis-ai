"""Create a small fake SQLite database for demos and for SQL dry-run previews.

    python scripts/make_demo_db.py            -> creates data/demo.db
"""
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "demo.db"

SCHEMA = """
CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT);
CREATE TABLE orders    (id INTEGER PRIMARY KEY, customer_id INTEGER, status TEXT, total REAL);
CREATE TABLE users     (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
CREATE TABLE salaries  (id INTEGER PRIMARY KEY, employee TEXT, salary REAL);
"""


def main():
    DB.parent.mkdir(exist_ok=True)
    if DB.exists():
        DB.unlink()
    con = sqlite3.connect(DB)
    con.executescript(SCHEMA)
    con.executemany("INSERT INTO customers VALUES (?,?,?)",
                    [(i, f"Customer {i}", f"customer{i}@example.com") for i in range(1, 51)])
    statuses = ["new", "paid", "shipped", "cancelled"]
    con.executemany("INSERT INTO orders VALUES (?,?,?,?)",
                    [(i, (i % 50) + 1, statuses[i % 4], round(20 + (i * 7) % 300, 2)) for i in range(1, 201)])
    con.executemany("INSERT INTO users VALUES (?,?,?)",
                    [(i, f"user{i}", "not-a-real-hash") for i in range(1, 11)])
    con.executemany("INSERT INTO salaries VALUES (?,?,?)",
                    [(i, f"Employee {i}", 50000 + i * 1000) for i in range(1, 11)])
    con.commit()
    con.close()
    print(f"Created {DB.relative_to(ROOT)} (50 customers, 200 orders, 10 users, 10 salaries)")


if __name__ == "__main__":
    sys.exit(main())
