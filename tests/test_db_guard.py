import pytest
from aegis import policy
from aegis.db_guard import check_sql

P = policy.load("database")

CASES = [
    ("SELECT id, status FROM orders LIMIT 10", "ALLOW"),
    ("SELECT * FROM orders", "CORRECT"),
    ("SELECT id FROM orders LIMIT 100000", "CORRECT"),
    ("SELECT a FROM x UNION SELECT b FROM y", "CORRECT"),
    ("SELECT 1; DROP TABLE orders", "BLOCK"),
    ("DROP TABLE orders", "BLOCK"),
    ("TRUNCATE TABLE orders", "BLOCK"),
    ("ALTER TABLE orders ADD COLUMN x INT", "BLOCK"),
    ("DELETE FROM orders", "BLOCK"),
    ("UPDATE orders SET status='x'", "BLOCK"),
    ("DELETE FROM orders WHERE id = 5", "REVIEW"),
    ("UPDATE orders SET status='x' WHERE id = 5", "REVIEW"),
    ("INSERT INTO orders (id) VALUES (1)", "REVIEW"),
    ("SELECT * FROM integration_tokens", "BLOCK"),
    ("SELECT * FROM SALARIES", "BLOCK"),
    ("SELECT password FROM users LIMIT 5", "BLOCK"),
    ("WITH t AS (SELECT * FROM salaries) SELECT * FROM t", "BLOCK"),
    ("SELECT * FROM orders o JOIN salaries s ON o.id = s.id", "BLOCK"),
    ("SELECT id INTO newtable FROM orders", "BLOCK"),
    ("this is not sql at all ;;;", "REVIEW"),
]


@pytest.mark.parametrize("sql,expected", CASES)
def test_sql(sql, expected):
    assert check_sql(sql, P).verdict.value == expected


@pytest.mark.parametrize("sql", [
    "SELECT * FROM orders LIMIT -1",
    "SELECT * FROM orders LIMIT ?",
    "SELECT * FROM orders LIMIT 10 + 5",
])
def test_unsafe_limit_is_replaced(sql):
    decision = check_sql(sql, P)
    assert decision.verdict.value == "CORRECT"
    assert decision.corrected.endswith("LIMIT 100")
    assert check_sql(decision.corrected, P).verdict.value == "ALLOW"


def test_correction_adds_limit():
    d = check_sql("SELECT * FROM orders", P)
    assert d.corrected.endswith("LIMIT 100")
    assert check_sql(d.corrected, P).verdict.value == "ALLOW"   # the fix passes its own check
