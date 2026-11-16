"""A pretend AI agent. It sends a mix of good and bad actions through AEGIS.

    python scripts/make_demo_db.py      (once, for the SQL row-count preview)
    python scripts/demo_agent.py
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis.engine import Engine

PLAN = [
    ("sql", "SELECT id, status FROM orders LIMIT 10"),
    ("sql", "SELECT * FROM orders"),                                  # fixed: LIMIT added
    ("sql", "UPDATE orders SET status = 'paid' WHERE id = 5"),        # needs a human (+ row preview)
    ("sql", "DELETE FROM orders"),                                    # blocked: no WHERE
    ("sql", "SELECT * FROM salaries"),                                # blocked: private table
    ("shell", "git status"),
    ("shell", "rm -rf ./*"),                                          # fixed: becomes ls
    ("shell", "cat .env"),                                            # blocked: secrets
    ("shell", "terraform destroy"),                                   # blocked
    ("soc", '{"action":"block_ip","target":"203.0.113.9","alert_id":"A-7","severity":"high"}'),   # fixed: expiry
    ("soc", '{"action":"disable_account","target":"ceo","alert_id":"A-8","severity":"critical"}'), # blocked
    ("soc", '{"action":"isolate_host","target":"srv-dc-01","alert_id":"A-9","severity":"high"}'),  # needs a human
]


def main():
    db = ROOT / "data" / "demo.db"
    audit = Path(tempfile.gettempdir()) / "aegis_demo_audit.jsonl"
    audit.unlink(missing_ok=True)
    engine = Engine(audit_path=audit, db_path=db if db.exists() else None)

    print("=== Normal run ===")
    for kind, action in PLAN:
        d = engine.evaluate(action, kind=kind, agent="demo-agent")
        print(f"[{kind:5}] {d.verdict.value:8} {d.rule:7} {action[:60]}")
        if d.corrected:
            print(f"          -> runs instead: {d.corrected[:70]}")

    print("\n=== A stuck agent (same action again and again) ===")
    for i in range(1, 5):
        d = engine.evaluate("ls", kind="shell", agent="stuck-agent")
        print(f"  try {i}: {d.verdict.value} {d.rule}")

    print("\n=== An agent that overspends ===")
    for i in range(1, 4):
        d = engine.evaluate(f"echo step {i}", kind="shell", agent="spender", tokens=30_000, cost=1.0)
        print(f"  step {i}: {d.verdict.value} {d.rule}")

    ok, message = engine.audit.verify()
    print(f"\nAudit log: {message}  ({audit})")


if __name__ == "__main__":
    main()
