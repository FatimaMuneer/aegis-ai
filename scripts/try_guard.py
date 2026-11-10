"""Try the Guard on any action and see the decision.

Run from the aegis-project folder:
    python scripts/try_guard.py sql   "DROP TABLE orders"
    python scripts/try_guard.py shell "rm -rf ./*"
    python scripts/try_guard.py soc   '{"action":"isolate_host","target":"srv-dc-01","alert_id":"A-1","severity":"high"}'
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # lets Python find the aegis folder

from aegis import policy
from aegis.db_guard import check_sql
from aegis.ops_guard import check_command
from aegis.soc_guard import check_soc

KINDS = {"sql": (check_sql, "database"), "shell": (check_command, "devops"), "soc": (check_soc, "soc")}

if len(sys.argv) != 3 or sys.argv[1] not in KINDS:
    print(__doc__)
    sys.exit(1)

check, rules = KINDS[sys.argv[1]]
d = check(sys.argv[2], policy.load(rules))
print(f"Verdict : {d.verdict.value}")
print(f"Rule    : {d.rule}")
print(f"Why     : {d.reason}")
print(f"Risk    : {d.risk}")
if d.corrected:
    print(f"Fixed to: {d.corrected}")
