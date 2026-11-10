"""Score the Guard on the labelled test cases (the engine is not needed).

    python scripts/eval_guard.py                   development cases (default)
    python scripts/eval_guard.py --split holdout   the FINAL test. Run it once, at the very end.
    python scripts/eval_guard.py --split all

What the numbers mean:
  caught     an attack that AEGIS stopped (verdict BLOCK or REVIEW)
  false      a safe action that AEGIS stopped by mistake
  exact      AEGIS gave exactly the answer written in the 'expected' column
  fixed ok   a CORRECT answer whose fixed action passes the same Guard again
"""
import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))                      # lets Python find the aegis folder

from aegis import policy
from aegis.baseline import baseline_check
from aegis.db_guard import check_sql
from aegis.ops_guard import check_command
from aegis.soc_guard import check_soc

GUARDS = {"sql": (check_sql, "database"), "shell": (check_command, "devops"), "soc": (check_soc, "soc")}
STOP = {"BLOCK", "REVIEW"}          # answers that stop an action from running on its own


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "n/a"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="dev", choices=["dev", "holdout", "all"])
    args = ap.parse_args()
    if args.split != "dev":
        print("NOTE: the holdout set is for the final test. Do not change any rule because of what it shows.\n")

    with open(ROOT / "data" / "test_cases.csv", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if args.split == "all" or r["split"] == args.split]

    tally, results = {}, []
    for r in rows:
        fn, rules = GUARDS[r["domain"]]
        pol = policy.load(rules)
        d = fn(r["action"], pol)
        v, b = d.verdict.value, baseline_check(r["domain"], r["action"])
        fixed_ok = (fn(d.corrected, pol).verdict.value == "ALLOW") if v == "CORRECT" else None
        results.append(dict(id=r["id"], domain=r["domain"], label=r["label"], expected=r["expected"],
                            aegis=v, rule=d.rule, baseline=b, action=r["action"]))
        for key in (r["domain"], "ALL"):
            t = tally.setdefault(key, dict(n=0, att=0, caught=0, b_caught=0, safe=0, false=0, b_false=0, exact=0, corr=0, corr_ok=0))
            t["n"] += 1
            t["exact"] += v == r["expected"]
            if r["label"] == "attack":
                t["att"] += 1; t["caught"] += v in STOP; t["b_caught"] += b == "BLOCK"
            if r["label"] == "safe":
                t["safe"] += 1; t["false"] += v in STOP; t["b_false"] += b == "BLOCK"
            if fixed_ok is not None:
                t["corr"] += 1; t["corr_ok"] += fixed_ok

    print(f"Split: {args.split}   Cases: {len(rows)}\n")
    print(f"{'':6}{'cases':>6} | {'attacks caught':^23} | {'safe stopped (false)':^23} | {'exact':>6} | {'fixed ok':>9}")
    print(f"{'':6}{'':>6} | {'AEGIS':>10} {'baseline':>12} | {'AEGIS':>10} {'baseline':>12} | {'':>6} |")
    for key in ("sql", "shell", "soc", "ALL"):
        t = tally.get(key)
        if not t:
            continue
        print(f"{key:6}{t['n']:>6} | {pct(t['caught'], t['att']):>5} {t['caught']:>2}/{t['att']:<2} {pct(t['b_caught'], t['att']):>6} {t['b_caught']:>2}/{t['att']:<2}"
              f" | {pct(t['false'], t['safe']):>5} {t['false']:>2}/{t['safe']:<2} {pct(t['b_false'], t['safe']):>6} {t['b_false']:>2}/{t['safe']:<2}"
              f" | {pct(t['exact'], t['n']):>6} | {pct(t['corr_ok'], t['corr']):>9}")

    misses = [x for x in results if x["label"] == "attack" and x["aegis"] not in STOP]
    false_alarms = [x for x in results if x["label"] == "safe" and x["aegis"] in STOP]
    print(f"\nMISSED ATTACKS ({len(misses)}): attacks that AEGIS let through")
    for x in misses:
        print(f"  {x['id']}  {x['aegis']:8} {x['action'][:90]}")
    print(f"\nFALSE ALARMS ({len(false_alarms)}): safe actions that AEGIS stopped")
    for x in false_alarms:
        print(f"  {x['id']}  {x['aegis']:8} ({x['rule']}) {x['action'][:80]}")

    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    path = out / f"guard_eval_{args.split}.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader(); w.writerows(results)
    print(f"\nFull results saved to {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()