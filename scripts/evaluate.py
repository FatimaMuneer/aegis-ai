"""Score the WHOLE engine (behaviour + guards + risk + audit) on the labelled test cases.

scripts/eval_guard.py tests only the three guards. This script sends every case through
Engine.evaluate(), so risk rules and the audit log are included too.

    python scripts/evaluate.py                    development cases (default)
    python scripts/evaluate.py --split holdout    the FINAL test. Run it once, at the very end.
    python scripts/evaluate.py --split all
    python scripts/evaluate.py --domain shell     only sql, shell or soc cases

Writes results/engine_eval_<split>.csv and results/engine_audit_<split>.jsonl
"""
import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis.baseline import baseline_check
from aegis.engine import Engine, verdict_name

STOP = {"BLOCK", "REVIEW"}


def pct(a, b):
    return f"{100 * a / b:.0f}%" if b else "n/a"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="dev", choices=["dev", "holdout", "all"])
    ap.add_argument("--domain", default=None, choices=["sql", "shell", "soc"])
    args = ap.parse_args()

    with open(ROOT / "data" / "test_cases.csv", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if args.split == "all" or r["split"] == args.split]
    if args.domain:
        rows = [r for r in rows if r["domain"] == args.domain]

    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    audit_path = out / f"engine_audit_{args.split}.jsonl"
    audit_path.unlink(missing_ok=True)
    db = ROOT / "data" / "demo.db"
    engine = Engine(audit_path=audit_path, db_path=db if db.exists() else None)

    tally, results = {}, []
    for r in rows:
        d = engine.evaluate(r["action"], kind=r["domain"], agent=r["id"])      # one agent per case: no loop flags
        v, b = verdict_name(d), baseline_check(r["domain"], r["action"])
        results.append(dict(id=r["id"], domain=r["domain"], label=r["label"], expected=r["expected"],
                            aegis=v, rule=d.rule, risk=d.risk, baseline=b, action=r["action"]))
        for key in (r["domain"], "ALL"):
            t = tally.setdefault(key, dict(n=0, att=0, caught=0, b_caught=0, safe=0, false=0, b_false=0, exact=0))
            t["n"] += 1
            t["exact"] += v == r["expected"]
            if r["label"] == "attack":
                t["att"] += 1; t["caught"] += v in STOP; t["b_caught"] += b == "BLOCK"
            if r["label"] == "safe":
                t["safe"] += 1; t["false"] += v in STOP; t["b_false"] += b == "BLOCK"

    print(f"ENGINE evaluation   split: {args.split}   cases: {len(rows)}\n")
    print(f"{'':6}{'cases':>6} | {'attacks caught':^23} | {'safe stopped (false)':^23} | {'exact':>6}")
    print(f"{'':6}{'':>6} | {'AEGIS':>10} {'baseline':>12} | {'AEGIS':>10} {'baseline':>12} |")
    for key in ("sql", "shell", "soc", "ALL"):
        t = tally.get(key)
        if t:
            print(f"{key:6}{t['n']:>6} | {pct(t['caught'], t['att']):>5} {t['caught']:>2}/{t['att']:<2} {pct(t['b_caught'], t['att']):>6} {t['b_caught']:>2}/{t['att']:<2}"
                  f" | {pct(t['false'], t['safe']):>5} {t['false']:>2}/{t['safe']:<2} {pct(t['b_false'], t['safe']):>6} {t['b_false']:>2}/{t['safe']:<2}"
                  f" | {pct(t['exact'], t['n']):>6}")

    misses = [x for x in results if x["label"] == "attack" and x["aegis"] not in STOP]
    print(f"\nMISSED ATTACKS ({len(misses)})")
    for x in misses:
        print(f"  {x['id']}  {x['aegis']:8} {x['action'][:90]}")

    path = out / f"engine_eval_{args.split}.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader(); w.writerows(results)
    print(f"\nSaved {path.relative_to(ROOT)}.  Audit log: {engine.audit.verify()[1]}")


if __name__ == "__main__":
    main()
