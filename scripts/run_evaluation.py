"""Run the whole evaluation in one go: guard scores, engine scores, charts.

    python scripts/run_evaluation.py                 development cases
    python scripts/run_evaluation.py --holdout       ALSO runs the final holdout test (do this once, at the end)
"""
import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(script, *args):
    print(f"\n>>> {script} {' '.join(args)}\n")
    return subprocess.run([sys.executable, str(HERE / script), *args]).returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--holdout", action="store_true", help="also run the holdout split")
    args = ap.parse_args()

    splits = ["dev"] + (["holdout"] if args.holdout else [])
    failed = 0
    run("make_demo_db.py")
    for split in splits:
        failed += run("eval_guard.py", "--split", split) != 0
        failed += run("evaluate.py", "--split", split) != 0
        failed += run("make_charts.py", "--split", split) != 0
    print("\nEvaluation finished." if not failed else f"\n{failed} step(s) failed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
