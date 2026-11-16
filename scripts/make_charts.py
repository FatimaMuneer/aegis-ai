"""Draw the comparison charts for the report / presentation.

    python scripts/make_charts.py                 uses results/guard_eval_dev.csv
    python scripts/make_charts.py --split all

Needs:  pip install matplotlib
Saves PNG files into results/charts/
"""
import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

STOP = {"BLOCK", "REVIEW"}
DOMAINS = ["sql", "shell", "soc"]
NAMES = {"sql": "Database (SQL)", "shell": "DevOps (shell)", "soc": "SOC"}


def rates(rows):
    """Per domain: attacks caught % and safe actions wrongly stopped %, for AEGIS and the baseline."""
    out = {}
    for domain in DOMAINS + ["ALL"]:
        subset = [r for r in rows if domain == "ALL" or r["domain"] == domain]
        attacks = [r for r in subset if r["label"] == "attack"]
        safe = [r for r in subset if r["label"] == "safe"]
        pct = lambda a, b: 100 * a / b if b else 0
        out[domain] = {
            "caught_aegis": pct(sum(r["aegis"] in STOP for r in attacks), len(attacks)),
            "caught_base": pct(sum(r["baseline"] == "BLOCK" for r in attacks), len(attacks)),
            "false_aegis": pct(sum(r["aegis"] in STOP for r in safe), len(safe)),
            "false_base": pct(sum(r["baseline"] == "BLOCK" for r in safe), len(safe)),
        }
    return out


def bar_chart(plt, data, key_a, key_b, title, ylabel, path):
    labels = [NAMES.get(d, "All domains") for d in DOMAINS + ["ALL"]]
    xs = range(len(labels))
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar([x - 0.2 for x in xs], [data[d][key_a] for d in DOMAINS + ["ALL"]], 0.4, label="AEGIS", color="#2563eb")
    ax.bar([x + 0.2 for x in xs], [data[d][key_b] for d in DOMAINS + ["ALL"]], 0.4, label="Keyword baseline", color="#94a3b8")
    ax.set_xticks(list(xs)); ax.set_xticklabels(labels)
    ax.set_ylim(0, 118); ax.set_ylabel(ylabel); ax.set_title(title); ax.legend(loc="upper center", ncol=2)
    for container in ax.containers:
        ax.bar_label(container, fmt="%.0f%%", fontsize=8)
    fig.tight_layout(); fig.savefig(path, dpi=160); plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="dev")
    args = ap.parse_args()

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("Install matplotlib first:  pip install matplotlib")
        return 1

    src = ROOT / "results" / f"guard_eval_{args.split}.csv"
    if not src.exists():
        print(f"{src.relative_to(ROOT)} not found. Run:  python scripts/eval_guard.py --split {args.split}")
        return 1
    with open(src, encoding="utf-8") as f:
        data = rates(list(csv.DictReader(f)))

    out = ROOT / "results" / "charts"
    out.mkdir(parents=True, exist_ok=True)
    bar_chart(plt, data, "caught_aegis", "caught_base", "Attacks stopped (higher is better)", "% of attacks stopped",
              out / "attacks_caught.png")
    bar_chart(plt, data, "false_aegis", "false_base", "Safe actions wrongly stopped (lower is better)",
              "% of safe actions stopped", out / "false_alarms.png")
    print("Saved charts in", out.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
