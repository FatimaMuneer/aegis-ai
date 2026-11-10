"""learn.py - suggests rules from repeated approvals.

Idea: if a human keeps approving the same kind of action, AEGIS can suggest
"stop asking me about this". It only SUGGESTS. A person must run add_rule()
before anything changes, and the engine never lets a learned rule override a
hard BLOCK.

  record_approval(audit, action)   -> call this when a human clicks "approve"
  suggest_rules(audit)             -> patterns approved 3+ times
  add_rule(pattern, reason)        -> saves it to policies/learned.yaml

CLI:
  python -m aegis.learn suggest
  python -m aegis.learn add --pattern "..." --reason "..."
"""
import argparse
import re
from collections import Counter
from pathlib import Path

import yaml

LEARNED_FILE = Path(__file__).parent / "policies" / "learned.yaml"


def normalize(text: str) -> str:
    """'DELETE FROM logs WHERE id = 42' and '... id = 77' become the same shape."""
    text = re.sub(r"'[^']*'|\"[^\"]*\"", "<S>", text)
    text = re.sub(r"\b\d+\b", "<N>", text)
    return " ".join(text.lower().split())


def to_regex(normalized: str) -> str:
    parts = re.split(r"(<n>|<s>)", normalized)
    out = []
    for p in parts:
        if p == "<n>":
            out.append(r"\d+")
        elif p == "<s>":
            out.append(r"(?:'[^']*'|\"[^\"]*\")")
        else:
            out.append(r"\s+".join(re.escape(w) for w in p.split(" ")))
    return "(?i)^" + "".join(out) + "$"


def record_approval(audit, action: str, agent: str = "default", kind: str = "other"):
    return audit.append({"verdict": "HUMAN_APPROVED", "agent": agent, "kind": kind,
                         "original": action, "rule": "HUMAN", "reason": "approved by a person"})


def load_rules(path=LEARNED_FILE) -> list:
    path = Path(path)
    if not path.exists():
        return []
    return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("rules") or []


def matches(rules: list, action: str):
    """Return the first learned rule that matches the action, or None."""
    for rule in rules:
        if re.search(rule["pattern"], action.strip()):
            return rule
    return None


def suggest_rules(audit, min_count=3, path=LEARNED_FILE) -> list:
    known = {r["pattern"] for r in load_rules(path)}
    counts, examples = Counter(), {}
    for entry in audit.read_all():
        if entry.get("verdict") == "HUMAN_APPROVED":
            key = normalize(entry["original"])
            counts[key] += 1
            examples.setdefault(key, entry["original"])
    return [{"pattern": to_regex(k), "approved_times": n, "example": examples[k]}
            for k, n in counts.most_common()
            if n >= min_count and to_regex(k) not in known]


def add_rule(pattern: str, reason: str, path=LEARNED_FILE) -> dict:
    re.compile(pattern)  # stop early if the regex is broken
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else None) or {}
    rules = data.get("rules") or []
    rule = {"id": f"LRN-{len(rules) + 1:03d}", "pattern": pattern, "reason": reason}
    data["rules"] = rules + [rule]
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return rule


if __name__ == "__main__":
    from .audit import AuditLog

    parser = argparse.ArgumentParser(prog="aegis.learn")
    sub = parser.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("suggest")
    s.add_argument("--audit", default="aegis_audit.jsonl")
    a = sub.add_parser("add")
    a.add_argument("--pattern", required=True)
    a.add_argument("--reason", required=True)
    args = parser.parse_args()

    if args.cmd == "suggest":
        found = suggest_rules(AuditLog(args.audit))
        if not found:
            print("No repeated approvals yet.")
        for item in found:
            print(f"Approved {item['approved_times']}x, e.g. {item['example']}")
            print(f"  pattern: {item['pattern']}")
    else:
        print("Saved:", add_rule(args.pattern, args.reason))
