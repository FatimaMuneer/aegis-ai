"""export.py - exports the audit log to CSV or JSON for the evaluation.

  python -m aegis.export --format csv  --out results.csv
  python -m aegis.export --format json --out results.json

The JSON file also says whether the log's fingerprint chain is still intact.
"""
import argparse
import csv
import json

from .audit import AuditLog

COLUMNS = ["seq", "ts", "agent", "kind", "verdict", "rule", "risk",
           "reason", "original", "corrected", "flags", "tokens", "cost"]


def export_csv(audit: AuditLog, out_path: str) -> str:
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for entry in audit.read_all():
            row = dict(entry)
            row["flags"] = ",".join(entry.get("flags") or [])
            writer.writerow(row)
    return out_path


def export_json(audit: AuditLog, out_path: str) -> str:
    ok, message = audit.verify()
    data = {"log_intact": ok, "integrity_message": message, "entries": audit.read_all()}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return out_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="aegis.export")
    parser.add_argument("--audit", default="aegis_audit.jsonl")
    parser.add_argument("--format", choices=["csv", "json"], default="csv")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    out = args.out or f"aegis_results.{args.format}"
    log = AuditLog(args.audit)
    print("Wrote", export_csv(log, out) if args.format == "csv" else export_json(log, out))
