"""cli.py - the command line for AEGIS.

    python -m aegis.cli check sql   "SELECT * FROM orders"
    python -m aegis.cli check shell "rm -rf ./*"
    python -m aegis.cli check soc   '{"action":"block_ip","target":"203.0.113.9","alert_id":"A-1","severity":"high"}'
    python -m aegis.cli audit --last 10
    python -m aegis.cli verify
    python -m aegis.cli export --format csv --out results.csv
    python -m aegis.cli suggest                 # rules AEGIS suggests from repeated approvals
    python -m aegis.cli chat
    python -m aegis.cli serve --port 8000
    python -m aegis.cli proxy -- <command that starts an MCP server>
"""
import argparse
import json
import sys

from .audit import AuditLog
from .engine import Engine


def cmd_check(args) -> int:
    engine = Engine(audit_path=args.audit, db_path=args.db)
    decision = engine.evaluate(args.action, kind=args.kind, agent=args.agent)
    if args.json:
        print(json.dumps(decision.to_dict(), indent=2))
    else:
        print(f"Verdict : {decision.verdict.value}")
        print(f"Rule    : {decision.rule}")
        print(f"Why     : {decision.reason}")
        print(f"Risk    : {decision.risk}")
        if decision.corrected:
            print(f"Fixed to: {decision.corrected}")
    # exit code lets shell scripts react: 0 allowed/fixed, 1 needs a human, 2 blocked
    return {"ALLOW": 0, "CORRECT": 0, "REVIEW": 1, "BLOCK": 2}.get(decision.verdict.value, 1)


def cmd_audit(args) -> int:
    entries = AuditLog(args.audit).read_all()
    if args.verdict:
        entries = [e for e in entries if str(e.get("verdict", "")).upper() == args.verdict.upper()]
    for e in entries[-args.last:]:
        print(f"#{e['seq']:<4} {e['ts']}  {e.get('verdict', '?'):<14} {e.get('rule', ''):<7} "
              f"{e.get('kind', ''):<6} {str(e.get('original', ''))[:60]}")
    if not entries:
        print("The log is empty.")
    return 0


def cmd_verify(args) -> int:
    ok, message = AuditLog(args.audit).verify()
    print(("OK: " if ok else "TAMPERED: ") + message)
    return 0 if ok else 1


def cmd_export(args) -> int:
    from . import export
    log = AuditLog(args.audit)
    out = args.out or f"aegis_results.{args.format}"
    print("Wrote", export.export_csv(log, out) if args.format == "csv" else export.export_json(log, out))
    return 0


def cmd_suggest(args) -> int:
    from . import learn
    found = learn.suggest_rules(AuditLog(args.audit))
    if not found:
        print("No repeated approvals yet.")
    for item in found:
        print(f"Approved {item['approved_times']}x, e.g. {item['example']}")
        print(f"  pattern: {item['pattern']}")
    return 0


def cmd_chat(args) -> int:
    from .chat import run_chat
    run_chat(Engine(audit_path=args.audit, db_path=args.db))
    return 0


def cmd_serve(args) -> int:
    try:
        import uvicorn
    except ImportError:
        print("Install the server first:  pip install -r requirements.txt")
        return 1
    uvicorn.run("aegis.api:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def cmd_proxy(args) -> int:
    from .mcp_proxy import run_proxy
    command = [c for c in args.command if c != "--"]
    if not command:
        print("Give the MCP server command after '--', e.g.  aegis.cli proxy -- npx some-mcp-server")
        return 1
    return run_proxy(command, Engine(audit_path=args.audit, db_path=args.db), agent=args.agent)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis", description="AEGIS: the accountability layer for AI agents.")
    p.add_argument("--audit", default="aegis_audit.jsonl", help="audit log file")
    p.add_argument("--db", default=None, help="SQLite file used for SQL dry-run previews")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="check one action")
    c.add_argument("kind", choices=["sql", "shell", "soc"])
    c.add_argument("action")
    c.add_argument("--agent", default="cli")
    c.add_argument("--json", action="store_true", help="print the decision as JSON")
    c.set_defaults(func=cmd_check)

    a = sub.add_parser("audit", help="show the latest log entries")
    a.add_argument("--last", type=int, default=20)
    a.add_argument("--verdict", default=None)
    a.set_defaults(func=cmd_audit)

    sub.add_parser("verify", help="check the log was not tampered with").set_defaults(func=cmd_verify)

    e = sub.add_parser("export", help="export the log to CSV or JSON")
    e.add_argument("--format", choices=["csv", "json"], default="csv")
    e.add_argument("--out", default=None)
    e.set_defaults(func=cmd_export)

    sub.add_parser("suggest", help="suggest rules from repeated approvals").set_defaults(func=cmd_suggest)
    sub.add_parser("chat", help="talk to AEGIS in plain language").set_defaults(func=cmd_chat)

    s = sub.add_parser("serve", help="start the API and dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--reload", action="store_true")
    s.set_defaults(func=cmd_serve)

    x = sub.add_parser("proxy", help="put AEGIS in front of an MCP server")
    x.add_argument("--agent", default="mcp")
    x.add_argument("command", nargs=argparse.REMAINDER)
    x.set_defaults(func=cmd_proxy)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())