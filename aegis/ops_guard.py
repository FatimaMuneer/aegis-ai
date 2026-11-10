"""DevOps checker. Splits shell commands safely and applies rules."""
import re
import shlex

from .models import Decision, Verdict, SEVERITY


def _d(v, rule, reason, original, corrected=None, risk="LOW"):
    return Decision(v, rule, reason, original, corrected, risk)


def _starts_with(tokens, prefix: str) -> bool:
    p = prefix.split()
    return tokens[:len(p)] == p


def _preview_arg(t: str) -> str:
    return t if re.fullmatch(r"[\w./*?\-]+", t) else shlex.quote(t)


def _check_one(seg: str, policy: dict) -> Decision:
    try:
        tokens = shlex.split(seg)
    except ValueError:
        return _d(Verdict.REVIEW, "DO-11", "Could not read this command safely.", seg, risk="MEDIUM")
    if not tokens:
        return _d(Verdict.REVIEW, "DO-11", "Empty command.", seg)

    if tokens[0] == "sudo":
        inner = _check_one(shlex.join(tokens[1:]), policy) if len(tokens) > 1 else None
        if inner and inner.verdict == Verdict.BLOCK:
            return inner
        return _d(Verdict.REVIEW, "DO-09", "sudo (admin rights) needs a human.", seg, risk="HIGH")

    joined = " ".join(tokens).lower()
    prog = tokens[0].split("/")[-1]

    for b in policy.get("blocked_commands", []):
        if b.lower() in joined:
            return _d(Verdict.BLOCK, "DO-01", f"'{b}' is never allowed.", seg, risk="HIGH")

    for t in tokens[1:]:
        for pat in policy.get("secret_patterns", []):
            if re.search(pat, t.lstrip("<>").lower()):
                return _d(Verdict.BLOCK, "DO-03", "This touches secrets (keys, .env, credentials).", seg, risk="HIGH")

    allowed = policy.get("allowed_paths", [])
    for t in tokens[1:]:
        p = t.lstrip("<>")
        if p.startswith(("/", "~")) and not any(p.startswith(a) for a in allowed):
            return _d(Verdict.BLOCK, "DO-08", f"'{p}' is outside the project folder.", seg, risk="HIGH")
        if ".." in p.split("/"):
            return _d(Verdict.BLOCK, "DO-08", "Going up with '..' leaves the project folder.", seg, risk="HIGH")

    if prog == "rm":
        flags = [t for t in tokens[1:] if t.startswith("-")]
        targets = [t for t in tokens[1:] if not t.startswith("-")]
        if any(("*" in t or "?" in t) for t in targets):
            fixed = "ls " + " ".join(_preview_arg(t) for t in targets)
            return _d(Verdict.CORRECT, "DO-06", "Wildcard delete. Replaced by a safe preview (ls).", seg, fixed, risk="MEDIUM")
        recursive = any(f == "--recursive" or (not f.startswith("--") and "r" in f.lower()) for f in flags)
        what = "Recursive delete" if recursive else "Delete"
        return _d(Verdict.REVIEW, "DO-06", f"{what} needs a human.", seg, risk="MEDIUM")

    if any(t.startswith((">", "1>", "2>")) for t in tokens):
        return _d(Verdict.REVIEW, "DO-05", "Writing to a file needs a human.", seg, risk="MEDIUM")

    is_read = any(_starts_with(tokens, p) for p in policy.get("read_commands", []))
    if re.search(r"\bprod(uction)?\b", joined) and not is_read:
        return _d(Verdict.REVIEW, "DO-04", "Production change. A human must approve.", seg, risk="MEDIUM")
    if is_read:
        return _d(Verdict.ALLOW, "DO-00", "Read-only command.", seg)
    if any(_starts_with(tokens, p) for p in policy.get("change_commands", [])):
        return _d(Verdict.REVIEW, "DO-05", "This changes systems, so a human must approve.", seg, risk="MEDIUM")
    return _d(Verdict.REVIEW, "DO-11", "AEGIS does not recognise this command, so it fails closed.", seg, risk="MEDIUM")


def check_command(cmd: str, policy: dict) -> Decision:
    original = cmd.strip()
    if not original:
        return _d(Verdict.REVIEW, "DO-11", "Empty command.", original)
    if "$(" in original or "`" in original:
        return _d(Verdict.REVIEW, "DO-10", "Hidden command inside the command.", original, risk="HIGH")
    if re.search(r"\|\s*(sudo\s+)?(ba|z|da)?sh\b", original):
        return _d(Verdict.BLOCK, "DO-07", "Piping into a shell runs unknown code.", original, risk="HIGH")

    parts = [p.strip() for p in re.split(r"&&|\|\||;|\||\n", original) if p.strip()]
    results = [_check_one(p, policy) for p in parts]
    worst = max(results, key=lambda r: SEVERITY[r.verdict])
    if len(parts) > 1 and worst.verdict == Verdict.CORRECT:
        return _d(Verdict.REVIEW, "DO-12", "Chained commands with a risky part need a human.", original, risk="MEDIUM")
    worst.original = original
    return worst
