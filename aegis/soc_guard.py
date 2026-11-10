"""SOC checker. Reads a security response action (JSON) and decides.

Example action:
{"action": "isolate_host", "target": "srv-dc-01", "alert_id": "A-1042", "severity": "high"}
"""
import ipaddress
import json

from .models import Decision, Verdict

SEV = {"low": 0, "medium": 1, "high": 2, "critical": 3}
FREE_TEXT_FIELDS = ("reason", "evidence", "note", "alert_text", "summary")


def _d(v, rule, reason, original, corrected=None, risk="LOW"):
    return Decision(v, rule, reason, original, corrected, risk)


def _fix(a: dict, **changes) -> str:
    return json.dumps({**a, **changes}, sort_keys=True)


def check_soc(action, policy: dict, _recheck: bool = False) -> Decision:
    original = action.strip() if isinstance(action, str) else json.dumps(action, sort_keys=True)
    try:
        a = json.loads(original)
    except ValueError:
        return _d(Verdict.REVIEW, "SOC-00", "Action is not valid JSON, so a human must look.", original, risk="MEDIUM")
    if not isinstance(a, dict) or "action" not in a:
        return _d(Verdict.REVIEW, "SOC-00", "Action has no 'action' field.", original, risk="MEDIUM")

    name = str(a["action"]).lower()
    t = a.get("target")
    targets = t if isinstance(t, list) else ([] if t is None else [t])

    # SOC-08: prompt injection hidden in free text (logs, alerts)
    text = " ".join(str(a.get(k, "")) for k in FREE_TEXT_FIELDS).lower()
    for phrase in policy.get("injection_phrases", []):
        if phrase in text:
            return _d(Verdict.REVIEW, "SOC-08",
                      f"Free text contains an instruction-like phrase ('{phrase}'). Possible prompt injection.",
                      original, risk="HIGH")

    if name in policy.get("read_actions", []) or name in policy.get("monitor_actions", []):
        return _d(Verdict.ALLOW, "SOC-00", "Read-only or watch-only action.", original)
    if name not in policy.get("response_actions", []):
        return _d(Verdict.REVIEW, "SOC-00", f"Unknown action '{name}', so it fails closed.", original, risk="MEDIUM")

    # SOC-01: evidence
    if policy.get("require_alert_id", True) and not a.get("alert_id"):
        return _d(Verdict.BLOCK, "SOC-01", "No alert ID. No evidence, no action.", original, risk="HIGH")

    # SOC-06: protected accounts
    if name in ("disable_account", "reset_password"):
        protected = {p.lower() for p in policy.get("protected_accounts", [])}
        for tg in targets:
            if str(tg).lower() in protected:
                return _d(Verdict.BLOCK, "SOC-06", f"'{tg}' is a protected account. Only a human may touch it.",
                          original, risk="HIGH")

    # SOC-03: never block our own network
    if name == "block_ip":
        nets = [ipaddress.ip_network(n, strict=False) for n in policy.get("never_block", [])]
        for tg in targets:
            try:
                ip = ipaddress.ip_address(str(tg))
            except ValueError:
                return _d(Verdict.REVIEW, "SOC-03", f"'{tg}' is not a valid IP address.", original, risk="MEDIUM")
            if any(ip in n for n in nets):
                return _d(Verdict.BLOCK, "SOC-03", f"{ip} belongs to the company network or DNS.", original, risk="HIGH")

    # SOC-07: blast radius
    n = max(len(targets), int(a.get("count", 0) or 0))
    if n > int(policy.get("max_targets", 10)):
        return _d(Verdict.REVIEW, "SOC-07", f"Mass action on {n} targets. A human must approve.", original, risk="HIGH")

    # SOC-02: severity too low for such a strong action -> downgrade
    sev = SEV.get(str(a.get("severity", "low")).lower(), 0)
    need = SEV[policy.get("min_severity", {}).get(name, "medium")]
    if sev < need:
        weaker = policy.get("downgrade", {}).get(name)
        if weaker and not _recheck:
            fixed = _fix(a, action=weaker)
            if check_soc(fixed, policy, _recheck=True).verdict == Verdict.ALLOW:
                return _d(Verdict.CORRECT, "SOC-02",
                          f"Severity '{a.get('severity', 'low')}' is too low for {name}. Downgraded to {weaker}.",
                          original, fixed, risk="LOW")
        return _d(Verdict.REVIEW, "SOC-02", "Severity too low for this action.", original, risk="MEDIUM")

    # SOC-04 / SOC-05: critical assets (with impact preview)
    if name in ("isolate_host", "kill_process", "quarantine_file"):
        assets = policy.get("assets", {})
        for tg in targets:
            info = assets.get(str(tg))
            if info is None:
                return _d(Verdict.REVIEW, "SOC-05", f"'{tg}' is not in the asset inventory, so it fails closed.",
                          original, risk="MEDIUM")
            if info.get("criticality") in ("critical", "high"):
                preview = f"Impact preview: {info.get('users', '?')} user(s) depend on {tg} ({info.get('role', 'unknown role')})."
                risk = "HIGH" if info["criticality"] == "critical" else "MEDIUM"
                return _d(Verdict.REVIEW, "SOC-04",
                          f"{tg} is a {info['criticality']} asset. A human must approve. {preview}", original, risk=risk)

    # SOC-09: every IP block must expire
    if name == "block_ip" and not _recheck:
        try:
            dur = int(a.get("duration_minutes"))
        except (TypeError, ValueError):
            dur = None
        limit = int(policy.get("max_block_minutes", 1440))
        if dur is None or dur > limit or dur <= 0:
            default = int(policy.get("default_block_minutes", 60))
            fixed = _fix(a, duration_minutes=default)
            if check_soc(fixed, policy, _recheck=True).verdict == Verdict.ALLOW:
                return _d(Verdict.CORRECT, "SOC-09", f"Block had no valid expiry. Set to {default} minutes.",
                          original, fixed)
            return _d(Verdict.REVIEW, "SOC-09", "Could not set a safe expiry.", original)

    return _d(Verdict.ALLOW, "SOC-00", "Evidence, severity and target checked. Within limits.", original)
