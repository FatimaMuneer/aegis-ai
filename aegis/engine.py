"""engine.py - runs all the checks in order and writes the log.

Every agent action goes through Engine.evaluate(). The order is:
  1. behaviour   loop / budget  -> block the agent if it misbehaves
  2. guards      db_guard, ops_guard or soc_guard (Person A's rules)
  3. learned     a rule a human approved before can skip a "needs approval" step
  4. risk        keyword rules (+ optional AI); CRITICAL is always blocked
  5. dry-run     preview how many rows a risky SQL action would change
  6. audit       write the decision to the tamper-evident log
"""
import importlib
from dataclasses import replace

from . import dryrun, learn, risk
from .audit import AuditLog
from .behavior import BehaviourMonitor
from .models import Decision, Verdict

# which guard module handles which kind of action
GUARDS = {"sql": "db_guard", "db": "db_guard",
          "shell": "ops_guard", "ops": "ops_guard", "devops": "ops_guard",
          "soc": "soc_guard"}

# Verdict names are matched by text, so this works with your own models.py.
# If your Verdict enum uses other words, add them here.
BLOCK_NAMES = ("BLOCK", "BLOCKED", "DENY", "DENIED")
ALLOW_NAMES = ("ALLOW", "ALLOWED", "PASS")
APPROVAL_NAMES = ("ASK", "REVIEW", "APPROVAL", "NEEDS_APPROVAL", "PENDING", "CONFIRM")


def pick(names):
    """Find the first of these names that exists in your Verdict enum."""
    for name in names:
        if hasattr(Verdict, name):
            return getattr(Verdict, name)
    raise AttributeError(f"Verdict has none of {names} - check aegis/models.py")


def verdict_name(decision) -> str:
    return str(getattr(decision.verdict, "value", decision.verdict)).upper()


def is_blocked(decision) -> bool:
    return verdict_name(decision) in BLOCK_NAMES


def call_guard(kind: str, action: str):
    """ADAPTER: the one place that calls Person A's guard files.
    If a guard's function has another name, change the list below."""
    module_name = GUARDS.get(kind)
    if not module_name:
        return None
    try:
        module = importlib.import_module(f"aegis.{module_name}")
    except ImportError:
        return None
    for function_name in ("check", "evaluate", "inspect"):
        function = getattr(module, function_name, None)
        if callable(function):
            return function(action)
    return None


class Engine:
    def __init__(self, audit_path="aegis_audit.jsonl", db_path=None, use_ai_risk=False,
                 learned_path=learn.LEARNED_FILE, block_at="CRITICAL", **behaviour_settings):
        self.audit = AuditLog(audit_path)
        self.behaviour = BehaviourMonitor(**behaviour_settings)
        self.db_path = db_path
        self.use_ai_risk = use_ai_risk
        self.block_at = block_at
        self.learned = learn.load_rules(learned_path)

    def _decision(self, names, rule, reason, action, level="LOW"):
        return Decision(verdict=pick(names), rule=rule, reason=reason,
                        original=action, corrected=None, risk=level)

    def evaluate(self, action: str, kind: str = "other", agent: str = "default",
                 tokens: int = 0, cost: float = 0.0):
        kind = kind.lower()
        extra = {}

        # 1) behaviour
        flags = self.behaviour.check(agent, action, tokens, cost)
        if "LOOP" in flags or "BUDGET_EXCEEDED" in flags:
            reason = ("Agent is stuck repeating the same action." if "LOOP" in flags
                      else "Agent went over its token/cost budget.")
            decision = self._decision(BLOCK_NAMES, "BHV-01", reason, action, "HIGH")
        else:
            # 2) guards
            decision = call_guard(kind, action)
            if decision is None:
                decision = self._decision(ALLOW_NAMES, "ENG-00", "No rule matched.", action)

            # 3) learned rules (never override a BLOCK)
            if verdict_name(decision) in APPROVAL_NAMES:
                rule = learn.matches(self.learned, action)
                if rule:
                    decision = replace(decision, verdict=pick(ALLOW_NAMES), rule=rule["id"],
                                       reason="Auto-approved: " + rule["reason"])

            # 4) risk
            result = risk.assess(action, kind, use_ai=self.use_ai_risk)
            level = risk.higher(str(decision.risk), result["level"])
            decision = replace(decision, risk=level)
            extra["risk_source"] = result["source"]
            if not is_blocked(decision) and risk.rank(level) >= risk.rank(self.block_at):
                decision = replace(decision, verdict=pick(BLOCK_NAMES), rule="RSK-01",
                                   reason=f"Risk {level}: {result['reason']}")

            # 5) dry-run
            if (not is_blocked(decision) and kind in ("sql", "db")
                    and risk.rank(level) >= risk.rank("MEDIUM")):
                preview = dryrun.dry_run_sql(action, self.db_path)
                extra["dry_run"] = preview
                decision = replace(decision, reason=f"{decision.reason} {preview['message']}")

        # 6) audit
        self.audit.append({
            "agent": agent, "kind": kind, "verdict": verdict_name(decision),
            "rule": decision.rule, "risk": str(decision.risk), "reason": decision.reason,
            "original": decision.original, "corrected": decision.corrected,
            "flags": flags, "tokens": tokens, "cost": cost, **extra})
        return decision