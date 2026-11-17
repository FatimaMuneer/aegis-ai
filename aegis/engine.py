
"""engine.py - runs all the checks in order and writes the log.

Every agent action goes through Engine.evaluate(). The order is:
  1. behaviour   loop / budget -> block the agent if it misbehaves
  2. guards      db_guard, ops_guard or soc_guard
  3. learned     a previously approved rule can skip a needs-approval step
  4. risk        keyword rules (+ optional AI); CRITICAL is blocked
  5. dry-run     preview how many rows a risky SQL action would change
  6. audit       write the decision to the tamper-evident log
"""

import importlib
from dataclasses import replace

from . import dryrun, learn, policy, risk
from .audit import AuditLog
from .behavior import BehaviourMonitor
from .models import Decision, Verdict


BLOCK_NAMES = ("BLOCK", "BLOCKED", "DENY", "DENIED")
ALLOW_NAMES = ("ALLOW", "ALLOWED", "PASS")
APPROVAL_NAMES = (
    "ASK",
    "REVIEW",
    "APPROVAL",
    "NEEDS_APPROVAL",
    "PENDING",
    "CONFIRM",
)


def pick(names):
    """Find the first matching verdict in the Verdict enum."""
    for name in names:
        if hasattr(Verdict, name):
            return getattr(Verdict, name)

    raise AttributeError(
        f"Verdict has none of {names} - check aegis/models.py"
    )


def verdict_name(decision) -> str:
    return str(
        getattr(decision.verdict, "value", decision.verdict)
    ).upper()


def is_blocked(decision) -> bool:
    return verdict_name(decision) in BLOCK_NAMES


# kind -> (module, function, policy file)
GUARD_FUNCTIONS = {
    "sql": ("db_guard", "check_sql", "database"),
    "db": ("db_guard", "check_sql", "database"),
    "shell": ("ops_guard", "check_command", "devops"),
    "ops": ("ops_guard", "check_command", "devops"),
    "devops": ("ops_guard", "check_command", "devops"),
    "soc": ("soc_guard", "check_soc", "soc"),
}


def call_guard(kind: str, action: str):
    """Call the correct security guard for the requested action kind."""

    spec = GUARD_FUNCTIONS.get(kind)

    if not spec:
        return None

    module_name, function_name, policy_name = spec

    module = importlib.import_module(f"aegis.{module_name}")
    guard_function = getattr(module, function_name)

    return guard_function(action, policy.load(policy_name))


class Engine:

    def __init__(
        self,
        audit_path="aegis_audit.jsonl",
        db_path=None,
        use_ai_risk=False,
        learned_path=learn.LEARNED_FILE,
        block_at="CRITICAL",
        **behaviour_settings
    ):
        self.audit = AuditLog(audit_path)
        self.behaviour = BehaviourMonitor(**behaviour_settings)
        self.db_path = db_path
        self.use_ai_risk = use_ai_risk
        self.block_at = block_at
        self.learned = learn.load_rules(learned_path)

    def _decision(
        self,
        names,
        rule,
        reason,
        action,
        level="LOW"
    ):
        return Decision(
            verdict=pick(names),
            rule=rule,
            reason=reason,
            original=action,
            corrected=None,
            risk=level,
        )

    def evaluate(
        self,
        action: str,
        kind: str = "other",
        agent: str = "default",
        tokens: int = 0,
        cost: float = 0.0
    ):
        kind = (kind or "other").strip().lower()
        extra = {}

        # 1. Behaviour monitoring
        flags = self.behaviour.check(
            agent,
            action,
            tokens,
            cost
        )

        if "LOOP" in flags or "BUDGET_EXCEEDED" in flags:
            reason = (
                "Agent is stuck repeating the same action."
                if "LOOP" in flags
                else "Agent went over its token/cost budget."
            )

            decision = self._decision(
                BLOCK_NAMES,
                "BHV-01",
                reason,
                action,
                "HIGH"
            )

        else:
            # 2. Security guards
            decision = call_guard(kind, action)

            # Unknown action types must never be automatically allowed.
            if decision is None:
                decision = self._decision(
                    ("REVIEW",),
                    "ENG-01",
                    (
                        f"Unsupported action kind '{kind}'. "
                        "No security guard is configured. "
                        "Human review is required."
                    ),
                    action,
                    "HIGH"
                )

            # 3. Previously approved learned rules.
            # Only apply them to recognised action types.
            # Never override a BLOCK or an unsupported action.
            if (
                kind in GUARD_FUNCTIONS
                and verdict_name(decision) in APPROVAL_NAMES
            ):
                rule = learn.matches(self.learned, action)

                if rule:
                    decision = replace(
                        decision,
                        verdict=pick(ALLOW_NAMES),
                        rule=rule["id"],
                        reason="Auto-approved: " + rule["reason"]
                    )

            # 4. Risk assessment
            result = risk.assess(
                action,
                kind,
                use_ai=self.use_ai_risk
            )

            level = risk.higher(
                str(decision.risk),
                result["level"]
            )

            decision = replace(
                decision,
                risk=level
            )

            extra["risk_source"] = result["source"]

            # CRITICAL risk is blocked regardless of the guard verdict.
            if (
                not is_blocked(decision)
                and risk.rank(level) >= risk.rank(self.block_at)
            ):
                decision = replace(
                    decision,
                    verdict=pick(BLOCK_NAMES),
                    rule="RSK-01",
                    reason=f"Risk {level}: {result['reason']}"
                )

            # 5. SQL dry-run preview
            if (
                not is_blocked(decision)
                and kind in ("sql", "db")
                and risk.rank(level) >= risk.rank("MEDIUM")
            ):
                preview = dryrun.dry_run_sql(
                    action,
                    self.db_path
                )

                extra["dry_run"] = preview

                decision = replace(
                    decision,
                    reason=(
                        f"{decision.reason} "
                        f"{preview['message']}"
                    )
                )

        # 6. Audit logging
        self.audit.append({
            "agent": agent,
            "kind": kind,
            "verdict": verdict_name(decision),
            "rule": decision.rule,
            "risk": str(decision.risk),
            "reason": decision.reason,
            "original": decision.original,
            "corrected": decision.corrected,
            "flags": flags,
            "tokens": tokens,
            "cost": cost,
            **extra
        })

        return decision
