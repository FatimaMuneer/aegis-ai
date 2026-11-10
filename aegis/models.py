from dataclasses import dataclass, asdict
from enum import Enum


class Verdict(str, Enum):
    ALLOW = "ALLOW"      # safe, run it
    CORRECT = "CORRECT"  # unsafe but fixable, run the fixed version
    REVIEW = "REVIEW"    # a human must decide
    BLOCK = "BLOCK"      # never allowed


# Higher number = stricter. Used to pick the worst result.
SEVERITY = {Verdict.ALLOW: 0, Verdict.CORRECT: 1, Verdict.REVIEW: 2, Verdict.BLOCK: 3}


@dataclass   
class Decision:
    verdict: Verdict
    rule: str            # e.g. "DB-05"
    reason: str          # plain-language explanation
    original: str        # what the agent asked to run
    corrected: str | None = None
    risk: str = "LOW"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d