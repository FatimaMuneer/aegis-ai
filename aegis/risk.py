"""risk.py - the OPTIONAL AI risk checker.

assess(text) always works offline using simple keyword rules.
assess(text, use_ai=True) also asks an AI model for a second opinion, but only if:
    - you ran:  pip install anthropic
    - the ANTHROPIC_API_KEY environment variable is set
If anything goes wrong (no key, no internet, odd answer) it quietly falls back to
the keyword rules, so AEGIS never depends on the AI being available.
"""
import json
import importlib
import os
import re

LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# (level, regex, why) - the highest matching level wins
RULES = [
    ("CRITICAL", r"\bdrop\s+(database|schema)\b|\btruncate\s+table\b", "wipes a database or table"),
    ("CRITICAL", r"\brm\s+-\w*(rf|fr)\w*\s+(/|~|\*)", "force-deletes a root or home folder"),
    ("HIGH", r"\bdrop\s+table\b", "deletes a table"),
    ("HIGH", r"\bdelete\s+from\s+\w+\s*;?\s*$", "DELETE with no WHERE"),
    ("HIGH", r"\bupdate\s+\w+\s+set\b(?!.*\bwhere\b)", "UPDATE with no WHERE"),
    ("HIGH", r"\bsudo\b|\bchmod\s+7\d\d\b", "uses admin power or opens permissions"),
    ("MEDIUM", r"\b(delete|update|insert|alter)\b", "changes data"),
    ("MEDIUM", r"\b(rm|mv|kill|curl|wget)\b", "changes files, processes or uses the network"),
]


def rank(level: str) -> int:
    return LEVELS.index(level) if level in LEVELS else 0


def higher(a: str, b: str) -> str:
    return a if rank(a) >= rank(b) else b


def keyword_assess(text: str) -> dict:
    level, reasons = "LOW", []
    for rule_level, pattern, why in RULES:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            level = higher(level, rule_level)
            reasons.append(why)
    return {"level": level, "reason": "; ".join(reasons) or "nothing risky found",
            "source": "keywords"}


def ai_assess(text: str, kind: str):
    """Ask an AI model. Returns a dict, or None if unavailable."""
    if not os.getenv("ANTHROPIC_API_KEY"):
        return None
    try:
        anthropic = importlib.import_module("anthropic")  # optional dependency
        client = anthropic.Anthropic()
        reply = client.messages.create(
            model=os.getenv("AEGIS_RISK_MODEL", "claude-haiku-5-5"),
            max_tokens=200,
            messages=[{"role": "user", "content": (
                f"You are a security reviewer. An AI agent wants to run this {kind} action:\n\n"
                f"{text}\n\n"
                'Reply with JSON only: {"level": "LOW|MEDIUM|HIGH|CRITICAL", "reason": "one short sentence"}')}],
        )
        answer = reply.content[0].text.strip()
        answer = re.sub(r"^```(?:json)?|```$", "", answer).strip()
        data = json.loads(answer)
        level = str(data["level"]).upper()
        if level not in LEVELS:
            return None
        return {"level": level, "reason": str(data.get("reason", "")), "source": "ai"}
    except Exception:
        return None


def assess(text: str, kind: str = "other", use_ai: bool = False) -> dict:
    result = keyword_assess(text)
    if use_ai:
        ai = ai_assess(text, kind)
        if ai:  # keep the stricter of the two opinions
            if rank(ai["level"]) > rank(result["level"]):
                return ai
            result["reason"] += f" (AI agrees: {ai['level']})"
    return result
