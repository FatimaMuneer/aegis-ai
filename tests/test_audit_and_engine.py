import json

import pytest

from aegis import learn
from aegis.audit import AuditLog
from aegis.engine import Engine


# ---------- audit log ----------
def test_empty_log_is_intact(audit):
    assert audit.verify() == (True, "log is intact")


def test_entries_are_chained(audit):
    first = audit.append({"verdict": "ALLOW"})
    second = audit.append({"verdict": "BLOCK"})
    assert first["seq"] == 1 and second["seq"] == 2
    assert second["prev_hash"] == first["hash"]
    assert audit.verify()[0] is True


def test_modified_entry_is_detected(audit):
    for v in ("ALLOW", "BLOCK", "REVIEW"):
        audit.append({"verdict": v})
    lines = audit.path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["verdict"] = "ALLOW"                       # someone rewrites history
    lines[1] = json.dumps(entry)
    audit.path.write_text("\n".join(lines) + "\n")
    ok, message = audit.verify()
    assert not ok and "2" in message


def test_deleted_entry_is_detected(audit):
    for v in ("ALLOW", "BLOCK", "REVIEW"):
        audit.append({"verdict": v})
    lines = audit.path.read_text().splitlines()
    audit.path.write_text("\n".join([lines[0], lines[2]]) + "\n")   # remove the middle line
    assert audit.verify()[0] is False


# ---------- engine ----------
def test_dangerous_shell_command_is_blocked(engine):
    d = engine.evaluate("terraform destroy", kind="shell")
    assert d.verdict.value == "BLOCK" and d.rule == "DO-01"


def test_safe_shell_command_is_allowed(engine):
    assert engine.evaluate("ls", kind="shell").verdict.value == "ALLOW"


def test_correction_is_returned(engine):
    d = engine.evaluate("rm -rf ./*", kind="shell")
    assert d.verdict.value == "CORRECT" and d.corrected == "ls ./*"


def test_soc_action_goes_through_soc_guard(engine):
    action = json.dumps({"action": "disable_account", "target": "ceo", "alert_id": "A-1", "severity": "critical"})
    d = engine.evaluate(action, kind="soc")
    assert d.verdict.value == "BLOCK" and d.rule == "SOC-06"


def test_unknown_kind_requires_review(engine):
    d = engine.evaluate("hello", kind="other")

    assert d.verdict.value == "REVIEW"
    assert d.rule == "ENG-01"
    assert "Unsupported action kind" in d.reason


def test_every_decision_is_logged(engine):
    engine.evaluate("ls", kind="shell")
    engine.evaluate("cat .env", kind="shell")
    entries = engine.audit.read_all()
    assert [e["verdict"] for e in entries] == ["ALLOW", "BLOCK"]
    assert engine.audit.verify()[0] is True


def test_loop_is_blocked(engine):
    verdicts = [engine.evaluate("ls", kind="shell", agent="a").verdict.value for _ in range(4)]
    assert verdicts[:2] == ["ALLOW", "ALLOW"] and verdicts[2] == "BLOCK"
    assert engine.audit.read_all()[2]["rule"] == "BHV-01"


def test_loops_are_tracked_per_agent(engine):
    for _ in range(2):
        engine.evaluate("ls", kind="shell", agent="a")
    assert engine.evaluate("ls", kind="shell", agent="b").verdict.value == "ALLOW"


def test_budget_is_enforced(tmp_path):
    engine = Engine(audit_path=tmp_path / "a.jsonl", learned_path=tmp_path / "l.yaml", token_budget=100)
    assert engine.evaluate("echo 1", kind="shell", agent="x", tokens=60).verdict.value == "ALLOW"
    d = engine.evaluate("echo 2", kind="shell", agent="x", tokens=60)
    assert d.verdict.value == "BLOCK" and d.rule == "BHV-01"


# ---------- learned rules ----------
def make_rule(tmp_path, action):
    path = tmp_path / "learned.yaml"
    learn.add_rule(learn.to_regex(learn.normalize(action)), "approved many times", path=path)
    return path


def test_learned_rule_skips_a_review(tmp_path):
    action = "git push origin main"
    assert Engine(audit_path=tmp_path / "a1.jsonl", learned_path=tmp_path / "none.yaml") \
        .evaluate(action, kind="shell").verdict.value == "REVIEW"
    engine = Engine(audit_path=tmp_path / "a2.jsonl", learned_path=make_rule(tmp_path, action))
    d = engine.evaluate(action, kind="shell")
    assert d.verdict.value == "ALLOW" and d.rule == "LRN-001"


def test_learned_rule_never_overrides_a_block(tmp_path):
    action = "terraform destroy"
    engine = Engine(audit_path=tmp_path / "a.jsonl", learned_path=make_rule(tmp_path, action))
    assert engine.evaluate(action, kind="shell").verdict.value == "BLOCK"


def test_repeated_approvals_become_a_suggestion(audit, tmp_path):
    for i in (1, 2, 3):
        learn.record_approval(audit, f"DELETE FROM logs WHERE id = {i}", kind="sql")
    suggestions = learn.suggest_rules(audit, path=tmp_path / "none.yaml")
    assert len(suggestions) == 1 and suggestions[0]["approved_times"] == 3


def test_two_approvals_are_not_enough(audit, tmp_path):
    for i in (1, 2):
        learn.record_approval(audit, f"DELETE FROM logs WHERE id = {i}", kind="sql")
    assert learn.suggest_rules(audit, path=tmp_path / "none.yaml") == []


def test_bad_regex_is_rejected(tmp_path):
    with pytest.raises(Exception):
        learn.add_rule("([unclosed", "bad", path=tmp_path / "x.yaml")


# ---------- SQL through the engine (needs sqlglot) ----------
def test_sql_goes_through_db_guard(engine):
    pytest.importorskip("sqlglot")
    assert engine.evaluate("DROP TABLE orders", kind="sql").verdict.value == "BLOCK"
    assert engine.evaluate("SELECT * FROM orders", kind="sql").verdict.value == "CORRECT"
