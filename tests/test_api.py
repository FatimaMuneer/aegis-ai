"""API tests. They are skipped automatically if fastapi / httpx are not installed."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlglot")      # aegis.api imports the engine, which loads the SQL guard on demand

from fastapi.testclient import TestClient

from aegis import api


@pytest.fixture
def client(engine, monkeypatch):
    monkeypatch.setattr(api, "engine", engine)      # each test uses its own empty log
    return TestClient(api.app)


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_dashboard_is_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "AEGIS" in r.text


def test_evaluate_blocks_a_dangerous_command(client):
    r = client.post("/evaluate", json={"action": "terraform destroy", "kind": "shell"})
    assert r.status_code == 200
    assert r.json()["verdict"] == "BLOCK" and r.json()["rule"] == "DO-01"


def test_evaluate_corrects_sql(client):
    r = client.post("/evaluate", json={"action": "SELECT * FROM orders", "kind": "sql"})
    body = r.json()
    assert body["verdict"] == "CORRECT" and body["corrected"].endswith("LIMIT 100")


def test_evaluate_needs_an_action(client):
    assert client.post("/evaluate", json={"kind": "sql"}).status_code == 422


def test_audit_and_stats(client):
    client.post("/evaluate", json={"action": "ls", "kind": "shell"})
    client.post("/evaluate", json={"action": "cat .env", "kind": "shell"})
    assert client.get("/audit").json()["count"] == 2
    assert client.get("/audit?verdict=BLOCK").json()["count"] == 1
    stats = client.get("/stats").json()
    assert stats["total"] == 2 and stats["verdicts"] == {"ALLOW": 1, "BLOCK": 1} and stats["log_intact"]


def test_verify_endpoint(client):
    client.post("/evaluate", json={"action": "ls", "kind": "shell"})
    assert client.get("/audit/verify").json()["intact"] is True


def test_pending_and_approve(client):
    client.post("/evaluate", json={"action": "git push origin main", "kind": "shell"})
    assert client.get("/pending").json()["count"] == 1
    client.post("/approve", json={"action": "git push origin main", "kind": "shell"})
    assert client.get("/pending").json()["count"] == 0


def test_chat_endpoint(client):
    r = client.post("/chat", json={"message": "terraform destroy"})
    assert r.json()["decision"]["verdict"] == "BLOCK"


def test_bad_rule_regex_is_rejected(client):
    r = client.post("/learn/rules", json={"pattern": "([unclosed", "reason": "x"})
    assert r.status_code == 400


def test_suggestions_endpoint(client):
    assert client.get("/learn/suggestions").json()["suggestions"] == []
