"""API tests. They are skipped automatically if fastapi / httpx are not installed."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("sqlglot")      # aegis.api imports the engine, which loads the SQL guard on demand

from fastapi.testclient import TestClient

from aegis import api

TEST_REVIEW_TOKEN = "test-review-token-for-aegis-unit-tests-2026"


@pytest.fixture
def client(engine, monkeypatch):
    monkeypatch.setattr(api, "engine", engine)      # each test uses its own empty log
    monkeypatch.setenv("AEGIS_REVIEW_TOKEN", TEST_REVIEW_TOKEN)
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
    pending = client.get("/pending").json()
    assert pending["count"] == 1

    review_seq = pending["entries"][0]["seq"]
    response = client.post("/approve", json={"review_seq": review_seq}, headers={"Authorization": f"Bearer {TEST_REVIEW_TOKEN}"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "APPROVED"
    assert body["executed"] is False
    assert body["approval_id"]

    assert client.get("/pending").json()["count"] == 0

    entries = api.engine.audit.read_all()
    assert entries[-1]["verdict"] == "APPROVAL_GRANTED"
    assert not any(e["verdict"] == "HUMAN_APPROVED" for e in entries)
    assert client.get("/learn/suggestions").json()["suggestions"] == []


def test_approval_requires_a_real_review_event(client):
    response = client.post("/approve", json={"review_seq": 999}, headers={"Authorization": f"Bearer {TEST_REVIEW_TOKEN}"})
    assert response.status_code == 404


def test_review_cannot_be_approved_twice(client):
    client.post("/evaluate", json={"action": "git push origin main", "kind": "shell"})
    review_seq = client.get("/pending").json()["entries"][0]["seq"]

    first = client.post("/approve", json={"review_seq": review_seq}, headers={"Authorization": f"Bearer {TEST_REVIEW_TOKEN}"})
    second = client.post("/approve", json={"review_seq": review_seq}, headers={"Authorization": f"Bearer {TEST_REVIEW_TOKEN}"})

    assert first.status_code == 200
    assert second.status_code == 409


def test_rejection_resolves_review_without_grant(client):
    client.post("/evaluate", json={"action": "git push origin main", "kind": "shell"})
    review_seq = client.get("/pending").json()["entries"][0]["seq"]

    response = client.post("/reject", json={"review_seq": review_seq}, headers={"Authorization": f"Bearer {TEST_REVIEW_TOKEN}"})

    assert response.status_code == 200
    assert response.json()["status"] == "REJECTED"
    assert response.json()["executed"] is False
    assert client.get("/pending").json()["count"] == 0

    entries = api.engine.audit.read_all()
    assert entries[-1]["verdict"] == "APPROVAL_REJECTED"


def test_chat_endpoint(client):
    r = client.post("/chat", json={"message": "terraform destroy"})
    assert r.json()["decision"]["verdict"] == "BLOCK"


def test_bad_rule_regex_is_rejected(client):
    r = client.post("/learn/rules", json={"pattern": "([unclosed", "reason": "x"})
    assert r.status_code == 400


def test_suggestions_endpoint(client):
    assert client.get("/learn/suggestions").json()["suggestions"] == []
