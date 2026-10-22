
import pytest
from fastapi.testclient import TestClient
import app.main as main

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def use_test_database(tmp_path, monkeypatch):
    """Keep test scans isolated from the real database."""
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test_history.sqlite3")


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_scenarios_endpoint():
    response = client.get("/scenarios")

    assert response.status_code == 200

    scenario_ids = {
        item["id"] for item in response.json()["scenarios"]
    }

    assert scenario_ids == {
        "secure",
        "moderate_risk",
        "high_risk",
    }


def test_secure_and_high_risk_scans_differ():
    secure_response = client.post(
        "/scan",
        json={"label": "Secure test", "scenario": "secure"},
    )
    risky_response = client.post(
        "/scan",
        json={"label": "High risk test", "scenario": "high_risk"},
    )

    assert secure_response.status_code == 200, secure_response.text
    assert risky_response.status_code == 200, risky_response.text

    secure = secure_response.json()
    risky = risky_response.json()

    assert secure["scan_id"] != risky["scan_id"]
    assert secure["scenario"] == "secure"
    assert risky["scenario"] == "high_risk"

    assert secure["posture_score"] > risky["posture_score"]
    assert (
        secure["summary"]["total_findings"]
        < risky["summary"]["total_findings"]
    )


def test_unknown_scenario_is_rejected():
    response = client.post(
        "/scan",
        json={"scenario": "unknown_scenario"},
    )

    assert response.status_code in (400, 422)


def test_scans_are_saved_in_history():
    first = client.post(
        "/scan",
        json={"scenario": "secure"},
    )
    second = client.post(
        "/scan",
        json={"scenario": "high_risk"},
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text

    response = client.get("/history?limit=10")

    assert response.status_code == 200

    history_ids = {
        item["scan_id"]
        for item in response.json()["history"]
    }

    assert first.json()["scan_id"] in history_ids
    assert second.json()["scan_id"] in history_ids
