from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_analyze_endpoint():
    payload = {
        "alert_id": "api-test-1",
        "environment": "simulated",
        "events": [
            {
                "event_id": "e1",
                "timestamp": "2026-01-01T00:00:00Z",
                "source": "ids",
                "event_type": "intrusion",
                "severity": 9,
                "detail": "suspicious",
            }
        ],
    }
    resp = client.post("/analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "decision" in data
    assert data["decision"]["decision"] in ("ALLOW", "REVIEW", "BLOCK")
    assert "assessment" in data
    assert "risk" in data
