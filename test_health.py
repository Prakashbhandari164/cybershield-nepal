from fastapi.testclient import TestClient
from app.main import app, validate_url

client = TestClient(app)

def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"

def test_tips():
    r = client.get("/api/tips")
    assert r.status_code == 200 and len(r.json()["tips"]) >= 3

def test_dashboard():
    r = client.get("/")
    assert r.status_code == 200 and "CyberShield Nepal" in r.text

def test_rejects_http():
    try:
        validate_url("http://example.com")
    except ValueError as e:
        assert "HTTPS" in str(e)
    else:
        assert False, "HTTP URL should be rejected"
