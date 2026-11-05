import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.pop("MODEL_API_KEY", None)

from fastapi.testclient import TestClient
import main

client = TestClient(main.app)


def test_home_and_health():
    assert client.get("/").status_code == 200
    assert client.get("/health").json() == {"ok": True}


def test_chat_flow_and_report():
    r = client.post("/api/chat", json={"message": "URGENT account blocked, send OTP"})
    assert r.status_code == 200
    sid = r.json()["session_id"]
    assert client.get(f"/api/report/{sid}").status_code == 200


def test_honeypot_requires_key():
    assert client.post("/honeypot", json={"message": "hi"}).status_code == 401
    ok = client.post("/honeypot", json={"message": "hi"},
                     headers={"x-api-key": main.API_KEY})
    assert ok.status_code == 200


def test_empty_message_rejected():
    assert client.post("/api/chat", json={"message": ""}).status_code == 422
