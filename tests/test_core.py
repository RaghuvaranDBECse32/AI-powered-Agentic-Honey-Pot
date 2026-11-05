import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.pop("MODEL_API_KEY", None)  # force rule-based mode in tests

import agent, detection, extraction


def setup_function(_):
    agent.reset_all()


def test_extract_upi_not_email():
    r = extraction.extract("pay to scammer@okaxis or mail john@gmail.com")
    assert r["upi_ids"] == ["scammer@okaxis"]


def test_extract_link_phone_account_ifsc():
    r = extraction.extract(
        "Go to https://fake-bank.example/login. Call +91 98765 43210. "
        "Acct 123456789012 IFSC HDFC0001234")
    assert r["phishing_links"] == ["https://fake-bank.example/login"]
    assert r["phone_numbers"] == ["9876543210"]
    assert r["bank_accounts"] == ["123456789012"]
    assert r["ifsc_codes"] == ["HDFC0001234"]


def test_phone_not_counted_as_account():
    assert extraction.extract("call 9876543210")["bank_accounts"] == []


def test_detection_scam_vs_normal():
    assert detection.analyze("URGENT your account is blocked, send OTP")["risk_score"] >= 50
    assert detection.analyze("Lunch tomorrow at 1pm?")["risk_score"] < 40


def test_hindi_detection():
    assert detection.analyze("आपका खाता बंद, तुरंत ओटीपी भेजें")["risk_score"] >= 50


def test_multi_turn_session_accumulates_intel():
    a = agent.handle(None, "URGENT account blocked. Send OTP at http://x.example/a")
    sid = a["session_id"]
    b = agent.handle(sid, "Pay fee to evil@paytm now, urgent")
    assert b["conversation_turns"] == 2
    assert b["extracted_intelligence"]["upi_ids"] == ["evil@paytm"]
    assert b["extracted_intelligence"]["phishing_links"] == ["http://x.example/a"]
    assert b["agent_reply"]


def test_benign_message_ignored():
    r = agent.handle(None, "see you at lunch")
    assert r["engagement_status"] == "ignored" and r["agent_reply"] is None


def test_report_exists():
    sid = agent.handle(None, "URGENT blocked account OTP")["session_id"]
    assert agent.build_report(sid)["turns"] == 1
    assert agent.build_report("missing") is None
