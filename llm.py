"""Meta Model API client (OpenAI-compatible).

Config via environment variables:
    MODEL_API_KEY   your Meta Model API key (never commit it)
    LLM_BASE_URL    default https://api.meta.ai/v1
    LLM_MODEL       default muse-spark-1.1  (check the Models tab for newer)
"""
import json
import logging
import os
import re

log = logging.getLogger("honeypot.llm")

DETECT_PROMPT = """You are a fraud-analysis assistant. Analyse the message and \
reply with ONLY a JSON object, no markdown, in exactly this shape:
{"risk_score": <integer 0-100>,
 "scam_type": "<one of: Bank account block, OTP theft, KYC fraud, Lottery / prize, Delivery fee, Payment request, Other, Not a clear scam>",
 "indicators": ["<short phrase>", ...],
 "explanation": "<one or two plain sentences in the same language as the message>"}"""

AGENT_PROMPT = """You are role-playing an ordinary, slightly nervous person who \
received a suspicious message, as part of a defensive fraud-research tool.
Rules:
- Reply in the same language as the latest message (English, Hindi or Tamil).
- Keep replies to 1-3 short sentences.
- NEVER share real OTPs, PINs, passwords, card numbers or any personal data. \
Do not invent real-looking credentials.
- Stay cooperative and curious so the sender keeps talking. Ask questions \
that make them reveal where to pay: UPI ID, account number, IFSC, phone \
number, or the link again.
- Never threaten, insult, or escalate. Never give legal or financial advice."""


def is_configured() -> bool:
    return bool(os.getenv("MODEL_API_KEY"))


def model_name() -> str:
    return os.getenv("LLM_MODEL", "muse-spark-1.1")


_client = None


def _get_client():
    global _client
    if _client is None:
        from openai import OpenAI  # imported lazily so the app runs without it

        _client = OpenAI(
            base_url=os.getenv("LLM_BASE_URL", "https://api.meta.ai/v1"),
            api_key=os.getenv("MODEL_API_KEY"),
            timeout=20.0,
            max_retries=1,
        )
    return _client


def _parse_json(text: str) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("no JSON object in model output")
    return json.loads(match.group(0))


def _clean_detection(raw: dict) -> dict:
    score = int(float(raw.get("risk_score", 0)))
    indicators = raw.get("indicators", [])
    if not isinstance(indicators, list):
        indicators = [str(indicators)]
    return {
        "risk_score": max(0, min(100, score)),
        "scam_type": str(raw.get("scam_type", "Other"))[:60],
        "indicators": [str(i)[:100] for i in indicators][:8],
        "explanation": str(raw.get("explanation", ""))[:500],
    }


def detect(message: str) -> dict:
    """Classify a message with the LLM. Raises on any failure."""
    r = _get_client().chat.completions.create(
        model=model_name(),
        messages=[
            {"role": "system", "content": DETECT_PROMPT},
            {"role": "user", "content": message},
        ],
        temperature=0,
    )
    return _clean_detection(_parse_json(r.choices[0].message.content or ""))


def agent_reply(history: list) -> str:
    """Generate the honeypot persona's next reply. Raises on failure."""
    r = _get_client().chat.completions.create(
        model=model_name(),
        messages=[{"role": "system", "content": AGENT_PROMPT}] + history[-12:],
        temperature=0.7,
    )
    text = (r.choices[0].message.content or "").strip()
    if not text:
        raise ValueError("empty reply from model")
    return text[:600]
