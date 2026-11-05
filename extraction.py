"""Deterministic extraction of scam intelligence (regex-based, no LLM).

Extraction is intentionally rule-based so results are reproducible and
cannot be hallucinated by a model.
"""
import re

UPI_RE = re.compile(r"\b[a-zA-Z0-9._\-]{2,64}@[a-zA-Z]{2,32}\b(?!\.[a-zA-Z])")
URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"']+"
    r"|\b(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd)/[^\s<>\"']+",
    re.IGNORECASE,
)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}(?!\d)")
ACCOUNT_RE = re.compile(r"(?<!\d)\d{9,18}(?!\d)")
IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")

_TRAILING = ".,;:!?)]}'\""


def _dedupe(items):
    seen, out = set(), []
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def extract(text: str) -> dict:
    """Return extracted intelligence from one message."""
    urls = [u.rstrip(_TRAILING) for u in URL_RE.findall(text)]

    phones = []
    for m in PHONE_RE.findall(text):
        digits = re.sub(r"\D", "", m)[-10:]
        phones.append(digits)

    # Remove URL text so digits inside links aren't read as accounts/UPI.
    scrubbed = URL_RE.sub(" ", text)
    upi_ids = UPI_RE.findall(scrubbed)

    phone_set = set(phones)
    accounts = []
    for m in ACCOUNT_RE.findall(scrubbed):
        if m[-10:] in phone_set and len(m) in (10, 12):
            continue  # it's a phone number, not an account
        accounts.append(m)

    return {
        "upi_ids": _dedupe(upi_ids),
        "phone_numbers": _dedupe(phones),
        "bank_accounts": _dedupe(accounts),
        "ifsc_codes": _dedupe(IFSC_RE.findall(text)),
        "phishing_links": _dedupe(urls),
    }


def merge(base: dict, new: dict) -> dict:
    """Merge two intel dicts, de-duplicating values."""
    keys = set(base) | set(new)
    return {k: _dedupe(list(base.get(k, [])) + list(new.get(k, []))) for k in keys}


def empty() -> dict:
    return {
        "upi_ids": [],
        "phone_numbers": [],
        "bank_accounts": [],
        "ifsc_codes": [],
        "phishing_links": [],
    }


def mask(value: str) -> str:
    """Mask a sensitive value for logs: keep first 2 and last 2 chars."""
    if len(value) <= 5:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]
