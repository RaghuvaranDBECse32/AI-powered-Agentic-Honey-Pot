"""Rule-based scam detection used as a fallback when no LLM is available.

Includes a small set of Hindi and Tamil keywords. This is a heuristic, not
a trained classifier, and the score it returns is illustrative.
"""

# (indicator label, weight, keywords)
RULES = [
    ("Urgency / pressure", 20,
     ["urgent", "immediately", "today", "last chance", "within 24",
      "तुरंत", "உடனடியாக"]),
    ("Account block / suspension threat", 25,
     ["blocked", "suspended", "freeze", "deactivated", "बंद", "முடக்க"]),
    ("Requests OTP / PIN / password", 30,
     ["otp", "pin", "password", "cvv", "ओटीपी", "ஓடிபி"]),
    ("Asks for payment / fee", 25,
     ["pay", "fee", "transfer", "send money", "upi", "processing charge"]),
    ("Contains a link to click", 20,
     ["http://", "https://", "www.", "click", "bit.ly"]),
    ("KYC / bank verification lure", 20,
     ["kyc", "verify", "bank", "account", "खाता", "கணக்கு"]),
    ("Prize / lottery lure", 25,
     ["lottery", "winner", "prize", "reward", "cashback", "congratulations"]),
    ("Delivery / customs fee lure", 15,
     ["parcel", "delivery", "customs", "courier"]),
]

SCAM_TYPES = [
    ("OTP theft", ["otp", "ओटीपी", "ஓடிபி"]),
    ("Bank account block", ["blocked", "suspended", "freeze", "बंद", "முடக்க"]),
    ("KYC fraud", ["kyc"]),
    ("Lottery / prize", ["lottery", "winner", "prize", "congratulations"]),
    ("Delivery fee", ["parcel", "delivery", "customs", "courier"]),
    ("Payment request", ["upi", "pay", "fee", "transfer"]),
]


def analyze(message: str) -> dict:
    text = message.lower()
    score, indicators = 0, []
    for label, weight, words in RULES:
        if any(w in text for w in words):
            score += weight
            indicators.append(label)
    score = min(score, 100)

    scam_type = "Other"
    for name, words in SCAM_TYPES:
        if any(w in text for w in words):
            scam_type = name
            break
    if score < 40:
        scam_type = "Not a clear scam"

    explanation = (
        "Rule-based check found: " + ", ".join(indicators) + "."
        if indicators else "No common scam indicators were found."
    )
    return {
        "risk_score": score,
        "scam_type": scam_type,
        "indicators": indicators,
        "explanation": explanation,
    }


FALLBACK_REPLIES = [
    "Oh no, is my account really in trouble? Which bank is this from, "
    "and what is the official reference number?",
    "I'm not very good with this. Can you tell me exactly where I should "
    "send it? Please share the UPI ID or account details.",
    "I want to be careful. Can you resend the payment details and the "
    "link once more? The first one did not open.",
    "Okay, I am ready to proceed. Which name will show on the payment "
    "so I know it is correct?",
]


def fallback_reply(turn: int) -> str:
    return FALLBACK_REPLIES[(turn - 1) % len(FALLBACK_REPLIES)]
