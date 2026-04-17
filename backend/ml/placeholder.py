SUSPICIOUS_URL_WORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "password",
    "reset",
    "account",
    "wallet",
    "bank",
    "confirm",
]


def has_suspicious_words(url: str) -> bool:
    normalized_url = url.lower()
    return any(word in normalized_url for word in SUSPICIOUS_URL_WORDS)


def analyze_threat(email: str, url: str) -> dict[str, str | int]:
    """Simple placeholder for future ML model integration."""
    if has_suspicious_words(url):
        return {
            "status": "Phishing",
            "confidence": 92,
            "message": "URL contains suspicious phishing-related keywords.",
        }

    return {
        "status": "Safe",
        "confidence": 12,
        "message": "No suspicious URL keywords found by baseline rules.",
    }
