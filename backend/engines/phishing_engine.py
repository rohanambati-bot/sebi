"""
Phishing / Impersonation Detection Engine
------------------------------------------
Rule-based + linguistic heuristic scoring engine that flags AI-generated /
human-crafted phishing content impersonating SEBI, stock exchanges, brokers
and listed companies.

Why heuristic instead of a black-box model for a hackathon MVP?
- Fully explainable output (each flag is shown to the investor -> builds trust)
- No dependency on external GPU/LLM inference -> works offline, low latency
- Easily extended: swap the scoring function for a trained classifier later
  using the same feature vector produced here (see FEATURES dict).
"""

import re
import difflib
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

OFFICIAL_DOMAINS = [
    "sebi.gov.in", "nseindia.com", "bseindia.com", "cdslindia.com",
    "nsdl.co.in", "zerodha.com", "upstox.com", "groww.in",
    "icicidirect.com", "angelone.in", "hdfcsec.com", "kotaksecurities.com",
    "motilaloswal.com", "5paisa.com", "sharekhan.com",
]

URGENCY_PHRASES = [
    "act now", "immediate action", "account will be suspended", "urgent",
    "within 24 hours", "final notice", "your account has been blocked",
    "verify immediately", "failure to comply", "last warning",
    "click below to avoid", "expire today", "limited time",
]

CREDENTIAL_HARVEST_PHRASES = [
    "otp", "one time password", "upi pin", "atm pin", "cvv", "net banking password",
    "share your pan", "aadhaar number", "login credentials", "update your kyc",
    "click here to verify", "confirm your password", "reset your password now",
]

AUTHORITY_IMPERSONATION_TERMS = [
    "sebi", "securities and exchange board", "nse", "bse", "rbi",
    "income tax department", "stock exchange", "regulator",
]

INVESTMENT_SCAM_TERMS = [
    "guaranteed returns", "risk free", "double your money", "insider tip",
    "sure shot", "100% profit", "exclusive ipo allotment", "pre-ipo shares",
    "join our telegram", "join our whatsapp group for tips",
]

GENERIC_GREETINGS = ["dear customer", "dear user", "dear valued client", "dear sir/madam"]

SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rebrand.ly"]


_URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s,)\]]+"
    r"|\b(?:[a-z0-9-]+\.)+(?:com|net|org|in|co|info|io|gov\.in|co\.in)(?:/[^\s,)\]]*)?\b",
    re.IGNORECASE,
)

_NEGATION_WINDOW = re.compile(
    r"\b(never|does not|doesn't|will not|won't|no need to|don't need to)\b[^.!?]{0,40}$",
    re.IGNORECASE,
)


def _extract_urls(text: str):
    return list(dict.fromkeys(_URL_RE.findall(text)))


def _is_negated(text_lower: str, phrase: str) -> bool:
    """Check if a matched phrase is preceded (within the same clause) by a
    negation like 'SEBI never asks for OTP' — this should NOT be scored as
    a credential-harvesting attempt, it's the opposite: a warning."""
    idx = text_lower.find(phrase)
    if idx == -1:
        return False
    preceding = text_lower[max(0, idx - 40):idx]
    return bool(_NEGATION_WINDOW.search(preceding))


def _domain_of(url: str) -> str:
    if not url.startswith("http"):
        url = "http://" + url
    try:
        return urlparse(url).netloc.lower().replace("www.", "")
    except Exception:
        return ""


def _typosquat_score(domain: str):
    """Return (closest_official_domain, similarity_ratio) for a candidate domain."""
    best_domain, best_ratio = None, 0.0
    for official in OFFICIAL_DOMAINS:
        ratio = difflib.SequenceMatcher(None, domain, official).ratio()
        if ratio > best_ratio:
            best_domain, best_ratio = official, ratio
    return best_domain, best_ratio


def _count_hits(text_lower: str, phrases):
    return [p for p in phrases if p in text_lower]


def analyze_text(text: str, sender: str = ""):
    """
    Analyze a message (email body / SMS / WhatsApp text) and return a
    structured risk report.
    """
    text_lower = text.lower()
    flags = []
    score = 0
    features = {}

    # 1. Urgency / pressure language
    hits = _count_hits(text_lower, URGENCY_PHRASES)
    if hits:
        score += min(20, 6 * len(hits))
        flags.append({
            "type": "urgency_language",
            "severity": "medium",
            "detail": f"Pressure/urgency phrases detected: {', '.join(hits[:4])}",
        })
    features["urgency_hits"] = len(hits)

    # 2. Credential / OTP harvesting requests (skip phrases used in a
    # negated/warning context, e.g. "SEBI never asks for your OTP")
    hits = [ph for ph in _count_hits(text_lower, CREDENTIAL_HARVEST_PHRASES)
            if not _is_negated(text_lower, ph)]
    if hits:
        score += min(30, 10 * len(hits))
        flags.append({
            "type": "credential_harvesting",
            "severity": "high",
            "detail": f"Requests sensitive data: {', '.join(hits[:4])}",
        })
    features["credential_hits"] = len(hits)

    # 3. Regulator / exchange impersonation without official domain backing
    authority_hits = _count_hits(text_lower, AUTHORITY_IMPERSONATION_TERMS)
    features["authority_hits"] = len(authority_hits)

    # 4. Investment scam language ("guaranteed returns" etc.)
    hits = _count_hits(text_lower, INVESTMENT_SCAM_TERMS)
    if hits:
        score += min(25, 8 * len(hits))
        flags.append({
            "type": "investment_scam_language",
            "severity": "high",
            "detail": f"Unrealistic-return / tip-sharing language: {', '.join(hits[:4])}",
        })
    features["scam_hits"] = len(hits)

    # 5. Generic greeting (mass-phishing signature)
    hits = _count_hits(text_lower, GENERIC_GREETINGS)
    if hits:
        score += 5
        flags.append({
            "type": "generic_greeting",
            "severity": "low",
            "detail": "Uses generic greeting instead of your registered name",
        })

    # 6. URL analysis: shorteners + typosquatting
    urls = _extract_urls(text)
    # catch shorteners even if the regex/TLD list missed them (e.g. bit.ly)
    for shortener in SHORTENER_DOMAINS:
        if shortener in text_lower and not any(shortener in u.lower() for u in urls):
            urls.append(shortener)
    suspicious_urls = []
    for url in urls:
        domain = _domain_of(url)
        if not domain:
            continue
        if any(s in domain for s in SHORTENER_DOMAINS):
            suspicious_urls.append({"url": url, "reason": "URL shortener hides real destination"})
            score += 15
            continue
        if domain in OFFICIAL_DOMAINS:
            continue
        closest, ratio = _typosquat_score(domain)
        if 0.75 <= ratio < 1.0:
            suspicious_urls.append({
                "url": url,
                "reason": f"Looks like a lookalike of official domain '{closest}' "
                          f"(similarity {ratio:.0%})",
            })
            score += 25
        elif authority_hits and ratio < 0.75:
            suspicious_urls.append({
                "url": url,
                "reason": "Mentions a regulator/exchange but link is not on any recognised official domain",
            })
            score += 15
    if suspicious_urls:
        flags.append({
            "type": "suspicious_links",
            "severity": "critical" if any("lookalike" in u["reason"] for u in suspicious_urls) else "high",
            "detail": suspicious_urls,
        })
    features["url_count"] = len(urls)
    features["suspicious_url_count"] = len(suspicious_urls)

    # 7. Sender domain check
    if sender:
        sender_domain = sender.split("@")[-1].lower().strip() if "@" in sender else sender.lower()
        if authority_hits and sender_domain not in OFFICIAL_DOMAINS:
            closest, ratio = _typosquat_score(sender_domain)
            if ratio >= 0.7:
                score += 20
                flags.append({
                    "type": "sender_spoofing",
                    "severity": "critical",
                    "detail": f"Sender domain '{sender_domain}' impersonates '{closest}' "
                              f"(similarity {ratio:.0%}) but is not an official domain",
                })

    score = max(0, min(100, score))
    if score >= 70:
        verdict = "CRITICAL"
    elif score >= 45:
        verdict = "HIGH"
    elif score >= 20:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    return {
        "risk_score": score,
        "verdict": verdict,
        "flags": flags,
        "features": features,
        "urls_found": urls,
    }
