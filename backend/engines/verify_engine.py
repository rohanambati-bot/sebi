"""
Authentic Communication Verification Engine
--------------------------------------------
Addresses the second half of the problem statement: "limited mechanisms to
verify that a communication purportedly from SEBI, a stock exchange, a listed
company, or a registered intermediary is genuine".

Design (MVP, hackathon-scope):
1. An issuer (SEBI / exchange / broker / listed co.) registers an outgoing
   official communication. We compute a SHA-256 hash of the normalised
   content + a short human-readable VERIFY-CODE, and store it in a registry
   (in-memory dict here; production = append-only DB / blockchain-anchored
   ledger for tamper-evidence).
2. The VERIFY-CODE is meant to be printed/appended to the real communication
   (e.g. "Verify this message at sebi-verify.gov.in using code SEBI-4F91A2").
3. Any investor who receives a message claiming to be official can:
   a) paste the VERIFY-CODE -> instant AUTHENTIC / NOT FOUND result, or
   b) paste the full message text -> we fuzzy-match it against everything
      in the registry to catch copy-pasted-with-edits phishing forwards,
      and flag partial matches as "TAMPERED / DOES NOT MATCH REGISTRY".
"""

import hashlib
import difflib
import time
import secrets
import re

_REGISTRY = {}  # verify_code -> record


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def _make_code(issuer: str) -> str:
    prefix = "".join(ch for ch in issuer.upper() if ch.isalnum())[:4] or "ORG"
    return f"{prefix}-{secrets.token_hex(3).upper()}"


def register_communication(issuer: str, channel: str, content: str):
    normalized = _normalize(content)
    content_hash = hashlib.sha256(normalized.encode()).hexdigest()
    code = _make_code(issuer)
    record = {
        "verify_code": code,
        "issuer": issuer,
        "channel": channel,
        "content": content,
        "normalized": normalized,
        "content_hash": content_hash,
        "registered_at": time.time(),
    }
    _REGISTRY[code] = record
    return record


def verify_by_code(code: str):
    record = _REGISTRY.get(code.strip().upper())
    if not record:
        return {"status": "NOT_FOUND", "message": "No official communication registered under this code."}
    return {
        "status": "AUTHENTIC",
        "issuer": record["issuer"],
        "channel": record["channel"],
        "registered_at": record["registered_at"],
    }


def verify_by_content(content: str):
    normalized = _normalize(content)
    content_hash = hashlib.sha256(normalized.encode()).hexdigest()

    # exact match
    for record in _REGISTRY.values():
        if record["content_hash"] == content_hash:
            return {
                "status": "AUTHENTIC",
                "match_type": "exact",
                "issuer": record["issuer"],
                "verify_code": record["verify_code"],
                "similarity": 1.0,
            }

    # fuzzy match to catch slightly-edited phishing forwards of real messages
    best_record, best_ratio = None, 0.0
    for record in _REGISTRY.values():
        ratio = difflib.SequenceMatcher(None, normalized, record["normalized"]).ratio()
        if ratio > best_ratio:
            best_record, best_ratio = record, ratio

    if best_record and best_ratio >= 0.6:
        return {
            "status": "TAMPERED_OR_ALTERED",
            "match_type": "fuzzy",
            "closest_issuer": best_record["issuer"],
            "closest_verify_code": best_record["verify_code"],
            "similarity": round(best_ratio, 2),
            "message": "This closely resembles a registered official communication but does not "
                       "match exactly — it may have been edited by a scammer after copying the original.",
        }

    return {
        "status": "UNVERIFIED",
        "message": "No matching official communication found in the registry. "
                    "Treat with caution and verify independently with the issuer.",
    }


def list_registry():
    return [
        {
            "verify_code": r["verify_code"],
            "issuer": r["issuer"],
            "channel": r["channel"],
            "registered_at": r["registered_at"],
            "preview": r["content"][:80],
        }
        for r in _REGISTRY.values()
    ]


def seed_demo_data():
    register_communication(
        "SEBI",
        "email",
        "SEBI Circular: Investors are advised that SEBI never asks for OTP, "
        "password or UPI PIN over phone or email. All official circulars are "
        "published only on sebi.gov.in.",
    )
    register_communication(
        "NSE",
        "sms",
        "NSE Alert: Your annual account statement is available on your registered "
        "broker portal. NSE will never ask you to click a link to 'unlock' your account.",
    )
    register_communication(
        "Zerodha",
        "email",
        "Zerodha: Your monthly contract note for June 2026 has been generated and is "
        "available in the console under Reports.",
    )
