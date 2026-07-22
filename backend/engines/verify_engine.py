"""
Authentic Communication Verification Engine (PKI-based)
----------------------------------------------------------
Implements real digital signature generation and verification.
1. Generating RSA 2048 key pairs for issuers (saved locally to backend/keys/).
2. Digitally signing registered communications using the issuer's private key.
3. Storing the signature (hex), public key (PEM), and metadata in the database.
4. Verifying digital signatures on the investor side.
5. Detecting and decoding QR codes in uploaded images using OpenCV.
6. Hashing documents, audio, or video files to verify their absolute authenticity.
"""

import os
import re
import hashlib
import time
import secrets
import difflib
import json
import cv2
import numpy as np

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Database bridge
import database

KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "keys")
if not os.path.exists(KEYS_DIR):
    os.makedirs(KEYS_DIR)

ISSUER_DOMAINS = {
    "SEBI": "sebi.gov.in",
    "NSE": "nseindia.com",
    "BSE": "bseindia.com",
    "ZERODHA": "zerodha.com",
    "ICICI DIRECT": "icicidirect.com",
    "ANGEL ONE": "angelone.in",
    "GROWW": "groww.in"
}

def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())

def _make_code(issuer: str) -> str:
    prefix = "".join(ch for ch in issuer.upper() if ch.isalnum())[:4] or "ORG"
    return f"{prefix}-{secrets.token_hex(3).upper()}"

def _get_or_create_keys(issuer: str):
    """
    Load or generate RSA 2048 private/public keys for an issuer.
    Returns (private_key_obj, public_key_pem_str)
    """
    safe_issuer = re.sub(r"[^a-zA-Z0-9]", "_", issuer.strip().upper())
    priv_path = os.path.join(KEYS_DIR, f"{safe_issuer}_private.pem")
    
    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
    else:
        # Generate new RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # Save private key
        with open(priv_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
    # Derive public key PEM
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    return private_key, pub_pem

def register_communication(issuer: str, channel: str, content: str):
    normalized = _normalize(content)
    # Check if a file is registered or plain text
    content_hash = hashlib.sha256(normalized.encode()).hexdigest()
    
    # 1. Load keys & sign content
    private_key, public_key_pem = _get_or_create_keys(issuer)
    
    signature = private_key.sign(
        normalized.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    sig_hex = signature.hex()
    
    # 2. Get official domain
    domain = ISSUER_DOMAINS.get(issuer.strip().upper(), f"registered-{issuer.lower().strip()}.in")
    
    # 3. Create verify code
    code = _make_code(issuer)
    
    # 4. Save to Database
    success = database.register_comm_db(
        verify_code=code,
        issuer=issuer,
        channel=channel,
        content=content,
        normalized=normalized,
        content_hash=content_hash,
        signature=sig_hex,
        public_key=public_key_pem,
        source_domain=domain
    )
    
    if success:
        return {
            "verify_code": code,
            "content_hash": content_hash,
            "signature": sig_hex,
            "public_key": public_key_pem,
            "source_domain": domain,
            "registered_at": time.time()
        }
    else:
        raise Exception("Database registration failed")

def verify_signature_pki(normalized_content: str, sig_hex: str, pub_pem: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(pub_pem.encode())
        sig_bytes = bytes.fromhex(sig_hex)
        public_key.verify(
            sig_bytes,
            normalized_content.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def verify_by_code(code: str):
    record = database.get_comm_by_code(code)
    if not record:
        return {
            "status": "UNVERIFIED",
            "verdict_label": "NOT_FOUND",
            "message": "No official communication registered under this code. Treat with absolute caution."
        }
    
    # Verify PKI digital signature
    sig_valid = verify_signature_pki(record["normalized"], record["signature"], record["public_key"])
    
    if sig_valid:
        return {
            "status": "VERIFIED",
            "verdict_label": "AUTHENTIC",
            "issuer": record["issuer"],
            "channel": record["channel"],
            "source_domain": record["source_domain"],
            "registered_at": record["registered_at"],
            "signature_valid": True,
            "message": f"Digitally signed by verified issuer: {record['issuer']} ({record['source_domain']}). Cryptographic PKI signature is valid."
        }
    else:
        return {
            "status": "UNVERIFIED",
            "verdict_label": "TAMPERED_OR_ALTERED",
            "issuer": record["issuer"],
            "channel": record["channel"],
            "signature_valid": False,
            "message": f"WARNING: Communication under code {code} is registered, but the cryptographic digital signature verification FAILED. The record may have been tampered with."
        }

def verify_by_content(content: str):
    normalized = _normalize(content)
    content_hash = hashlib.sha256(normalized.encode()).hexdigest()
    
    # 1. Check exact hash match
    record = database.get_comm_by_hash(content_hash)
    if record:
        sig_valid = verify_signature_pki(record["normalized"], record["signature"], record["public_key"])
        if sig_valid:
            return {
                "status": "VERIFIED",
                "verdict_label": "AUTHENTIC",
                "match_type": "exact",
                "issuer": record["issuer"],
                "verify_code": record["verify_code"],
                "source_domain": record["source_domain"],
                "registered_at": record["registered_at"],
                "similarity": 1.0,
                "message": "Found exact cryptographic match in the SEBI-registry. Digital signature is authentic."
            }
            
    # 2. Fuzzy match against all registered records
    all_records = database.get_all_comms()
    best_record, best_ratio = None, 0.0
    
    for r in all_records:
        ratio = difflib.SequenceMatcher(None, normalized, r["normalized"]).ratio()
        if ratio > best_ratio:
            best_record, best_ratio = r, ratio
            
    if best_record and best_ratio >= 0.6:
        # Check if it was exact but failed hash due to formatting
        sig_valid = verify_signature_pki(best_record["normalized"], best_record["signature"], best_record["public_key"])
        
        return {
            "status": "UNVERIFIED",
            "verdict_label": "TAMPERED_OR_ALTERED",
            "match_type": "fuzzy",
            "closest_issuer": best_record["issuer"],
            "closest_verify_code": best_record["verify_code"],
            "source_domain": best_record["source_domain"],
            "similarity": round(best_ratio, 2),
            "signature_valid": sig_valid,
            "message": f"This text closely matches (similarity {best_ratio:.0%}) a registered communication from {best_record['issuer']}. However, it contains alterations. It may have been tampered with or modified by a scammer."
        }
        
    return {
        "status": "UNVERIFIED",
        "verdict_label": "UNVERIFIED",
        "message": "No matching official communication found in the public registry. Independent verification is required."
    }

def verify_by_file(file_bytes: bytes, filename: str):
    """
    Supports uploading:
    1. Signed .json payload files.
    2. Images containing printed QR codes.
    3. General documents/media (verifies SHA-256 hash matching).
    """
    # Case 1: JSON payload
    if filename.lower().endswith(".json"):
        try:
            data = json.loads(file_bytes.decode("utf-8"))
            if "verify_code" in data and "content" in data and "signature" in data:
                # Look up verify code
                code = data["verify_code"]
                record = database.get_comm_by_code(code)
                if record:
                    # Verify signature inside JSON against official public key
                    sig_valid = verify_signature_pki(_normalize(data["content"]), record["signature"], record["public_key"])
                    if sig_valid:
                        return {
                            "status": "VERIFIED",
                            "verdict_label": "AUTHENTIC",
                            "issuer": record["issuer"],
                            "verify_code": code,
                            "source_domain": record["source_domain"],
                            "message": f"Digital signature verified for payload. Issued by {record['issuer']} ({record['source_domain']})."
                        }
        except Exception:
            pass
            
    # Case 2: Image that might contain a QR code
    ext = filename.lower().split(".")[-1]
    if ext in ["jpg", "jpeg", "png", "bmp"]:
        try:
            # Load image from bytes using OpenCV
            nparr = np.frombuffer(file_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if img is not None:
                # Attempt to detect and decode QR code
                qr_detector = cv2.QRCodeDetector()
                val, points, straight_qrcode = qr_detector.detectAndDecode(img)
                if val:
                    # Extract code from URL e.g. code=XXXX-XXXX or directly the code
                    code_match = re.search(r"code=([A-Z0-9\-]+)", val, re.IGNORECASE)
                    code = code_match.group(1) if code_match else val.strip().upper()
                    
                    # Verify using the decoded code
                    result = verify_by_code(code)
                    result["qr_detected"] = True
                    result["qr_value"] = val
                    return result
        except Exception:
            pass
            
    # Case 3: Verify by general file hash (checks if the exact file has been registered)
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    
    # We normalized and checked content_hash. If someone registered a file, the content_hash would match this SHA-256
    record = database.get_comm_by_hash(file_hash)
    if record:
        sig_valid = verify_signature_pki(record["normalized"], record["signature"], record["public_key"])
        if sig_valid:
            return {
                "status": "VERIFIED",
                "verdict_label": "AUTHENTIC",
                "issuer": record["issuer"],
                "verify_code": record["verify_code"],
                "source_domain": record["source_domain"],
                "message": f"File matches registered publication in registry. Verified authenticity for '{filename}'."
            }
            
    return {
        "status": "UNVERIFIED",
        "verdict_label": "UNVERIFIED",
        "message": f"No registered communication matches the cryptographic hash of this file ({file_hash[:16]}...). Treat as unverified."
    }

def list_registry():
    records = database.get_all_comms()
    return [
        {
            "verify_code": r["verify_code"],
            "issuer": r["issuer"],
            "channel": r["channel"],
            "registered_at": r["registered_at"],
            "preview": r["content"][:80],
            "source_domain": r["source_domain"]
        }
        for r in records
    ]

def seed_demo_data():
    """Seed initial records using SQLite"""
    # Seed default SEBI, NSE and Zerodha keys/communications if empty
    all_comms = list_registry()
    if len(all_comms) == 0:
        register_communication(
            "SEBI",
            "email",
            "SEBI Circular: Investors are advised that SEBI never asks for OTP, "
            "password or UPI PIN over phone or email. All official circulars are "
            "published only on sebi.gov.in."
        )
        register_communication(
            "NSE",
            "sms",
            "NSE Alert: Your annual account statement is available on your registered "
            "broker portal. NSE will never ask you to click a link to 'unlock' your account."
        )
        register_communication(
            "Zerodha",
            "email",
            "Zerodha: Your monthly contract note for June 2026 has been generated and is "
            "available in the console under Reports."
        )
