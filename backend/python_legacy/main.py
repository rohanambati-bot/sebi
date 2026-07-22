"""
SentinelSEBI Backend
=====================
FastAPI service powering the Sentinel AI Investor Protection Platform.
Includes endpoints for:
1. /auth/*       — user authentication and role switching
2. /phishing/*   — text and link phishing detection
3. /verify/*     — issuer communications registry, file verification, QR detection
4. /media/*      — image forensics, audio frequency checking, video deepfake analysis
5. /dashboard/*  — stats counters, recent analyses logs
6. /alerts/*     — public warnings & threat alerts feed
7. /reports/*    — SEBI incident response & takedown panel
"""

import os
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

import database
from engines import phishing_engine, verify_engine, media_engine, audio_engine, video_engine

app = FastAPI(title="SentinelSEBI API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Seed demo data in the SQLite registry
verify_engine.seed_demo_data()


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/auth/login")
def login(req: LoginRequest):
    user = database.verify_user(req.username, req.password)
    if not user:
        raise HTTPException(401, "Invalid username or password")
    
    # Return a basic token encoding the role and username
    token = f"sentinel_token_{user['role']}_{user['username']}"
    return {
        "access_token": token,
        "role": user["role"],
        "username": user["username"]
    }


# ---------------------------------------------------------------------------
# Module 1: Phishing / impersonation detection
# ---------------------------------------------------------------------------

class PhishingRequest(BaseModel):
    text: str
    sender: str = ""
    channel: str = "email"  # email | sms | whatsapp | social


@app.post("/phishing/analyze")
def analyze_phishing(req: PhishingRequest):
    if not req.text or not req.text.strip():
        raise HTTPException(400, "text is required")
        
    result = phishing_engine.analyze_text(req.text, req.sender)
    result["channel"] = req.channel
    
    # Log scan to DB
    database.add_scan(
        content_type="text",
        text_or_filename=req.text,
        sender=req.sender,
        channel=req.channel,
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        explanation=[{
            "type": f.get("type", "phishing_signature"),
            "severity": f.get("severity", "medium"),
            "detail": f.get("detail", "")
        } for f in result["flags"]]
    )
    
    return result


# ---------------------------------------------------------------------------
# Module 2: Authenticity verification registry
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    issuer: str
    channel: str
    content: str


class VerifyCodeRequest(BaseModel):
    code: str


class VerifyContentRequest(BaseModel):
    content: str


@app.post("/verify/register")
def register(req: RegisterRequest):
    try:
        record = verify_engine.register_communication(req.issuer, req.channel, req.content)
        return {
            "verify_code": record["verify_code"],
            "content_hash": record["content_hash"],
            "signature": record["signature"],
            "public_key": record["public_key"],
            "source_domain": record["source_domain"]
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to register: {e}")


@app.post("/verify/by-code")
def verify_code(req: VerifyCodeRequest):
    return verify_engine.verify_by_code(req.code)


@app.post("/verify/by-content")
def verify_content(req: VerifyContentRequest):
    return verify_engine.verify_by_content(req.content)


@app.post("/verify/by-file")
async def verify_file(file: UploadFile = File(...)):
    content = await file.read()
    try:
        return verify_engine.verify_by_file(content, file.filename)
    except Exception as e:
        raise HTTPException(400, f"Error verifying file: {e}")


@app.get("/verify/registry")
def registry():
    return verify_engine.list_registry()


# ---------------------------------------------------------------------------
# Module 3: Forensic media scans (image, audio, video)
# ---------------------------------------------------------------------------

_LAST_PREVIEWS = {}

@app.post("/media/analyze-image")
async def analyze_image(file: UploadFile = File(...)):
    content = await file.read()
    try:
        result, preview_png = media_engine.analyze_image(content)
    except Exception as e:
        raise HTTPException(400, f"Could not process image: {e}")
        
    _LAST_PREVIEWS[file.filename] = preview_png
    result["preview_url"] = f"/media/preview/{file.filename}"
    
    # Log scan to DB
    database.add_scan(
        content_type="image",
        text_or_filename=file.filename,
        sender="Upload",
        channel="file",
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        explanation=[{
            "type": "image_forensics",
            "severity": "medium" if result["risk_score"] < 55 else "high",
            "detail": e
        } for e in result["evidence"]]
    )
    
    return result


@app.get("/media/preview/{filename}")
def get_preview(filename: str):
    png = _LAST_PREVIEWS.get(filename)
    if not png:
        raise HTTPException(404, "No preview available")
    return Response(content=png, media_type="image/png")


@app.post("/media/analyze-audio")
async def analyze_audio(file: UploadFile = File(...)):
    content = await file.read()
    try:
        result = audio_engine.analyze_audio(content, file.filename)
    except Exception as e:
        raise HTTPException(400, f"Could not process audio: {e}")
        
    # Log scan to DB
    database.add_scan(
        content_type="audio",
        text_or_filename=file.filename,
        sender="Upload",
        channel="file",
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        explanation=[{
            "type": "audio_forensics",
            "severity": "medium" if result["risk_score"] < 60 else "high",
            "detail": e
        } for e in result["evidence"]]
    )
    
    return result


@app.post("/media/analyze-video")
async def analyze_video(file: UploadFile = File(...)):
    content = await file.read()
    try:
        result = video_engine.analyze_video(content, file.filename)
    except Exception as e:
        raise HTTPException(400, f"Could not process video: {e}")
        
    # Log scan to DB
    database.add_scan(
        content_type="video",
        text_or_filename=file.filename,
        sender="Upload",
        channel="file",
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        explanation=[{
            "type": "video_forensics",
            "severity": "medium" if result["risk_score"] < 60 else "high",
            "detail": e
        } for e in result["evidence"]]
    )
    
    return result


# ---------------------------------------------------------------------------
# Dashboard and Stats
# ---------------------------------------------------------------------------

@app.get("/dashboard/stats")
def dashboard_stats():
    return database.get_dashboard_stats()


@app.get("/dashboard/recent")
def dashboard_recent():
    return database.get_recent_scans()


# ---------------------------------------------------------------------------
# Alerts Feed
# ---------------------------------------------------------------------------

class AlertCreateRequest(BaseModel):
    title: str
    category: str
    description: str
    severity: str

@app.get("/alerts/feed")
def alerts_feed():
    return database.get_alerts()

@app.post("/alerts/create")
def create_alert(req: AlertCreateRequest):
    success = database.add_alert(req.title, req.category, req.description, req.severity)
    return {"status": "success" if success else "failed"}


# ---------------------------------------------------------------------------
# SEBI Reports Control
# ---------------------------------------------------------------------------

class ReportStatusRequest(BaseModel):
    report_id: int
    status: str

@app.get("/reports/list")
def list_reports():
    return database.get_reports()

@app.post("/reports/status")
def update_report_status(req: ReportStatusRequest):
    success = database.update_report_status(req.report_id, req.status)
    return {"status": "success" if success else "failed"}


# ---------------------------------------------------------------------------
# Social Media Monitor
# ---------------------------------------------------------------------------

@app.get("/social/feed")
def get_social_feed():
    return database.get_social_scans(limit=10)

_INGESTION_POOL = [
    {
        "text": "WARNING: SCAM ALERT! Telegram channels using my name 'Sunil Singhania' to run investment advisory services are 100% FRAUDULENT. I never run such channels.",
        "sender": "@SunilSinghaniaOfficial"
    },
    {
        "text": "Guaranteed IPO allotment tip! Double your money with our pre-IPO broker pool allocation of Groww shares. Join Telegram for sure shot 100% profits.",
        "sender": "@WealthWizardIPOTips"
    },
    {
        "text": "NSE Chief Announcement: Emergency systems upgrade completed successfully. Standard trading API endpoints are verified as authentic.",
        "sender": "@NSEIndiaOfficial"
    },
    {
        "text": "SEBI URGENT UPDATE: All trading accounts will be frozen within 24 hours under new KYC compliance regulation. Click sebi-kyc-verify-portal.net to update PAN.",
        "sender": "@sebi_kyc_compliance"
    }
]

_ingest_index = 0

@app.post("/social/ingest")
def ingest_social():
    global _ingest_index
    post = _INGESTION_POOL[_ingest_index % len(_INGESTION_POOL)]
    _ingest_index += 1
    
    # Run through phishing/impersonation scorer
    result = phishing_engine.analyze_text(post["text"], post["sender"])
    
    # Log scan to DB as social scan
    database.add_scan(
        content_type="text",
        text_or_filename=post["text"],
        sender=post["sender"],
        channel="social",
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        explanation=[{
            "type": f.get("type", "phishing_signature"),
            "severity": f.get("severity", "medium"),
            "detail": f.get("detail", "")
        } for f in result["flags"]]
    )
    
    return {
        "text": post["text"],
        "sender": post["sender"],
        "channel": "social",
        "risk_score": result["risk_score"],
        "verdict": result["verdict"],
        "explanation": result["flags"]
    }



# ---------------------------------------------------------------------------
# System Management
# ---------------------------------------------------------------------------

@app.post("/system/reset")
def system_reset():
    database.reset_database()
    verify_engine.seed_demo_data()
    return {"status": "Database successfully reset to clean seeded states."}


@app.get("/health")
def health():
    return {"status": "ok"}
