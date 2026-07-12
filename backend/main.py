"""
SentinelSEBI Backend
=====================
FastAPI service powering three modules aligned to the SEBI TechSprint
Problem Statement 1 (AI-Driven Detection of Synthetic Media & Phishing Attacks):

1. /phishing/*  — detects AI-generated / human phishing emails, SMS, WhatsApp
                   messages impersonating SEBI, exchanges, brokers, listed cos.
2. /verify/*    — lets issuers (SEBI/exchange/broker) register genuine
                   communications, and lets investors check authenticity.
3. /media/*     — heuristic forensic scan (ELA + metadata) on images to flag
                   likely-manipulated / AI-generated visuals.

Run:
    pip install -r requirements.txt
    uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

from engines import phishing_engine, verify_engine, media_engine

app = FastAPI(title="SentinelSEBI API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

verify_engine.seed_demo_data()


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
    record = verify_engine.register_communication(req.issuer, req.channel, req.content)
    return {"verify_code": record["verify_code"], "content_hash": record["content_hash"]}


@app.post("/verify/by-code")
def verify_code(req: VerifyCodeRequest):
    return verify_engine.verify_by_code(req.code)


@app.post("/verify/by-content")
def verify_content(req: VerifyContentRequest):
    return verify_engine.verify_by_content(req.content)


@app.get("/verify/registry")
def registry():
    return verify_engine.list_registry()


# ---------------------------------------------------------------------------
# Module 3: Synthetic media / image forensics
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
    return result


@app.get("/media/preview/{filename}")
def get_preview(filename: str):
    png = _LAST_PREVIEWS.get(filename)
    if not png:
        raise HTTPException(404, "No preview available")
    return Response(content=png, media_type="image/png")


@app.get("/health")
def health():
    return {"status": "ok"}
