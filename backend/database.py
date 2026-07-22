import sqlite3
import os
import time
import json

DB_FILE = os.path.join(os.path.dirname(__file__), "sentinel.db")

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    # Delete db if it is corrupted, or just create tables if they don't exist
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    
    # 2. Registry table (PKI signed communications)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS registry (
            verify_code TEXT PRIMARY KEY,
            issuer TEXT NOT NULL,
            channel TEXT NOT NULL,
            content TEXT NOT NULL,
            normalized TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            public_key TEXT NOT NULL,
            source_domain TEXT NOT NULL,
            registered_at REAL NOT NULL
        )
    """)
    
    # 3. Scans table (forensic / phishing audit trail)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content_type TEXT NOT NULL, -- 'text', 'image', 'audio', 'video'
            text_or_filename TEXT NOT NULL,
            sender TEXT,
            channel TEXT,
            risk_score INTEGER NOT NULL,
            verdict TEXT NOT NULL,
            explanation TEXT NOT NULL, -- JSON string of flags/findings
            created_at REAL NOT NULL
        )
    """)
    
    # 4. Alerts table (Warnings feed)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL, -- 'deepfake', 'phishing', 'fake_audio', 'social', 'market_alert'
            description TEXT NOT NULL,
            severity TEXT NOT NULL, -- 'low', 'medium', 'high', 'critical'
            created_at REAL NOT NULL
        )
    """)
    
    # 5. Reports table (SEBI action panel)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            evidence_summary TEXT NOT NULL,
            status TEXT NOT NULL, -- 'PENDING_REVIEW', 'INVESTIGATING', 'TAKEDOWN_ISSUED', 'DISMISSED'
            created_at REAL NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)
    
    # Seed default users if they don't exist
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("investor", "investor123", "investor"))
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ("sebi_admin", "sebi123", "sebi_admin"))
    
    # Seed initial alerts if empty
    cursor.execute("SELECT COUNT(*) FROM alerts")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO alerts (title, category, description, severity, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            "Surge in Deepfake Videos Impersonating Stock Advisors",
            "deepfake",
            "Scammers are using AI face-swap technology to create fake videos of well-known financial influencers promoting penny stocks on Instagram and Telegram. SEBI advises investors to verify credentials on the official registry.",
            "critical",
            time.time() - 3600 * 4
        ))
        cursor.execute("""
            INSERT INTO alerts (title, category, description, severity, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            "Phishing Campaign Mimicking Major Brokerage KYC Portals",
            "phishing",
            "Urgent SMS messages warning that trading accounts will be locked unless Aadhaar/PAN details are updated on 'lookalike' domains are circulating. Verify the sender domain name.",
            "high",
            time.time() - 3600 * 24
        ))
        cursor.execute("""
            INSERT INTO alerts (title, category, description, severity, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            "Fake Voice Memos Mimicking Executive Announcements",
            "fake_audio",
            "Audio clips mimicking listed company CEOs announcing major acquisition deals or earnings beats have been spotted. Always double-check official exchange filings.",
            "medium",
            time.time() - 3600 * 48
        ))
        
    # Seed some sample scans to populate dashboard charts initially
    cursor.execute("SELECT COUNT(*) FROM scans")
    if cursor.fetchone()[0] == 0:
        # We can seed 10-15 mock scans for beautiful visual graphs
        scans_data = [
            ("text", "Urgent NSE account update required", "support@nse-verify.org", "email", 85, "CRITICAL", "Urgency language + credential harvesting + spoofed domain"),
            ("image", "ceo_announcement_leak.png", "", "image", 65, "LIKELY_MANIPULATED", "High ELA noise variance on text boxes, metadata missing"),
            ("text", "Your Zerodha contract note is ready", "noreply@zerodha.com", "email", 0, "LOW", "No threat signatures detected"),
            ("audio", "sunil_singhania_tip.wav", "", "audio", 90, "CRITICAL", "FFT spectrum shows voice-cloning high-frequency suppression"),
            ("video", "kamath_deepfake_bse.mp4", "", "video", 75, "HIGH", "Face boundary instability and Laplacian sharpness mismatch"),
            ("text", "Double your money in 7 days guaranteed!", "wealth@quickgain.in", "whatsapp", 55, "HIGH", "Investment scam phrases + Telegram group link"),
            ("image", "sebi_circular_screenshot.jpg", "", "image", 15, "LIKELY_AUTHENTIC", "EXIF intact, low re-compression error variance"),
            ("audio", "official_rbi_warning.wav", "", "audio", 10, "LIKELY_AUTHENTIC", "Natural harmonic resonance and room tone verified"),
            ("text", "🚨 EMERGENCY ALERT: SEBI chief orders immediate freeze on trading accounts. Click http://sebi-alert-verify.com to verify details.", "@sebi_announcements_fake", "social", 95, "CRITICAL", "Authority impersonation + lookalike domain + urgency flags"),
            ("text", "Guaranteed 100% gains! Join our Telegram VIP trading channel for inside tips on pre-IPO allocations: t.me/insider_stock_wealth", "@wealth_wizard_india", "social", 78, "HIGH", "Investment scam returns + Telegram tip-sharing link"),
            ("text", "NSE scheduled maintenance this Saturday. Standard API connections will resume on Monday morning. No action required.", "@NSEIndiaOfficial", "social", 5, "LOW", "Standard informational notice, official handle")
        ]
        for ctype, name, sender, chan, score, verd, expl in scans_data:
            cursor.execute("""
                INSERT INTO scans (content_type, text_or_filename, sender, channel, risk_score, verdict, explanation, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (ctype, name, sender, chan, score, verd, json.dumps([{"type": "heuristics", "severity": verd.lower(), "detail": expl}]), time.time() - 3600 * 12))
            
            # Auto-report high risk ones
            if score >= 70:
                scan_id = cursor.lastrowid
                cursor.execute("""
                    INSERT INTO reports (scan_id, evidence_summary, status, created_at)
                    VALUES (?, ?, ?, ?)
                """, (scan_id, f"Auto-flagged high-risk {ctype} ({score}/100): {expl}", "PENDING_REVIEW", time.time() - 3600 * 12))
                
    conn.commit()
    conn.close()

# Users management
def add_user(username, password, role):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username, password):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role FROM users WHERE username = ? AND password = ?", (username, password))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"username": row["username"], "role": row["role"]}
    return None

# Scans management
def add_scan(content_type, text_or_filename, sender=None, channel=None, risk_score=0, verdict="LOW", explanation=None):
    if explanation is None:
        explanation = []
    conn = get_db()
    cursor = conn.cursor()
    
    explanation_str = json.dumps(explanation)
    created_at = time.time()
    
    cursor.execute("""
        INSERT INTO scans (content_type, text_or_filename, sender, channel, risk_score, verdict, explanation, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (content_type, text_or_filename, sender, channel, risk_score, verdict, explanation_str, created_at))
    scan_id = cursor.lastrowid
    
    # Auto-generate fraud report for high risk detections (score >= 70)
    if risk_score >= 70:
        summary = f"System auto-reported high-risk {content_type} detected: {text_or_filename[:80]}. Score: {risk_score}/100."
        cursor.execute("""
            INSERT INTO reports (scan_id, evidence_summary, status, created_at)
            VALUES (?, ?, ?, ?)
        """, (scan_id, summary, "PENDING_REVIEW", created_at))
        
        # Also post a public alert for critical risks (score >= 85)
        if risk_score >= 85:
            alert_title = f"Alert: High-risk {content_type.capitalize()} Impersonation Detected"
            alert_desc = f"Sentinel has auto-flagged a high-risk {content_type} containing: '{text_or_filename[:120]}'. Scanned source: {sender or 'unknown'} on channel: {channel or 'direct upload'}. Investors are warned to be cautious."
            cursor.execute("""
                INSERT INTO alerts (title, category, description, severity, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (alert_title, "phishing" if content_type == "text" else "deepfake", alert_desc, "high", created_at))
            
    conn.commit()
    conn.close()
    return scan_id

def get_recent_scans(limit=10):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "content_type": r["content_type"],
            "text_or_filename": r["text_or_filename"],
            "sender": r["sender"],
            "channel": r["channel"],
            "risk_score": r["risk_score"],
            "verdict": r["verdict"],
            "explanation": json.loads(r["explanation"]),
            "created_at": r["created_at"]
        })
    return results

def get_social_scans(limit=10):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE channel = 'social' ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "content_type": r["content_type"],
            "text_or_filename": r["text_or_filename"],
            "sender": r["sender"],
            "channel": r["channel"],
            "risk_score": r["risk_score"],
            "verdict": r["verdict"],
            "explanation": json.loads(r["explanation"]),
            "created_at": r["created_at"]
        })
    return results

def get_dashboard_stats():
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Total count
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]
    
    # 2. Risk counts
    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_score >= 70")
    high_risk = cursor.fetchone()[0]
    
    # 3. Verified count
    cursor.execute("SELECT COUNT(*) FROM registry")
    registered_count = cursor.fetchone()[0]
    
    # 4. Count breakdown by content_type (phishing, deepfake, fake audio, fake social, other)
    cursor.execute("SELECT content_type, COUNT(*) as c FROM scans GROUP BY content_type")
    types_raw = cursor.fetchall()
    
    # 5. Severity distribution
    cursor.execute("SELECT verdict, COUNT(*) as c FROM scans GROUP BY verdict")
    verdicts_raw = cursor.fetchall()
    
    conn.close()
    
    # Map raw counts
    breakdown = {"text": 0, "image": 0, "audio": 0, "video": 0}
    for r in types_raw:
        if r["content_type"] in breakdown:
            breakdown[r["content_type"]] = r["c"]
            
    verdicts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "LIKELY_AUTHENTIC": 0, "SUSPICIOUS": 0, "LIKELY_MANIPULATED": 0}
    for r in verdicts_raw:
        verdicts[r["verdict"]] = r["c"]
        
    return {
        "total_scans": total_scans,
        "high_risk_scans": high_risk,
        "registered_comms": registered_count,
        "breakdown": {
            "phishing_emails": breakdown.get("text", 0),
            "deepfake_videos": breakdown.get("video", 0),
            "fake_audios": breakdown.get("audio", 0),
            "manipulated_images": breakdown.get("image", 0)
        },
        "verdicts": verdicts
    }

# Alerts Feed
def get_alerts(limit=20):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "title": r["title"],
            "category": r["category"],
            "description": r["description"],
            "severity": r["severity"],
            "created_at": r["created_at"]
        })
    return results

def add_alert(title, category, description, severity):
    conn = get_db()
    cursor = conn.cursor()
    created_at = time.time()
    cursor.execute("""
        INSERT INTO alerts (title, category, description, severity, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (title, category, description, severity, created_at))
    conn.commit()
    conn.close()
    return True

# SEBI Fraud Reports
def get_reports():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT reports.id as r_id, reports.evidence_summary, reports.status, reports.created_at,
               scans.id as s_id, scans.content_type, scans.text_or_filename, scans.risk_score, scans.verdict, scans.sender, scans.channel
        FROM reports
        LEFT JOIN scans ON reports.scan_id = scans.id
        ORDER BY reports.created_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        results.append({
            "id": r["r_id"],
            "evidence_summary": r["evidence_summary"],
            "status": r["status"],
            "created_at": r["created_at"],
            "scan": {
                "id": r["s_id"],
                "content_type": r["content_type"],
                "text_or_filename": r["text_or_filename"],
                "risk_score": r["risk_score"],
                "verdict": r["verdict"],
                "sender": r["sender"],
                "channel": r["channel"]
            }
        })
    return results

def update_report_status(report_id, status):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE reports SET status = ? WHERE id = ?", (status, report_id))
    conn.commit()
    conn.close()
    return True

# Public signed communications registry
def register_comm_db(verify_code, issuer, channel, content, normalized, content_hash, signature, public_key, source_domain):
    conn = get_db()
    cursor = conn.cursor()
    registered_at = time.time()
    try:
        cursor.execute("""
            INSERT INTO registry (verify_code, issuer, channel, content, normalized, content_hash, signature, public_key, source_domain, registered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (verify_code, issuer, channel, content, normalized, content_hash, signature, public_key, source_domain, registered_at))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_comm_by_code(code):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM registry WHERE verify_code = ?", (code.strip().upper(),))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def get_comm_by_hash(content_hash):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM registry WHERE content_hash = ?", (content_hash,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def get_all_comms():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM registry ORDER BY registered_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# Helper to reset registry & database to fresh seeded state
def reset_database():
    if os.path.exists(DB_FILE):
        try:
            os.remove(DB_FILE)
        except OSError:
            pass
    init_db()

# Auto-initialize database on import
init_db()
