# SentinelSEBI (SEBI-Shield) — AI Investor Protection Platform

**Problem Statement:** AI-Driven Detection of Synthetic Media and Phishing Attacks in Securities Markets  
**SEBI Securities Market TechSprint Submission**

---

## 🚀 Quick Start (Single Unified Backend)

### 1. Install & Launch Unified Express Server
```powershell
cd backend
npm install
npm start
```

### 2. Access Web Console & Extension
- **Web App Console:** Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.
- **Chrome / Edge Extension:** Load unpacked from `extension/` directory at `chrome://extensions`.

### 3. Run Automated Unit Tests
```powershell
cd backend
node --test tests/engines.test.js
node --test tests/regional.test.js
node --test tests/eml.test.js
node --test tests/encryption.test.js
```

---

## 🔬 Core Architectural Refactoring Highlights

1. **100% Unified Node.js Express API Server ([server.js](file:///c:/Users/Rohan%20Ambathi/Downloads/sebi/backend/server.js)):**
   - Single unified server serving all 22+ API routes across Dashboard, Scanners, Verification PKI, Alerts, Legal Takedowns, and Social Monitoring.
2. **Persistent JSON Database Store ([db_manager.js](file:///c:/Users/Rohan%20Ambathi/Downloads/sebi/backend/db_manager.js)):**
   - Thread-safe file-backed storage (`data/db.json`). State persists across server restarts. No fake stat padding offsets.
3. **Honest Signal Processing:**
   - Real JPEG Quantization Table (DQT 0xFFDB) & EXIF Header Parser (`media_engine.js`).
   - Real WAV PCM Header & Zero-Crossing Rate (ZCR) / RMS Amplitude Analyzer (`audio_engine.js`).
   - Real MP4 Container Atom & Temporal Frame Delta Analyzer (`video_engine.js`).
   - Real RFC 2047 MIME Base64/Quoted-Printable Decoders & Encryption Forensics (`eml_parser.js`).
4. **1-Click CERT-In, DoT & NPCI Legal Enforcement Hub:**
   - Generates Section 70B IT Act 2000 CERT-In incident notices, Department of Telecommunications (DoT) DNS blocking directives, and NPCI DPIP VPA account freeze orders directly from the Web Console UI.
