# SentinelSEBI (SEBI-Shield) — AI-Driven Investor Protection Platform

**Problem Statement:** AI-Driven Detection of Synthetic Media and Phishing Attacks in Securities Markets  
**Submission:** SEBI Securities Market TechSprint

---

## 🏛️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Express Unified API Server                   │
│                        (server.js, port 8000)                    │
├──────────────────┬──────────────────┬───────────────────────────┤
│   JS Engines     │  Python ML       │  Infrastructure            │
│   (always avail) │  (when installed)│                            │
├──────────────────┼──────────────────┼───────────────────────────┤
│ PhishingEngine   │ librosa FFT/MFCC │ SQLite (sentinel.db)       │
│  └ tldts domain  │ ffmpeg-python    │ PBKDF2 + JWT Auth          │
│  └ DNSTwist typo │ resemblyzer      │ RSA-2048 PKI Signing       │
│ EMLParser        │ OpenCV + ELA     │ CERT-In Report Gen         │
│  └ mailparser    │ MediaPipe Face   │ DoT/NPCI Stubs             │
│  └ DKIM verify   │  Mesh (468 pts)  │                            │
│ AudioEngine      │ exifread EXIF    │ Docker Compose             │
│  └ 1024-pt FFT   │                  │                            │
│ MediaEngine      │                  │                            │
│  └ DQT parser    │                  │                            │
│ VideoEngine      │                  │                            │
│  └ MP4 atom parse│                  │                            │
└──────────────────┴──────────────────┴───────────────────────────┘
              ↕ child_process.execFile (ml_bridge.js)
```

**Hybrid Architecture:** Node.js Express is the unified API server. A Python ML microservice (`ml_service.py`) provides production-grade analysis when libraries are installed. JS engines provide instant fallback — no second HTTP server, one `npm start` runs everything.

---

## 🚀 Quick Start

### Option 1: Local Development
```powershell
cd backend
npm install
npm start
# → http://127.0.0.1:8000
```

### Option 2: Docker (Recommended)
```powershell
docker compose up --build
# → http://localhost:8000
```

### Optional: Python ML Libraries
```powershell
cd backend
pip install -r requirements.txt
```

### Chrome/Edge Extension
Load unpacked from `extension/` at `chrome://extensions`.

---

## 🧪 Test Suites
```powershell
cd backend
node --test tests/accuracy.test.js    # Phishing benchmark (100% accuracy)
node --test tests/engines.test.js     # All engine algorithms
node --test tests/regional.test.js    # Hindi/Tamil/Telugu detection
node --test tests/eml.test.js         # RFC 2047 decoders
node --test tests/encryption.test.js  # S/MIME + PGP forensics
```

---

## 🔬 Technical Implementation

### Production Tooling Integrated

| Module | Library | What It Does |
|---|---|---|
| **Phishing** | `tldts` | Proper TLD parsing for `.co.in`, `.gov.in` subdomains |
| **Phishing** | DNSTwist-style engine | Homoglyph, bitsquatting, vowel-swap typosquatting generation |
| **EML** | `mailparser` | Production multipart MIME parser (replaces hand-rolled RFC 2047) |
| **EML** | DKIM Verifier | Structural verification of DKIM-Signature fields (v/d/s/b/bh/h/a) |
| **Audio** | `librosa` | Real FFT spectral flatness, MFCC extraction, ZCR analysis |
| **Audio** | `ffmpeg-python` | Transcode MP3/AAC/OGG/FLAC → WAV before analysis |
| **Audio** | `resemblyzer` | Speaker embedding extraction for voiceprint comparison |
| **Image** | `opencv-python` + `mediapipe` | Face Mesh (468 landmarks), real ELA, spatial consistency |
| **Image** | `exifread` | Structured EXIF tag parsing, manipulation-tool signature detection |
| **Video** | `opencv-python` + `mediapipe` | Temporal face mesh tracking, flicker detection, luminance analysis |
| **PKI** | `jsonwebtoken` | Production JWT session tokens with PBKDF2 password hashing |

### Algorithmic Engines (JS — Always Available)

| Engine | Algorithm | Purpose |
|---|---|---|
| Shannon Entropy | H(X) = -Σ p(x) log₂ p(x) | Obfuscation/encoding detection |
| Levenshtein Distance | Dynamic programming matrix | Typosquatting domain similarity |
| 1024-Point DFT | Σ x(n)·e^(-j2πkn/N) | Audio spectral flatness |
| JPEG DQT Parser | 0xFFDB marker extraction | Quantization table variance |
| MP4 Atom Parser | ftyp/moov/mdat box parsing | Container structure analysis |
| RSA-2048 PKI | SHA-256 + RSA digital signatures | Communication authenticity |

---

## 📌 Honest Scoping

| Capability | Status |
|---|---|
| Real signal processing math | ✅ Shannon entropy, Levenshtein, FFT DSP, DQT variance |
| Production library integration | ✅ mailparser, tldts, librosa, OpenCV, MediaPipe, exifread |
| Multi-lingual phishing detection | ✅ Hindi, Tamil, Telugu, Marathi, Gujarati |
| SQLite persistent database | ✅ Real file storage with users, scans, alerts, takedowns |
| Cryptographic authentication | ✅ PBKDF2 + JWT |
| Neural deepfake classifier | ⏳ MesoNet model slot ready, awaiting checkpoint |
| CERT-In / DoT / NPCI APIs | 🏷️ Transparent institutional stubs |

---

## 📁 Project Structure
```
sebi/
├── backend/
│   ├── server.js              # Unified Express API server
│   ├── db_sqlite.js           # SQLite persistence layer
│   ├── ml_service.py          # Python ML microservice
│   ├── requirements.txt       # Python ML dependencies
│   ├── engines/
│   │   ├── phishing_engine.js # tldts + DNSTwist + Shannon + Levenshtein
│   │   ├── eml_parser.js      # mailparser + DKIM verification
│   │   ├── audio_engine.js    # Hybrid librosa/JS FFT
│   │   ├── media_engine.js    # Hybrid OpenCV+MediaPipe/JS DQT
│   │   ├── video_engine.js    # Hybrid OpenCV temporal/JS MP4 atom
│   │   ├── verify_engine.js   # RSA-2048 PKI registry
│   │   └── ml_bridge.js       # Python ↔ Node.js bridge
│   ├── tests/                 # Node.js test:runner suites
│   └── python_legacy/         # Deprecated Python backend (reference only)
├── frontend/                  # Web console (static HTML/CSS/JS)
├── extension/                 # Chrome/Edge browser extension
├── Dockerfile                 # Multi-stage Node+Python build
├── docker-compose.yml         # One-command deployment
└── README.md
```
