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

### Interactive API Documentation (Swagger UI)
Access interactive Swagger UI documentation at: **http://127.0.0.1:8000/api-docs**

### Brand Watch — Proactive CT-Log Typosquat Monitoring
Flips detection from reactive to proactive by monitoring Certificate Transparency (CT) logs for newly issued TLS certificates matching homoglyph and typosquat variants of protected capital market brands (`zerodha.com`, `groww.in`, `sebi.gov.in`, etc.) before phishing campaigns launch.

---


## 🔐 Authentication & Authorization

Endpoints are split by whether the action makes an assertion about someone else.

| Access | Endpoints | Rationale |
|---|---|---|
| **Public** | `/phishing/*`, `/media/*`, `/verify/by-code`, `/verify/by-content`, `/verify/by-file`, `/dashboard/*`, `/alerts/feed`, `/reports/list` | Investor protection tooling must work without an account |
| **Admin only** | `/reports/cert-in-takedown`, `/reports/status`, `/reports/dot-dns-block`, `/reports/npci-vpa-freeze`, `/alerts/create`, `/verify/register`, `/social/ingest`, `/system/reset`, `/audit/*` | These generate legal notices, publish public fraud accusations, or assert issuer authenticity |

```powershell
# Obtain a token
curl -X POST http://127.0.0.1:8000/auth/login `
  -H "Content-Type: application/json" `
  -d '{"username":"admin","password":"<YOUR_SEEDED_ADMIN_PASSWORD>"}'

# Use it
curl -X POST http://127.0.0.1:8000/reports/cert-in-takedown `
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" `
  -d '{"targetDomain":"scam.example"}'
```

**Configuration.** Set `JWT_SECRET` (32+ chars). The server refuses to start without it when `NODE_ENV=production`; in development it generates an ephemeral secret per process, so tokens do not survive a restart. Seeded default passwords are for local development only and are overridable via `SEED_ADMIN_PASSWORD`, `SEED_SEBI_PASSWORD`, and `SEED_INVESTOR_PASSWORD`. Rotate them before any non-local deployment.


**Security Posture & Defensive Controls.**
- **Helmet Security Headers:** `helmet()` middleware protects against XSS, clickjacking, MIME sniffing, and header disclosure (`contentSecurityPolicy: false` for dev build with CDN assets).
- **Rate Limiting:** Public POST endpoints are protected by `express-rate-limit` per-IP buckets (30 req/min for text analysis, 10 req/min for media analysis).
- **Input Length Caps:** Free-text payloads are capped at 50,000 characters with 400 responses above that limit to prevent regex DOS and DB bloat.
- **CORS Policy:** Unrestricted in development mode; in `NODE_ENV=production`, origin is locked down to `process.env.CORS_ORIGIN`.
- **Persistent ML Microservice:** `ml_service.py --serve` runs as a long-running subprocess over stdin/stdout JSON-RPC, loading heavy ML models (librosa, opencv, mediapipe) once at startup instead of cold-starting per request.


### API Endpoint Reference

All 49 routes in `server.js`, grouped by feature area.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| **Authentication** | | | |
| `POST` | `/auth/login` | Public | PBKDF2 password verification, returns signed JWT |
| `GET` | `/auth/me` | Auth | Returns current user identity and role |
| **Phishing Analysis** | | | |
| `POST` | `/phishing/analyze` | Public | Analyze text for phishing signals, typosquatting, scam language |
| `POST` | `/phishing/upload-eml` | Public | Parse `.eml` file: MIME, DKIM, Received-chain forensics, IOCs |
| **Media Forensics** | | | |
| `POST` | `/media/analyze-image` | Public | DQT variance, EXIF extraction, ELA (Python: OpenCV + MediaPipe) |
| `POST` | `/media/analyze-audio` | Public | 1024-pt FFT, ZCR, spectral flatness (Python: librosa + resemblyzer) |
| `POST` | `/media/analyze-video` | Public | MP4 atom parsing, temporal flicker (Python: OpenCV temporal mesh) |
| `GET` | `/media/preview/:filename` | Public | Serve media preview assets |
| **Authenticity Verification (PKI)** | | | |
| `POST` | `/verify/register` | Admin | Register official communication with RSA-2048 signature |
| `POST` | `/verify/by-code` | Public | Verify communication by verification code |
| `GET` | `/verify/by-code/:code` | Public | Verify communication by code (GET variant) |
| `POST` | `/verify/by-content` | Public | Fuzzy-match text against registered communications |
| `POST` | `/verify/by-file` | Public | Fuzzy-match uploaded file against registered communications |
| `GET` | `/verify/registry` | Public | List all registered authentic communications |
| `POST` | `/verify/check-text` | Public | Levenshtein fuzzy-match text (alias) |
| **Dashboard** | | | |
| `GET` | `/dashboard/stats` | Public | Live SQLite aggregate counts (scans, alerts, takedowns) |
| `GET` | `/dashboard/recent` | Public | Last 10 scans with verdicts |
| `GET` | `/dashboard/graph-network` | Public | Full IOC graph nodes and edges for visualization |
| **IOC Graph & Campaigns** | | | |
| `GET` | `/graph/stats` | Public | Graph node/edge/campaign counts |
| `GET` | `/graph/campaigns` | Public | List all campaigns with member counts |
| `GET` | `/graph/campaigns/:id` | Public | Campaign detail with all member indicators |
| `GET` | `/graph/ioc/:type/:value/scans` | Public | "How do you know?" — scans that sighted a given IOC |
| `POST` | `/graph/rebuild-campaigns` | Admin | Force recompute connected-component clustering |
| **Enrichment (RDAP · DNS · CT)** | | | |
| `GET` | `/enrichment/status` | Public | Queue depth and processing state |
| `GET` | `/enrichment/domain/:domain` | Public | Cached enrichment data for a domain |
| `POST` | `/enrichment/enqueue` | Admin | Manually enqueue a domain for enrichment |
| **Cross-Case Correlation** | | | |
| `GET` | `/correlation/matches` | Public | Voiceprint, pHash, and template similarity matches |
| `POST` | `/correlation/recompute` | Admin | Recompute all cross-case similarity scores |
| **Interoperability & Export** | | | |
| `GET` | `/export/stix` | Public | STIX 2.1 bundle with deterministic IDs |
| `GET` | `/export/misp/:campaignId` | Public | MISP event export for a campaign |
| `GET` | `/export/dossier/:campaignId` | Admin | Full investigation dossier with limitations section |
| `POST` | `/export/attack-mapping` | Public | MITRE ATT&CK technique mapping for flags |
| **Alerts** | | | |
| `GET` | `/alerts/feed` | Public | Active alerts feed |
| `POST` | `/alerts/create` | Admin | Publish a new investor alert |
| **Reports & Regulatory** | | | |
| `GET` | `/reports/list` | Public | List all reports and takedown notices |
| `GET` | `/reports/takedowns` | Public | List takedown notices |
| `POST` | `/reports/status` | Admin | Update report/takedown status |
| `POST` | `/reports/cert-in-takedown` | Admin | Generate CERT-In Section 70B takedown notice |
| `POST` | `/reports/dot-dns-block` | Admin | Submit DoT DNS block request (institutional stub) |
| `POST` | `/reports/npci-vpa-freeze` | Admin | Submit NPCI VPA freeze request (institutional stub) |
| **Social Intelligence** | | | |
| `GET` | `/social/feed` | Public | Social media intelligence feed |
| `POST` | `/social/ingest` | Admin | Ingest social media post for analysis |
| **System & Audit** | | | |
| `POST` | `/system/reset` | Admin | Reset database to clean state |
| `GET` | `/audit/log` | Admin | Tamper-evident audit log entries |
| `GET` | `/audit/verify-evidence` | Admin | Verify evidence hash chain integrity |
| `GET` | `/audit/evidence/:sha256` | Admin | Find all scans that submitted a given evidence artifact |
| `GET` | `/audit/verify` | Admin | Verify audit log hash chain integrity |
| `GET` | `/ml-status` | Public | Check Python ML service availability |
| **Brand Watch (Proactive CT-Log)** | | | |
| `GET` | `/brandwatch/watchlist` | Public | List protected brand targets and generated typosquat variant counts |
| `POST` | `/brandwatch/scan` | Admin | Trigger CT-log Certificate Transparency scan for brand variants |
| `GET` | `/brandwatch/alerts` | Public | Feed of proactive typosquat & CT-log threat alerts |

| `GET` | `*` | Public | SPA fallback — serves frontend |

## 🧾 Audit Trail

Every mutating action appends to `audit_log` with the actor, source IP, user agent, target, outcome, and a SHA-256 hash covering both the entry and its predecessor's hash. `GET /audit/verify` recomputes the chain and reports the first break.

```powershell
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8000/audit/verify
```

Scope: this detects in-place edits and deletions, proven by tests in `tests/audit.test.js`. It does **not** prove the log was not rewritten wholesale by someone with write access to the database file. Independent time/existence proof requires an external anchor (RFC 3161 timestamp authority), which is not yet implemented.

## 🧪 Test Suites
```powershell
cd backend
npm test                     # Full suite (176 tests)

node --test tests/accuracy.test.js    # Phishing benchmark — see caveat below
node --test tests/engines.test.js     # All engine algorithms
node --test tests/regional.test.js    # Hindi/Tamil/Telugu detection
node --test tests/eml.test.js         # RFC 2047 decoders
node --test tests/encryption.test.js  # S/MIME + PGP forensics
node --test tests/auth.test.js        # Auth enforcement & RBAC
node --test tests/audit.test.js       # Hash chain & tamper detection
node --test tests/migration.test.js   # Legacy schema migration
node --test tests/phase1_forensics.test.js  # Received-chain parsing, IOC extraction, sender spoofing
node --test tests/evidence.test.js    # Evidence retention & chain of custody
node --test tests/phase2_graph.test.js      # IOC graph, correlation & campaign clustering
node --test tests/phase3_enrichment.test.js # SSRF guard, rate limits, enrichment cache
node --test tests/phase4_correlation.test.js # Voiceprint, pHash, template matching
node --test tests/phase5_export.test.js     # STIX 2.1, MISP, ATT&CK, dossier
```

**Benchmark caveat.** The reported 100% accuracy is measured on 10 hand-labelled messages that are also the development set — it is not a held-out benchmark and should not be read as a generalization estimate. See `docs/EVALUATION.md`. A previously known evasion — inserting a percentage between words (`"Guaranteed 500% returns"`) — has been fixed; the regex now tolerates intervening non-word tokens. The remaining narrow gap is multi-word alphabetic phrases between qualifier and noun, which requires NLP-level parsing.

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
| Cryptographic authentication | ✅ PBKDF2 + JWT, enforced on all privileged routes |
| Role-based authorization | ✅ Admin/investor separation on regulatory endpoints |
| Tamper-evident audit trail | ✅ Hash-chained, with verification endpoint |
| IOC graph & campaign correlation | ✅ Derived from extracted indicators, not fixtures |
| RDAP / DNS / CT enrichment | ✅ Behind an SSRF guard; disabled by default |
| Voiceprint & perceptual-hash matching | ⚠️ Implemented, thresholds uncalibrated |
| STIX 2.1 / MISP / ATT&CK export | ✅ Deterministic ids, no invented coverage |
| Neural deepfake classifier | ⏳ MesoNet model slot ready, awaiting checkpoint |
| CERT-In / DoT / NPCI APIs | 🏷️ Transparent institutional stubs |
| Held-out accuracy benchmark | ❌ Current metrics are development-set only |
| Attacker attribution | ❌ Detection only — see Attribution Scope |

### Attribution Scope

The platform detects synthetic media and phishing, and — as of Phase 1 — extracts and retains the infrastructure-level evidence needed to investigate who is behind an attack. The distinction below matters for how output should be read:

- **Infrastructure attribution** (originating IP, sender forensics, UPI VPA/phone/wallet/Telegram IOCs, evidence hashing, campaign correlation, registrar/DNS/CT enrichment, cross-case similarity matching) — implemented across Phases 1–5.
- **Identity attribution** (the natural person behind the above) — out of scope by design. It requires legal process against a registrar, ISP, bank, or exchange. No amount of analysis here substitutes for that.

Deliberately excluded: visitor device fingerprinting, Tor de-anonymization, active scanning of attacker infrastructure, non-consensual private-group scraping, and any identity claim resting on IP alone (CGNAT and VPNs make it inadmissible standalone).

### Phase 1 — Evidence Capture & Chain of Custody

**Email forensics** (`backend/engines/eml_parser.js`). Every `.eml` upload now yields:
- The full `Received:` chain, parsed hop by hop, with a best-effort originating IP. Each hop distinguishes an MTA-verified connecting IP from an unverified client-declared HELO string — only the verified kind is trusted when walking the chain.
- `Return-Path`, `Reply-To` (with automatic mismatch-vs-`From` detection — a classic BEC tell), `Message-ID` (its domain often leaks the true sending platform even when `From:` is spoofed), `X-Mailer`, `X-Originating-IP`.
- `Authentication-Results` (SPF/DKIM/DMARC verdicts the receiving MTA already computed — no outbound lookup needed).
- Attachment filename, MIME type, and SHA-256 per attachment.

**IOC extraction** (`backend/engines/ioc_extractor.js`). Extracts and validates UPI VPAs (NPCI handle allowlist), Indian phone numbers, Telegram/WhatsApp links, ETH/TRON/BTC wallet addresses, and paired IFSC + bank account numbers from message text. Every extractor validates structure beyond a bare regex match to hold down false positives.

**Sender-domain spoofing** (`backend/engines/phishing_engine.js`). The `sender` argument, previously accepted and ignored, now drives a real check: a message invoking a regulator/exchange by name while sent from a non-official, non-typosquat domain is flagged `sender_spoofing`.

**Evidence retention** (`backend/evidence.js`). Uploads are hashed (SHA-256 + MD5) and stored content-addressed *before* analysis runs, so the recorded hash provably describes the bytes that were analyzed. Identical resubmissions dedupe to one stored file. `evidence_artifacts` chains each record's hash to its predecessor the same way `audit_log` does — `GET /audit/verify-evidence` (admin-only) detects tampering, and `GET /audit/evidence/:sha256` finds every scan that submitted a given artifact, which is how a reused lure across multiple victims gets discovered.

**No more truncation.** `/phishing/analyze` and `/phishing/upload-eml` persist full message text, extracted URLs/domains, and IOCs to the `scans` table instead of a 120-character label.

Not yet done from the Phase 1 plan: attachment content extraction (macros/embedded URLs inside Office/PDF attachments), real EXIF write-through for images (GPS/DateTimeOriginal/camera serial — currently returned by the Python ML service but not persisted), and request-context logging for the browser extension's reporting path.

### Phase 2 — IOC Graph & Campaign Correlation

`GET /dashboard/graph-network` no longer returns fixture data. Indicators extracted in Phase 1 are now persisted as a queryable entity graph and clustered into campaigns.

**Schema.** `iocs` (one row per distinct indicator, with `sighting_count`, `confidence`, `max_risk_score`), `ioc_links` (edges, each carrying the `evidence_scan_id` that evidenced it), `scan_iocs` (which scan sighted which indicator), and `campaigns`/`campaign_members`.

**Graph derivation** (`backend/engines/graph_engine.js`). Each scan contributes nodes for its sender domain, originating IP, referenced domains, and every IOC. Edges connect infrastructure hubs to payment/contact rails with readable relationships (`COLLECTS_TO`, `CONTACT_FOR`, `SENT_FROM`, `DELIVERED_VIA`). Rails are deliberately *not* linked to each other — two VPAs in one message are related through the message, and a direct VPA↔VPA edge would overstate the evidence.

**Campaign clustering.** Connected components over the edge set, recomputed on each ingest because one new edge can merge two previously separate clusters. Chosen over community detection (Louvain etc.) for explainability: an investigator can always answer "why are these in the same campaign" by walking the edges. A lone unlinked indicator is not promoted to a campaign — a single observation is an observation, not an operation.

**The payoff.** `POST /reports/cert-in-takedown` accepts a `campaignId` and enumerates every correlated indicator in the notice, so one click names all rotated domains, every collection VPA, and each contact channel — instead of the single target an operator happened to type. Verified live: two scans using different domains but the same UPI handle merged into one campaign, and the generated notice named both domains.

New endpoints: `GET /graph/stats`, `GET /graph/campaigns`, `GET /graph/campaigns/:id`, `GET /graph/ioc/:type/:value/scans` (the "how do you know" query), `POST /graph/rebuild-campaigns` (admin).

### Phase 3 — Enrichment (RDAP · DNS · CT)

**Disabled by default.** Set `SENTINEL_ENRICHMENT_ENABLED=true` to enable outbound lookups. The default-off posture is deliberate: fetching attacker infrastructure from the analysis host reveals investigation activity, so in production this should run from isolated egress.

Four lookups, no more — `backend/engines/enrichment_engine.js`:
- **RDAP** → registrar and creation date. Domain age under 30 days is the strongest single free fraud predictor, and the registrar is who a takedown is served on.
- **DNS** → A/AAAA/MX/NS/TXT plus SPF, then reverse-resolve the host.
- **Certificate Transparency** (crt.sh) → SAN lists routinely expose an operator's other domains.
- **DKIM key retrieval** → closes the gap `eml_parser` documents, enabling real signature verification rather than structural checks.

**Security controls** (`backend/net_guard.js`) — this is the first phase with outbound traffic, so the guard came first:
- SSRF protection resolves hostnames *then* validates every resolved address against loopback, RFC1918, CGNAT, link-local (including the cloud metadata endpoint at `169.254.169.254`), ULA, and IPv4-mapped IPv6. Checking the string before resolution is the classic bypass.
- HTTPS only; redirects refused except from a one-host allowlist (the RDAP bootstrap redirector), where the target is re-validated through the full guard and capped at one hop.
- Per-service token-bucket rate limiting, 24h response cache, hard timeouts, and response size caps.
- Fails closed: unparseable input is treated as blocked, never as safe.

Enrichment runs on a queue (`backend/enrichment_queue.js`) off the request path, so an RDAP timeout can never turn a working detection into a failed request.

Endpoints: `GET /enrichment/status`, `GET /enrichment/domain/:domain`, `POST /enrichment/enqueue` (admin).

### Phase 4 — Cross-Case Correlation

Phase 2 links indicators that co-occur; Phase 4 links artifacts that are *similar* across otherwise unconnected reports (`backend/engines/correlation_engine.js`).

- **Voiceprints now persist.** `ml_service.py` previously computed a resemblyzer embedding and reported only its dimensionality before discarding it. The vector is now stored and cosine-matched, so the same voice can be identified across different victims' recordings.
- **Perceptual hashing** (dHash + Hamming distance) matches a reused doctored image even after re-encoding, which SHA-256 cannot do.
- **Template fingerprinting** via character shingles groups messages sharing a scam kit; Jaccard similarity handles near-duplicates.
- **Infrastructure reuse scoring** weights shared nameservers, co-hosting, and same-registrar/same-day registration.

**Thresholds are uncalibrated.** No labelled multi-speaker corpus exists for this dataset, so false-match rates are unmeasured. The API returns `calibrated: false` and every response carries a lead-not-proof caveat. Voice embeddings are treated as biometric data under the DPDP Act. Stylometry was deliberately excluded as weak signal that is easy to challenge.

Endpoints: `GET /correlation/matches`, `POST /correlation/recompute` (admin).

### Phase 5 — Interoperability & Regulatory Output

`backend/engines/export_engine.js` makes output consumable by systems that already exist:

- **STIX 2.1 bundles** (`GET /export/stix`) with deterministic ids so re-export does not duplicate objects in a consumer's store. Indicators with no standard STIX type (UPI VPA, IFSC, wallets) use a custom `pattern_type` rather than being coerced into an ill-fitting standard type. Every relationship preserves its evidencing scan id.
- **MISP export** (`GET /export/misp/:campaignId`), distribution restricted to own-organisation because these are unvalidated leads.
- **MITRE ATT&CK tagging** (`POST /export/attack-mapping`). Unmapped flags return nothing rather than inventing coverage that would mislead an analyst.
- **Investigation dossier** (`GET /export/dossier/:campaignId`, admin) combining indicators, evidencing scans, chain of custody, enrichment provenance, ATT&CK techniques, and a mandatory limitations section that states what the platform does *not* prove.

---

## 📁 Project Structure
```
sebi/
├── backend/
│   ├── server.js              # Unified Express API server
│   ├── auth.js                # JWT middleware, RBAC guards
│   ├── audit.js               # Audit hash-chain primitives
│   ├── evidence.js            # Evidence retention & custody hash-chain
│   ├── net_guard.js           # SSRF guard, rate limiting, safe outbound fetch
│   ├── enrichment_queue.js    # Off-request-path enrichment job queue
│   ├── db_sqlite.js           # SQLite persistence + schema migrations
│   ├── ml_service.py          # Python ML microservice
│   ├── requirements.txt       # Python ML dependencies
│   ├── engines/
│   │   ├── phishing_engine.js # tldts + DNSTwist + Shannon + Levenshtein + sender spoofing
│   │   ├── eml_parser.js      # mailparser + DKIM verification + Received-chain forensics
│   │   ├── ioc_extractor.js   # UPI/phone/Telegram/wallet/IFSC extraction
│   │   ├── graph_engine.js    # IOC graph derivation + campaign clustering
│   │   ├── enrichment_engine.js  # RDAP, DNS, CT, DKIM key retrieval
│   │   ├── correlation_engine.js # Voiceprint, pHash, template similarity
│   │   ├── export_engine.js      # STIX 2.1, MISP, ATT&CK, dossier
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
