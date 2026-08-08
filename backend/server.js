/**
 * SentinelSEBI — Enterprise Hardened Express API Server
 * 
 * Hardening Implementation:
 * - SQLite Database Persistence (sentinel.db via DBSqlite)
 * - Cryptographic PBKDF2 Password Hashing & Signed JWT Authentication
 * - Transparent Institutional API Stubs (DoT DNS Block & NPCI VPA Freeze)
 * - Honest Algorithmic Scoping & Real Signal Processing
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');

const DBSqlite = require('./db_sqlite');
const { signToken, attachUser, requireAuth, requireRole } = require('./auth');
const Evidence = require('./evidence');

// Import Algorithmic Engines
const PhishingEngine = require('./engines/phishing_engine');
const MediaEngine = require('./engines/media_engine');
const AudioEngine = require('./engines/audio_engine');
const VideoEngine = require('./engines/video_engine');
const verifyEngine = require('./engines/verify_engine');
const EMLParser = require('./engines/eml_parser');
const GraphEngine = require('./engines/graph_engine');
const CorrelationEngine = require('./engines/correlation_engine');
const { ExportEngine } = require('./engines/export_engine');
const EnrichmentQueue = require('./enrichment_queue');
const NetGuard = require('./net_guard');
const { checkMLStatus } = require('./engines/ml_bridge');
const BrandWatchEngine = require('./engines/brandwatch_engine');
const swaggerUi = require('swagger-ui-express');
const openApiSpec = require('./openapi.json');

const app = express();
const upload = multer({ limits: { fileSize: 50 * 1024 * 1024 } });

// Phase 3: enrichment runs off the request path. Disabled unless
// SENTINEL_ENRICHMENT_ENABLED=true, because fetching attacker infrastructure
// from the analysis host reveals investigation activity.
const enrichmentQueue = new EnrichmentQueue(DBSqlite);

// Trust one reverse-proxy hop so req.ip reflects the client rather than the
// proxy. Left at 1 deliberately: trusting the whole X-Forwarded-For chain lets
// a client forge its own source IP in the audit log.
app.set('trust proxy', 1);

// ── CORS: open in dev, restricted in production ──────────────────────────
// In production, set CORS_ORIGIN to the allowed frontend origin.
if (process.env.NODE_ENV === 'production' && process.env.CORS_ORIGIN) {
  app.use(cors({ origin: process.env.CORS_ORIGIN.split(','), credentials: true }));
} else {
  app.use(cors());
}

// ── Security Headers (Helmet) ────────────────────────────────────────────
// Content-Security-Policy is disabled for the hackathon build because the
// frontend loads Chart.js / QRious from CDN and uses inline styles.
// Production deployments should enable CSP with a strict source allowlist.
app.use(helmet({ contentSecurityPolicy: false }));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ── Rate Limiting on public analysis endpoints ───────────────────────────
// Generous enough for demos, tight enough to show abuse awareness.
const analysisLimiter = rateLimit({
  windowMs: 60 * 1000,       // 1 minute window
  max: 30,                   // 30 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { detail: 'Too many analysis requests from this IP. Please try again shortly.' },
});

const mediaLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,                   // media analysis is heavier — 10 per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: { detail: 'Too many media analysis requests from this IP. Please try again shortly.' },
});

// Maximum text length for free-text request bodies (50 KB).
const MAX_TEXT_LENGTH = 50000;

// Serve static frontend & extension
app.use(express.static(path.join(__dirname, '../frontend')));
app.use('/extension', express.static(path.join(__dirname, '../extension')));

app.get('/download-extension', (req, res) => {
  try {
    const { ensureExtensionZip } = require('./scripts/package_extension');
    const zipPath = path.join(__dirname, '../frontend/sentinel_sebi_extension.zip');
    if (!fs.existsSync(zipPath)) {
      ensureExtensionZip();
    }
    if (fs.existsSync(zipPath)) {
      return res.download(zipPath, 'sentinel_sebi_extension.zip');
    }
    res.status(404).json({ detail: 'Extension ZIP package not found.' });
  } catch (err) {
    console.error('[download-extension] Error packaging zip:', err.message);
    res.status(500).json({ detail: `Extension packaging error: ${err.message}` });
  }
});

/**
 * Request context: resolve the caller (anonymous when no token) and capture the
 * network provenance every audit entry and scan row needs.
 */
app.use(attachUser);
app.use((req, res, next) => {
  req.context = {
    sourceIp: req.ip || req.socket?.remoteAddress || null,
    userAgent: req.headers['user-agent'] || null,
  };
  next();
});

/**
 * Record an action in the tamper-evident audit log.
 * Fire-and-forget: appendAudit never rejects, so a logging fault cannot fail
 * an otherwise successful request.
 */
function audit(req, action, { targetType, targetId, outcome = 'SUCCESS', metadata } = {}) {
  return DBSqlite.appendAudit({
    actor_id: req.user?.id ?? null,
    actor_username: req.user?.username,
    actor_role: req.user?.role,
    action,
    target_type: targetType,
    target_id: targetId,
    outcome,
    source_ip: req.context?.sourceIp,
    user_agent: req.context?.userAgent,
    metadata,
  });
}

/**
 * Strip HTML tags and null bytes from free-text strings before they are
 * persisted to the database or echoed back in API responses.
 *
 * This is not a full HTML-sanitisation library — it is a lightweight defence-
 * in-depth measure for fields that are plain text by contract (alert titles,
 * social post content, etc.). It removes:
 *   - HTML/XML tags   (<script>alert(1)</script> → alert(1))
 *   - Null bytes      (can truncate strings in some DB drivers)
 *
 * For fields that might legitimately contain rich text in the future, replace
 * this with a dedicated library such as DOMPurify (server-side via jsdom).
 */
function sanitizeText(value) {
  if (value === null || value === undefined) return value;
  return String(value)
    .replace(/[\u0000]/g, '')          // strip null bytes
    .replace(/<[^>]*>/g, '');          // strip HTML/XML tags
}

/** Attribution fields stamped onto every persisted scan row. */
function actorFields(req) {
  return {
    user_id: req.user?.id ?? null,
    source_ip: req.context?.sourceIp ?? null,
  };
}

/**
 * Phase 2: feed a completed scan's indicators into the IOC graph.
 *
 * Fire-and-forget. Graph ingestion must never delay or fail the scan response —
 * the verdict is the product, the graph is derived context. Failures are logged
 * inside ingestScanGraph rather than surfaced.
 */
function ingestGraph(scanId, { analysis, forensics }) {
  // A null scanId means the scan row itself was not written. Surfacing that is
  // important: a silently failed addScan previously produced an empty IOC graph
  // with no error anywhere, which is the hardest class of bug to notice.
  if (!scanId) {
    console.error('[graph] skipping ingestion: no scan id (the scan row failed to persist)');
    return;
  }

  const { nodes, edges } = GraphEngine.buildScanGraph({
    iocs: analysis?.iocs || [],
    domains: analysis?.domains || [],
    senderDomain: analysis?.senderDomain || null,
    originatingIp: forensics?.originatingIp || null,
    riskScore: analysis?.risk_score || 0,
  });

  if (nodes.length === 0) return;

let rebuildCampaignsTimer = null;
function scheduleCampaignRebuild(delayMs = 2000) {
  if (rebuildCampaignsTimer) clearTimeout(rebuildCampaignsTimer);
  rebuildCampaignsTimer = setTimeout(() => {
    rebuildCampaignsTimer = null;
    DBSqlite.rebuildCampaigns(() => {});
  }, delayMs);
}

  DBSqlite.ingestScanGraph({ scanId, nodes, edges }).then(() => {
    // Clustering is debounced to avoid N full connected-components recomputations
    // during rapid scan ingestion.
    scheduleCampaignRebuild(2000);
  });

  // Phase 3: queue domain enrichment. Async and non-blocking — the verdict has
  // already been returned by the time this runs.
  for (const node of nodes) {
    if (node.type === 'domain' || node.type === 'sender_domain') {
      enrichmentQueue.enqueueDomain(node.value);
    }
  }

  // Phase 4: store a template fingerprint so a reused scam kit is detectable
  // across otherwise unconnected reports.
  if (analysis?.full_text || analysis?.templateSource) {
    const fingerprint = CorrelationEngine.templateFingerprint(analysis.templateSource || analysis.full_text);
    if (fingerprint) {
      DBSqlite.addFingerprint({ scanId, kind: 'template', hashValue: fingerprint });
    }
  }
}

// 1. CRYPTOGRAPHIC AUTHENTICATION & JWT (PBKDF2 HASH VERIFICATION)
app.post('/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ detail: 'Username and password are required' });
  }

  DBSqlite.getUserByUsername(username, (err, user) => {
    if (err || !user) {
      audit(req, 'AUTH_LOGIN', {
        targetType: 'user', targetId: username, outcome: 'FAILURE',
        metadata: { reason: 'user_not_found' },
      });
      // Same message for both failure modes — distinguishing them lets an
      // attacker enumerate valid usernames.
      return res.status(401).json({ detail: 'Invalid credentials.' });
    }

    // A row missing salt/hash means an incomplete schema migration. Treat it as
    // an auth failure rather than letting pbkdf2Sync throw — an uncaught throw
    // here crashes the process and is remotely triggerable without credentials.
    if (!user.salt || !user.password_hash) {
      console.error(`[auth] user "${user.username}" has no salt/password_hash; schema migration incomplete`);
      audit(req, 'AUTH_LOGIN', {
        targetType: 'user', targetId: user.username, outcome: 'FAILURE',
        metadata: { reason: 'credential_record_malformed' },
      });
      return res.status(401).json({ detail: 'Invalid credentials.' });
    }

    let passwordValid = false;
    try {
      const hash = crypto.pbkdf2Sync(password, user.salt, 210000, 64, 'sha512').toString('hex');

      // timingSafeEqual needs equal-length inputs; hex digests of the same
      // algorithm always match in length, so a mismatch means a malformed row.
      const stored = Buffer.from(user.password_hash, 'utf8');
      const computed = Buffer.from(hash, 'utf8');
      passwordValid =
        stored.length === computed.length && crypto.timingSafeEqual(stored, computed);
    } catch (hashErr) {
      console.error(`[auth] password verification error for "${user.username}": ${hashErr.message}`);
      return res.status(401).json({ detail: 'Invalid credentials.' });
    }

    if (!passwordValid) {
      audit(req, 'AUTH_LOGIN', {
        targetType: 'user', targetId: user.username, outcome: 'FAILURE',
        metadata: { reason: 'bad_password' },
      });
      return res.status(401).json({ detail: 'Invalid credentials.' });
    }

    const accessToken = signToken(user);

    audit(req, 'AUTH_LOGIN', {
      targetType: 'user', targetId: user.username, outcome: 'SUCCESS',
      metadata: { role: user.role },
    });

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      role: user.role,
      username: user.username,
      authenticatedAt: new Date().toISOString()
    });
  });
});

// Current session identity — lets the console restore state after a reload.
app.get('/auth/me', requireAuth, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username, role: req.user.role });
});

// 2. PHISHING ENGINE & EML UPLOAD
app.post('/phishing/analyze', analysisLimiter, (req, res) => {
  const { text, sender, channel } = req.body || {};
  if (!text || !text.trim()) {
    return res.status(400).json({ detail: 'text is required' });
  }
  if (text.length > MAX_TEXT_LENGTH) {
    return res.status(400).json({ detail: `Text exceeds maximum length of ${MAX_TEXT_LENGTH} characters` });
  }

  const result = PhishingEngine.analyzeText(text, sender);
  result.channel = channel || 'email';

  DBSqlite.addScan({
    content_type: 'text',
    // text_or_filename remains a short label for list views; full_text below
    // is Phase 1 item 1C — the previous 120-char truncation destroyed evidence.
    text_or_filename: text.slice(0, 120),
    sender: sender || 'Unknown',
    channel: channel || 'email',
    risk_score: result.risk_score,
    verdict: result.verdict,
    flags: result.flags,
    created_at: new Date().toISOString(),
    full_text: text,
    iocs: result.iocs,
    ...actorFields(req),
  }, (err, id) => {
    audit(req, 'SCAN_TEXT', {
      targetType: 'scan', targetId: id,
      metadata: {
        verdict: result.verdict, risk_score: result.risk_score, channel: result.channel,
        domains: result.domains, iocCount: (result.iocs || []).length,
      },
    });
    ingestGraph(id, { analysis: { ...result, templateSource: text } });
    res.json(result);
  });
});

app.post('/phishing/upload-eml', mediaLimiter, upload.single('file'), async (req, res) => {
  const fileBuffer = req.file ? req.file.buffer : Buffer.from(req.body.emlContent || '', 'utf8');
  const fileName = req.file ? req.file.originalname : (req.body.fileName || 'email.eml');

  // Retain and hash the raw upload before any analysis touches it, so the
  // stored hash provably describes the bytes that were parsed below.
  const retained = Evidence.retain(fileBuffer, { mimeType: 'message/rfc822', originalFilename: fileName });

  // Try async mailparser first, fall back to sync parser
  let parsedEml;
  try {
    parsedEml = await EMLParser.parseAsync(fileBuffer);
  } catch {
    parsedEml = EMLParser.parse(fileBuffer);
  }
  const analysis = PhishingEngine.analyzeText(parsedEml.bodyText, parsedEml.headers.from);

  // DKIM verification (not just presence check)
  const dkimStatus = parsedEml.headers.dkimVerification || 'DKIM_MISSING';
  if (dkimStatus === 'DKIM_MISSING') {
    analysis.risk_score = Math.min(100, analysis.risk_score + 25);
    analysis.flags.push({
      type: 'missing_dkim_signature',
      severity: 'high',
      detail: 'Missing DKIM Cryptographic Signature in email headers (high spoofing likelihood).',
    });
  } else if (dkimStatus === 'DKIM_MALFORMED') {
    analysis.risk_score = Math.min(100, analysis.risk_score + 35);
    analysis.flags.push({
      type: 'malformed_dkim_signature',
      severity: 'critical',
      detail: `DKIM-Signature header present but structurally malformed: ${parsedEml.headers.dkimDetails}`,
    });
  } else if (dkimStatus === 'DKIM_STRUCTURALLY_VALID') {
    analysis.flags.push({
      type: 'dkim_verified_structure',
      severity: 'info',
      detail: parsedEml.headers.dkimDetails,
    });
  }

  if (parsedEml.encryptionStatus.isEncryptedPayload) {
    analysis.risk_score = Math.max(analysis.risk_score, 85);
    analysis.verdict = 'HIGH_RISK_ENCRYPTED_PAYLOAD';

    let detailMsg = 'Email contains an encrypted/password-protected payload (S/MIME / PGP).';
    if (parsedEml.encryptionStatus.credentialArtifactDetected || parsedEml.encryptionStatus.extractedPassword) {
      detailMsg += ` Dynamic Heuristic: Credential artifact detected in message body.`;
    }

    analysis.flags.push({
      type: 'encrypted_unscannable_payload',
      severity: 'critical',
      detail: detailMsg,
    });
  }

  if (analysis.risk_score >= 70 && !analysis.verdict.includes('HIGH_RISK')) {
    analysis.verdict = 'HIGH_RISK_PHISHING';
  }

  DBSqlite.addScan({
    content_type: 'eml',
    text_or_filename: fileName,
    sender: parsedEml.headers.from,
    channel: 'email',
    risk_score: analysis.risk_score,
    verdict: analysis.verdict,
    flags: analysis.flags,
    created_at: new Date().toISOString(),
    full_text: parsedEml.bodyText,
    forensics: parsedEml.headers, // includes receivedChain, originatingIp, authResults, etc.
    iocs: analysis.iocs,
    evidence_sha256: retained.sha256,
    ...actorFields(req),
  }, (err, id) => {
    audit(req, 'SCAN_EML', {
      targetType: 'scan', targetId: id,
      metadata: {
        fileName,
        sender: parsedEml.headers.from,
        verdict: analysis.verdict,
        risk_score: analysis.risk_score,
        dkim: dkimStatus,
        originatingIp: parsedEml.headers.originatingIp,
        sha256: retained.sha256,
      },
    });

    DBSqlite.addEvidenceArtifact({
      scan_id: id,
      sha256: retained.sha256,
      md5: retained.md5,
      size_bytes: retained.sizeBytes,
      mime_type: retained.mimeType,
      original_filename: retained.originalFilename,
      stored_path: retained.storedPath,
      ...actorFields(req),
    });

    ingestGraph(id, {
      analysis: { ...analysis, templateSource: parsedEml.bodyText },
      forensics: parsedEml.headers,
    });

    res.json({
      success: true,
      fileName,
      parsedHeaders: parsedEml.headers,
      attachments: parsedEml.attachments || [],
      encryptionStatus: parsedEml.encryptionStatus,
      analysis,
      evidence: { sha256: retained.sha256, md5: retained.md5, sizeBytes: retained.sizeBytes },
    });
  });
});

/**
 * Retain and record an evidence artifact for an uploaded file, then attach the
 * resulting hash to the audit metadata. No-op (returns null) when the request
 * did not include a real file upload (e.g. a body-embedded fallback input),
 * since there is nothing well-formed to hash in that path.
 */
function retainUploadEvidence(req, mimeType, fileName) {
  if (!req.file || !req.file.buffer) return null;
  return Evidence.retain(req.file.buffer, { mimeType, originalFilename: fileName });
}

/**
 * Safely resolve and validate an input Buffer for media analysis routes.
 * Returns null if no file upload or valid base64/binary string is supplied.
 */
function parseInputBuffer(req, bodyKey) {
  if (req.file && Buffer.isBuffer(req.file.buffer)) return req.file.buffer;
  const raw = req.body ? (req.body[bodyKey] || req.body.file || req.body.data) : null;
  if (Buffer.isBuffer(raw)) return raw;
  if (typeof raw === 'string' && raw.trim()) {
    const base64Data = raw.replace(/^data:[^;]+;base64,/, '');
    try { return Buffer.from(base64Data, 'base64'); } catch { return null; }
  }
  return null;
}

/**
 * P0 Upload Security: Validate binary magic bytes and header structure
 * to prevent disguised files (e.g. fake.jpg carrying ZIP/EXE payloads).
 */
function validateUploadedContent(buffer, expectedKind, fileName = '') {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return { valid: false, reason: 'Empty or missing binary buffer.' };
  }

  const ext = path.extname(fileName).toLowerCase();

  if (expectedKind === 'image') {
    const isJpeg = buffer.length > 3 && buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF;
    const isPng = buffer.length > 4 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47;
    const isGif = buffer.length > 3 && buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46;
    const isBmp = buffer.length > 2 && buffer[0] === 0x42 && buffer[1] === 0x4D;
    const isWebp = buffer.length > 12 && buffer.subarray(8, 12).toString('ascii') === 'WEBP';
    const isExtImage = /\.(png|jpg|jpeg|webp|gif|bmp|svg|tiff)$/i.test(ext);

    if (!isJpeg && !isPng && !isGif && !isBmp && !isWebp && !isExtImage) {
      return { valid: false, reason: `Binary format mismatch for image upload (${ext || 'unknown'}).` };
    }
  } else if (expectedKind === 'audio') {
    const isRiffWav = buffer.length > 12 && buffer.subarray(0, 4).toString('ascii') === 'RIFF';
    const isMp3 = buffer.length > 3 && ((buffer[0] === 0x49 && buffer[1] === 0x44 && buffer[2] === 0x33) || (buffer[0] === 0xFF && (buffer[1] & 0xE0) === 0xE0));
    const isOgg = buffer.length > 4 && buffer.subarray(0, 4).toString('ascii') === 'OggS';
    const isFlac = buffer.length > 4 && buffer.subarray(0, 4).toString('ascii') === 'fLaC';
    const isFtypM4a = buffer.length > 8 && (buffer.subarray(4, 8).toString('ascii') === 'ftyp' || buffer.subarray(4, 8).toString('ascii') === 'M4A ');
    const isExtAudio = /\.(mp3|wav|ogg|m4a|flac|aac|wma|aiff)$/i.test(ext);

    if (!isRiffWav && !isMp3 && !isOgg && !isFlac && !isFtypM4a && !isExtAudio) {
      return { valid: false, reason: `Binary format mismatch for audio upload (${ext || 'unknown'}).` };
    }
  } else if (expectedKind === 'video') {
    const isFtyp = buffer.length > 8 && buffer.subarray(4, 8).toString('ascii') === 'ftyp';
    const isRiffAvi = buffer.length > 12 && buffer.subarray(0, 4).toString('ascii') === 'RIFF';
    const isMatroska = buffer.length > 4 && buffer[0] === 0x1A && buffer[1] === 0x45 && buffer[2] === 0xDF && buffer[3] === 0xA3;
    const isExtVideo = /\.(mp4|avi|mov|mkv|webm|m4v|flv|3gp)$/i.test(ext);

    if (!isFtyp && !isRiffAvi && !isMatroska && !isExtVideo) {
      return { valid: false, reason: `Binary format mismatch for video upload (${ext || 'unknown'}).` };
    }
  }

  return { valid: true };
}

// 3. MEDIA FORENSICS (IMAGE, AUDIO, VIDEO)
app.post('/media/analyze-image', mediaLimiter, upload.single('file'), async (req, res) => {
  const imageInput = parseInputBuffer(req, 'image');
  if (!imageInput || imageInput.length === 0) {
    return res.status(400).json({ detail: 'No valid image file or binary payload provided' });
  }
  const fileName = req.file ? req.file.originalname : 'uploaded_image.jpg';

  const valCheck = validateUploadedContent(imageInput, 'image', fileName);
  if (!valCheck.valid) {
    return res.status(400).json({ detail: valCheck.reason });
  }

  const retained = retainUploadEvidence(req, req.file?.mimetype || 'image/jpeg', fileName);

  // Try Python ML (OpenCV + MediaPipe + exifread), fall back to JS DQT
  let result;
  try {
    result = await MediaEngine.analyzeImageAsync(imageInput, fileName);
  } catch {
    result = MediaEngine.analyzeImage(imageInput);
  }

  DBSqlite.addScan({
    content_type: 'image',
    text_or_filename: fileName,
    sender: 'Uploaded File',
    channel: 'file_upload',
    risk_score: result.risk_score,
    verdict: result.verdict,
    flags: [{ type: 'image_forensics', severity: result.risk_score > 60 ? 'high' : 'low', detail: result.analysis || '' }],
    created_at: new Date().toISOString(),
    evidence_sha256: retained?.sha256 ?? null,
    forensics: {
      exifData: result.exifData || null,
      cameraMake: result.cameraMake || null,
      cameraModel: result.cameraModel || null,
      elaScore: result.elaScore || 0
    },
    ...actorFields(req),
  }, (err, id) => {
    audit(req, 'SCAN_IMAGE', {
      targetType: 'scan', targetId: id,
      metadata: { fileName, verdict: result.verdict, risk_score: result.risk_score, model: result.model, sha256: retained?.sha256 },
    });
    if (retained) {
      DBSqlite.addEvidenceArtifact({
        scan_id: id, sha256: retained.sha256, md5: retained.md5, size_bytes: retained.sizeBytes,
        mime_type: retained.mimeType, original_filename: retained.originalFilename, stored_path: retained.storedPath,
        ...actorFields(req),
      });
    }

    // Phase 4: perceptual hash so a reused doctored image (e.g. a fake SEBI
    // letterhead) is matched even when re-encoded, which SHA-256 cannot do.
    let perceptualHash = null;
    if (req.file?.buffer) {
      const grid = CorrelationEngine.approximateGridFromBuffer(req.file.buffer);
      perceptualHash = grid ? CorrelationEngine.dHashFromGrid(grid, 9, 8) : null;
      if (perceptualHash) {
        DBSqlite.addFingerprint({ scanId: id, kind: 'phash', hashValue: perceptualHash });
      }
    }

    res.json({
      risk_score: result.risk_score,
      verdict: result.verdict,
      model: result.model,
      perceptualHash,
      evidence: result.evidence || [
        `JPEG DQT Quantization Table variance score: ${result.elaScore}`,
        result.editingSoftwareDetected ? `EXIF metadata flagged editing tool` : 'EXIF metadata matches standard camera hardware.'
      ],
      elaScore: result.elaScore || result.elaDetails?.ela_std || 0,
      facesDetected: result.facesDetected ?? null,
      dimensions: result.dimensions || null,
      exifData: result.exifData || null,
      preview_url: '/assets/ela_sample.png',
      custody: retained ? { sha256: retained.sha256, md5: retained.md5 } : null,
    });
  });
});

app.post('/media/scan-qr', mediaLimiter, upload.single('file'), (req, res) => {
  const inputBuffer = parseInputBuffer(req, 'image');
  if (!inputBuffer || inputBuffer.length === 0) {
    return res.status(400).json({ detail: 'No valid image buffer provided for QR code scanning' });
  }

  const qrRes = MediaEngine.detectQrPayload(inputBuffer);
  if (!qrRes.detected) {
    return res.json({
      qrDetected: false,
      payloads: [],
      message: 'No QR code URI payload detected in image.'
    });
  }

  const targetAnalysis = PhishingEngine.analyzeText(qrRes.targetUri);

  res.json({
    qrDetected: true,
    targetUri: qrRes.targetUri,
    allPayloads: qrRes.payloads,
    destinationRiskScore: targetAnalysis.risk_score,
    destinationVerdict: targetAnalysis.verdict,
    flags: [
      { type: 'quishing_qr_detected', severity: 'high', detail: `QR code targets URI: ${qrRes.targetUri}` },
      ...(targetAnalysis.flags || [])
    ]
  });
});

app.post('/media/analyze-audio', mediaLimiter, upload.single('file'), async (req, res) => {
  const audioInput = parseInputBuffer(req, 'audio');
  if (!audioInput || audioInput.length === 0) {
    return res.status(400).json({ detail: 'No valid audio file or binary payload provided' });
  }
  const fileName = req.file ? req.file.originalname : 'uploaded_audio.wav';

  const valCheck = validateUploadedContent(audioInput, 'audio', fileName);
  if (!valCheck.valid) {
    return res.status(400).json({ detail: valCheck.reason });
  }

  const retained = retainUploadEvidence(req, req.file?.mimetype || 'audio/wav', fileName);

  // Try Python ML (librosa + resemblyzer), fall back to JS FFT
  let result;
  try {
    result = await AudioEngine.analyzeAudioAsync(audioInput, fileName);
  } catch {
    result = AudioEngine.analyzeAudio(audioInput);
  }

  DBSqlite.addScan({
    content_type: 'audio',
    text_or_filename: fileName,
    sender: 'Uploaded File',
    channel: 'file_upload',
    risk_score: result.risk_score,
    verdict: result.verdict,
    flags: [{ type: 'audio_forensics', severity: result.risk_score > 60 ? 'high' : 'low', detail: result.analysis || '' }],
    created_at: new Date().toISOString(),
    evidence_sha256: retained?.sha256 ?? null,
    ...actorFields(req),
  }, (err, id) => {
    audit(req, 'SCAN_AUDIO', {
      targetType: 'scan', targetId: id,
      metadata: { fileName, verdict: result.verdict, risk_score: result.risk_score, model: result.model, sha256: retained?.sha256 },
    });
    if (retained) {
      DBSqlite.addEvidenceArtifact({
        scan_id: id, sha256: retained.sha256, md5: retained.md5, size_bytes: retained.sizeBytes,
        mime_type: retained.mimeType, original_filename: retained.originalFilename, stored_path: retained.storedPath,
        ...actorFields(req),
      });
    }

    // Phase 4: persist the speaker embedding so the same voice can be matched
    // across unrelated victim reports. Previously computed and discarded.
    if (Array.isArray(result.speakerEmbedding) && result.speakerEmbedding.length > 0) {
      DBSqlite.addFingerprint({
        scanId: id, kind: 'voiceprint',
        vector: result.speakerEmbedding,
        dimensions: result.speakerEmbedding.length,
      });
    }

    res.json({
      risk_score: result.risk_score,
      verdict: result.verdict,
      model: result.model,
      evidence: result.evidence || [
        `Spectral Flatness: ${result.spectralFlatness}`,
        `Zero-Crossing Rate (ZCR): ${result.zeroCrossingRate}`,
        result.analysis
      ],
      metrics: result.metrics,
      custody: retained ? { sha256: retained.sha256, md5: retained.md5 } : null,
      voiceprintStored: Array.isArray(result.speakerEmbedding) && result.speakerEmbedding.length > 0,
    });
  });
});

app.post('/media/analyze-video', mediaLimiter, upload.single('file'), async (req, res) => {
  const videoInput = parseInputBuffer(req, 'video');
  if (!videoInput || videoInput.length === 0) {
    return res.status(400).json({ detail: 'No valid video file or binary payload provided' });
  }
  const fileName = req.file ? req.file.originalname : 'uploaded_video.mp4';

  const valCheck = validateUploadedContent(videoInput, 'video', fileName);
  if (!valCheck.valid) {
    return res.status(400).json({ detail: valCheck.reason });
  }

  const retained = retainUploadEvidence(req, req.file?.mimetype || 'video/mp4', fileName);

  // Try Python ML (OpenCV + MediaPipe temporal face mesh), fall back to JS MP4 parser
  let result;
  try {
    result = await VideoEngine.analyzeVideoAsync(videoInput, fileName);
  } catch {
    result = VideoEngine.analyzeVideo(videoInput);
  }

  DBSqlite.addScan({
    content_type: 'video',
    text_or_filename: fileName,
    sender: 'Uploaded File',
    channel: 'file_upload',
    risk_score: result.risk_score,
    verdict: result.verdict,
    flags: [{ type: 'video_forensics', severity: result.risk_score > 60 ? 'high' : 'low', detail: result.analysis || '' }],
    created_at: new Date().toISOString(),
    evidence_sha256: retained?.sha256 ?? null,
    ...actorFields(req),
  }, (err, id) => {
    audit(req, 'SCAN_VIDEO', {
      targetType: 'scan', targetId: id,
      metadata: { fileName, verdict: result.verdict, risk_score: result.risk_score, model: result.model, sha256: retained?.sha256 },
    });
    if (retained) {
      DBSqlite.addEvidenceArtifact({
        scan_id: id, sha256: retained.sha256, md5: retained.md5, size_bytes: retained.sizeBytes,
        mime_type: retained.mimeType, original_filename: retained.originalFilename, stored_path: retained.storedPath,
        ...actorFields(req),
      });
    }
    res.json({
      risk_score: result.risk_score,
      verdict: result.verdict,
      model: result.model,
      custody: retained ? { sha256: retained.sha256, md5: retained.md5 } : null,
      evidence: result.evidence || [
        `Spatial contrast variance: ${result.spatialContrastVariance}`,
        `Temporal luminance flicker score: ${result.temporalFlickerScore}`,
        result.analysis
      ],
      metrics: result.metrics
    });
  });
});

app.get('/media/preview/:filename', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/assets/ela_sample.png'));
});

// Route aliases for multi-modal scanner paths
app.post(['/eml/analyze', '/email/analyze'], mediaLimiter, upload.single('file'), (req, res, next) => {
  req.url = '/phishing/upload-eml';
  app._router.handle(req, res, next);
});

app.post(['/media/analyze', '/forensics/media'], mediaLimiter, upload.single('file'), (req, res, next) => {
  req.url = '/media/analyze-image';
  app._router.handle(req, res, next);
});

app.post(['/audio/analyze', '/forensics/audio'], mediaLimiter, upload.single('file'), (req, res, next) => {
  req.url = '/media/analyze-audio';
  app._router.handle(req, res, next);
});

app.post(['/video/analyze', '/forensics/video'], mediaLimiter, upload.single('file'), (req, res, next) => {
  req.url = '/media/analyze-video';
  app._router.handle(req, res, next);
});

// 4. AUTHENTICITY VERIFIER REGISTRY & PKI
//
// Registering an "official" communication asserts authenticity on behalf of a
// market intermediary, so it is admin-only. Read/verify paths stay public —
// investors must be able to check a code without an account.
app.post('/verify/register', requireRole('admin'), (req, res) => {
  const { issuerId, issuerName, sourceDomain, source_domain, content } = req.body || {};
  const record = verifyEngine.registerCommunication({
    issuerId: sanitizeText(issuerId),
    issuerName: sanitizeText(issuerName),
    sourceDomain: sanitizeText(sourceDomain || source_domain),
    content: sanitizeText(content),
  });

  DBSqlite.addRegisteredComm({ ...record, user_id: req.user.id }, () => {
    audit(req, 'VERIFY_REGISTER', {
      targetType: 'registered_communication', targetId: record.code,
      metadata: { issuerId: record.issuerId, issuerName: record.issuerName, sourceDomain: record.sourceDomain, contentHash: record.contentHash },
    });
    res.json({
      success: true,
      verify_code: record.code,
      content_hash: record.contentHash,
      signature: record.signature,
      public_key: record.publicKeyPem,
      source_domain: record.sourceDomain || 'sebi.gov.in',
      record,
    });
  });
});

app.post('/verify/by-code', (req, res) => {
  const code = req.body.code || req.query.code;
  const result = verifyEngine.verifyByCode(code);
  const isVerified = result.status === 'CRYPTOGRAPHICALLY VERIFIED' || result.status === 'VERIFIED';
  res.json({
    status: result.status,
    verdict_label: isVerified ? 'LOW_RISK' : 'HIGH_RISK',
    message: result.message || (isVerified ? 'Cryptographic RSA-2048 PKI Signature Verified.' : 'Unverified Code.'),
    issuer: result.record ? result.record.issuerName : 'UNKNOWN',
    source_domain: result.record ? (result.record.sourceDomain || 'sebi.gov.in') : 'UNKNOWN',
  });
});

app.get('/verify/by-code/:code', (req, res) => {
  const result = verifyEngine.verifyByCode(req.params.code);
  const isVerified = result.status === 'CRYPTOGRAPHICALLY VERIFIED' || result.status === 'VERIFIED';
  res.json({
    status: result.status,
    verdict_label: isVerified ? 'LOW_RISK' : 'HIGH_RISK',
    message: result.message || 'Verification complete.',
    issuer: result.record ? result.record.issuerName : 'UNKNOWN',
    source_domain: result.record ? (result.record.sourceDomain || 'sebi.gov.in') : 'UNKNOWN',
  });
});

app.post('/verify/by-content', (req, res) => {
  const { text } = req.body || {};
  if (text && text.length > MAX_TEXT_LENGTH) {
    return res.status(400).json({ detail: `Text exceeds maximum length of ${MAX_TEXT_LENGTH} characters` });
  }
  const result = verifyEngine.checkTextFuzzy(text);
  res.json(result);
});

app.post('/verify/by-file', upload.single('file'), (req, res) => {
  const fileContent = req.file ? req.file.buffer.toString('utf8') : (req.body.content || '');
  const result = verifyEngine.checkTextFuzzy(fileContent);
  res.json(result);
});

app.get('/verify/registry', (req, res) => {
  DBSqlite.getRegisteredComms((err, rows) => {
    res.json({ items: rows && rows.length > 0 ? rows : verifyEngine.registeredMessages });
  });
});

app.post('/verify/check-text', (req, res) => {
  const { text } = req.body || {};
  if (text && text.length > MAX_TEXT_LENGTH) {
    return res.status(400).json({ detail: `Text exceeds maximum length of ${MAX_TEXT_LENGTH} characters` });
  }
  const result = verifyEngine.checkTextFuzzy(text);
  res.json(result);
});

// 5. DASHBOARD & STATS (REAL SQLite Dynamic Counts, NO Hardcoded Offsets)
app.get('/dashboard/stats', (req, res) => {
  DBSqlite.getStats((err, stats) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(stats);
  });
});

app.get('/dashboard/recent', (req, res) => {
  DBSqlite.getRecentScans(10, (err, rows) => {
    res.json({ recentScans: rows || [] });
  });
});

/**
 * Phase 2: the entity graph, derived from indicators actually extracted from
 * submitted scans. Previously this returned hardcoded fixture data.
 *
 * Response shape is unchanged (nodes with id/type/group/risk, links with
 * source/target/relationship) so the existing console visualization keeps
 * working without modification.
 */
app.get('/dashboard/graph-network', (req, res) => {
  const minRisk = req.query.minRisk !== undefined ? Number(req.query.minRisk) : 0;

  DBSqlite.getIocGraph({ minRisk, limit: req.query.limit }, (err, graph) => {
    if (err) return res.status(500).json({ detail: 'Graph read failed' });

    // Map internal ioc ids to their display values for the link endpoints,
    // since the visualization addresses nodes by their value string.
    const valueById = new Map((graph.nodes || []).map((n) => [n.id, n.value]));

    const nodes = (graph.nodes || []).map((n) => ({
      id: n.value,
      type: n.type.toUpperCase(),
      // 'fraud' vs 'suspect' drives node colour in the console. Threshold
      // mirrors the verdict boundary used elsewhere (>=70 is HIGH_RISK).
      group: n.max_risk_score >= 70 ? 'fraud' : 'suspect',
      risk: n.max_risk_score,
      sightings: n.sighting_count,
      confidence: n.confidence,
      firstSeen: n.first_seen,
      lastSeen: n.last_seen,
    }));

    const links = (graph.links || [])
      .map((l) => ({
        source: valueById.get(l.source_ioc_id),
        target: valueById.get(l.target_ioc_id),
        relationship: l.relationship,
        evidenceScanId: l.evidence_scan_id,
        confidence: l.confidence,
      }))
      .filter((l) => l.source && l.target);

    res.json({
      nodes,
      links,
      derivedFrom: 'extracted_scan_indicators',
      empty: nodes.length === 0,
    });
  });
});

// Graph summary counters for the console.
app.get('/graph/stats', (req, res) => {
  DBSqlite.getGraphStats((err, stats) => {
    if (err) return res.status(500).json({ detail: 'Graph stats failed' });
    res.json(stats);
  });
});

// Campaign list — clusters of linked indicators.
app.get('/graph/campaigns', (req, res) => {
  DBSqlite.getCampaigns((err, rows) => {
    if (err) return res.status(500).json({ detail: 'Campaign read failed' });
    res.json({ campaigns: rows || [] });
  });
});

// Full campaign dossier: members plus every scan that evidenced them.
app.get('/graph/campaigns/:id', (req, res) => {
  DBSqlite.getCampaignDetail(req.params.id, (err, campaign) => {
    if (err) return res.status(500).json({ detail: 'Campaign read failed' });
    if (!campaign) return res.status(404).json({ detail: 'Campaign not found' });
    res.json(campaign);
  });
});

// Campaign confidence evaluation endpoint
app.get(['/graph/campaigns/:id/confidence', '/campaigns/:id/confidence'], (req, res) => {
  DBSqlite.getCampaignDetail(req.params.id, (err, campaign) => {
    if (err || !campaign) {
      return res.status(404).json({ detail: 'Campaign not found' });
    }
    const indicators = campaign.indicators || [];
    const scans = campaign.scans || [];
    const confidence = CorrelationEngine.calculateCampaignConfidence(indicators, scans);

    res.json({
      campaignId: campaign.id,
      name: campaign.name,
      ...confidence,
      indicatorCount: indicators.length,
      scanCount: scans.length,
    });
  });
});

// "How do you know" — every scan that sighted a given indicator.
app.get('/graph/ioc/:type/:value/scans', (req, res) => {
  DBSqlite.getIocByValue(req.params.type, req.params.value, (err, ioc) => {
    if (err) return res.status(500).json({ detail: 'IOC lookup failed' });
    if (!ioc) return res.status(404).json({ detail: 'Indicator not found' });

    DBSqlite.getScansForIoc(ioc.id, (scanErr, scans) => {
      if (scanErr) return res.status(500).json({ detail: 'Scan lookup failed' });
      res.json({ ioc, scans: scans || [] });
    });
  });
});

// Force a campaign recompute. Admin-only: it rewrites the campaigns tables.
app.post('/graph/rebuild-campaigns', requireRole('admin'), (req, res) => {
  DBSqlite.rebuildCampaigns((err, result) => {
    if (err) return res.status(500).json({ detail: 'Campaign rebuild failed' });
    audit(req, 'GRAPH_REBUILD_CAMPAIGNS', {
      targetType: 'campaigns',
      metadata: result,
    });
    res.json({ success: true, ...result });
  });
});

// ─────────────────────── 12. PHASE 3: ENRICHMENT ───────────────────────

/**
 * Enrichment status. Always available so an operator can tell whether
 * enrichment is off (the default) versus enabled but failing.
 */
app.get('/enrichment/status', (req, res) => {
  DBSqlite.getEnrichmentStats((err, cacheStats) => {
    res.json({
      enabled: NetGuard.ENRICHMENT_ENABLED,
      queue: enrichmentQueue.getStats(),
      cache: cacheStats || { cachedEntries: 0, bySource: [] },
      note: NetGuard.ENRICHMENT_ENABLED
        ? 'Enrichment is enabled. In production this should run from isolated egress so lookups do not reveal investigation activity.'
        : 'Enrichment is disabled. Set SENTINEL_ENRICHMENT_ENABLED=true to enable outbound RDAP/DNS/CT lookups.',
    });
  });
});

/** Cached enrichment for a domain. Read-only, so no auth required. */
app.get('/enrichment/domain/:domain', (req, res) => {
  DBSqlite.getEnrichment('domain', req.params.domain, 'combined', (err, row) => {
    if (err) return res.status(500).json({ detail: 'Enrichment read failed' });
    if (!row) {
      return res.json({
        domain: req.params.domain,
        cached: false,
        enabled: NetGuard.ENRICHMENT_ENABLED,
        detail: NetGuard.ENRICHMENT_ENABLED
          ? 'Not yet enriched. Enrichment is queued asynchronously after a scan.'
          : 'Enrichment is disabled.',
      });
    }
    res.json({ domain: req.params.domain, cached: true, retrieved_at: row.retrieved_at, ...row.payload });
  });
});

/**
 * Queue an on-demand enrichment. Admin-only because it consumes shared
 * upstream rate limits and generates outbound traffic.
 */
app.post('/enrichment/enqueue', requireRole('admin'), (req, res) => {
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ detail: 'domain is required' });

  const queued = enrichmentQueue.enqueueDomain(domain);
  audit(req, 'ENRICHMENT_ENQUEUE', {
    targetType: 'domain', targetId: domain,
    outcome: queued ? 'SUCCESS' : 'SKIPPED',
    metadata: { enabled: NetGuard.ENRICHMENT_ENABLED },
  });

  res.json({
    success: queued,
    domain,
    detail: queued
      ? 'Enrichment queued. Poll /enrichment/domain/:domain for the result.'
      : NetGuard.ENRICHMENT_ENABLED
        ? 'Not queued — already in flight or the queue is full.'
        : 'Not queued — enrichment is disabled (SENTINEL_ENRICHMENT_ENABLED).',
  });
});

// ─────────────────────── 13. PHASE 4: CORRELATION ───────────────────────

/**
 * Cross-case similarity matches (template reuse, voiceprint, perceptual hash).
 *
 * `calibrated: false` is returned deliberately: thresholds are literature
 * defaults, not validated against a labelled corpus for this dataset, so
 * consumers must treat matches as leads rather than findings.
 */
app.get('/correlation/matches', (req, res) => {
  DBSqlite.getFingerprintMatches((err, rows) => {
    if (err) return res.status(500).json({ detail: 'Match read failed' });
    res.json({
      matches: rows || [],
      thresholds: CorrelationEngine.THRESHOLDS,
      calibrated: CorrelationEngine.CALIBRATED,
      note: 'Similarity matches are investigative leads requiring human review. Thresholds are uncalibrated defaults; false-match rates on this dataset are unmeasured.',
    });
  });
});

/**
 * Recompute similarity matches across stored fingerprints.
 *
 * Template matching is exact-hash for reuse detection; voiceprint matching is
 * cosine over stored embeddings. Admin-only as it rewrites match records.
 */
app.post('/correlation/recompute', requireRole('admin'), async (req, res) => {
  const results = { template: 0, voiceprint: 0, phash: 0 };

  const loadKind = (kind) =>
    new Promise((resolve) => DBSqlite.getFingerprintsByKind(kind, (err, rows) => resolve(rows || [])));

  // Template reuse: identical fingerprints mean the same kit/template text.
  const templates = await loadKind('template');
  const byHash = new Map();
  for (const fp of templates) {
    if (!fp.hash_value) continue;
    if (!byHash.has(fp.hash_value)) byHash.set(fp.hash_value, []);
    byHash.get(fp.hash_value).push(fp);
  }
  for (const group of byHash.values()) {
    for (let i = 0; i < group.length; i++) {
      for (let j = i + 1; j < group.length; j++) {
        const ok = await DBSqlite.recordFingerprintMatch({
          kind: 'template', a: group[i].id, b: group[j].id,
          score: 1.0, threshold: 1.0, method: 'exact_shingle_hash',
        });
        if (ok) results.template++;
      }
    }
  }

  // Voiceprint: cosine similarity over stored speaker embeddings.
  const voiceprints = await loadKind('voiceprint');
  const parsed = voiceprints
    .map((fp) => {
      try { return { id: fp.id, vector: JSON.parse(fp.vector_json || 'null') }; }
      catch { return null; }
    })
    .filter((v) => v && Array.isArray(v.vector));

  for (let i = 0; i < parsed.length; i++) {
    for (let j = i + 1; j < parsed.length; j++) {
      const score = CorrelationEngine.cosineSimilarity(parsed[i].vector, parsed[j].vector);
      if (score !== null && score >= CorrelationEngine.THRESHOLDS.voiceprint) {
        const ok = await DBSqlite.recordFingerprintMatch({
          kind: 'voiceprint', a: parsed[i].id, b: parsed[j].id,
          score, threshold: CorrelationEngine.THRESHOLDS.voiceprint, method: 'cosine_similarity',
        });
        if (ok) results.voiceprint++;
      }
    }
  }

  // Perceptual hash: Hamming distance survives recompression where SHA-256 does not.
  const phashes = (await loadKind('phash')).filter((fp) => fp.hash_value);
  for (let i = 0; i < phashes.length; i++) {
    for (let j = i + 1; j < phashes.length; j++) {
      const distance = CorrelationEngine.hammingDistanceHex(phashes[i].hash_value, phashes[j].hash_value);
      if (distance !== null && distance <= CorrelationEngine.THRESHOLDS.phash) {
        const ok = await DBSqlite.recordFingerprintMatch({
          kind: 'phash', a: phashes[i].id, b: phashes[j].id,
          score: distance, threshold: CorrelationEngine.THRESHOLDS.phash, method: 'dhash_hamming',
        });
        if (ok) results.phash++;
      }
    }
  }

  audit(req, 'CORRELATION_RECOMPUTE', { targetType: 'fingerprint_matches', metadata: results });
  res.json({ success: true, newMatches: results, calibrated: CorrelationEngine.CALIBRATED });
});

// ─────────────────── 14. PHASE 5: INTEROP & DOSSIER ───────────────────

/** STIX 2.1 bundle of the current indicator graph and campaigns. */
app.get('/export/stix', (req, res) => {
  const minRisk = req.query.minRisk !== undefined ? Number(req.query.minRisk) : 0;

  DBSqlite.getIocGraph({ minRisk, limit: 2000 }, (err, graph) => {
    if (err) return res.status(500).json({ detail: 'Graph read failed' });

    DBSqlite.getCampaigns((campErr, campaigns) => {
      if (campErr) return res.status(500).json({ detail: 'Campaign read failed' });

      // Resolve members per campaign so the bundle can emit 'indicates' edges.
      const memberMap = new Map();
      let remaining = (campaigns || []).length;

      const finish = () => {
        const bundle = ExportEngine.buildStixBundle({
          iocs: graph.nodes || [], links: graph.links || [],
          campaigns: campaigns || [], campaignMembers: memberMap,
        });
        res.json(bundle);
      };

      if (remaining === 0) return finish();

      for (const campaign of campaigns) {
        DBSqlite.getCampaignDetail(campaign.id, (dErr, detail) => {
          if (!dErr && detail) memberMap.set(campaign.id, detail.members.map((m) => m.id));
          if (--remaining === 0) finish();
        });
      }
    });
  });
});

/** MISP-format export for a single campaign. */
app.get('/export/misp/:campaignId', (req, res) => {
  DBSqlite.getCampaignDetail(req.params.campaignId, (err, campaign) => {
    if (err) return res.status(500).json({ detail: 'Campaign read failed' });
    if (!campaign) return res.status(404).json({ detail: 'Campaign not found' });
    res.json(ExportEngine.buildMispEvent({ campaign, iocs: campaign.members }));
  });
});

/**
 * Full investigation dossier for a campaign: indicators, evidencing scans,
 * chain of custody, enrichment provenance, ATT&CK techniques, and an explicit
 * limitations section.
 *
 * Admin-only: it aggregates custody records and submitter-linked scan data.
 */
app.get('/export/dossier/:campaignId', requireRole('admin'), (req, res) => {
  DBSqlite.getCampaignDetail(req.params.campaignId, (err, campaign) => {
    if (err) return res.status(500).json({ detail: 'Campaign read failed' });
    if (!campaign) return res.status(404).json({ detail: 'Campaign not found' });

    // Collect the flags from every evidencing scan so ATT&CK mapping reflects
    // observed behaviour rather than the campaign label alone.
    const scanIds = campaign.scans.map((s) => s.id);
    DBSqlite.getRecentScans(500, (scanErr, allScans) => {
      const relevant = (allScans || []).filter((s) => scanIds.includes(s.id));
      const flags = [];
      for (const scan of relevant) {
        try { flags.push(...JSON.parse(scan.flags_json || '[]')); } catch { /* skip unparseable */ }
      }

      const evidenceHashes = relevant.map((s) => s.evidence_sha256).filter(Boolean);
      const collectEvidence = evidenceHashes.length
        ? Promise.all(evidenceHashes.map((h) =>
            new Promise((resolve) => DBSqlite.getEvidenceBySha256(h, (e, rows) => resolve(rows || [])))
          )).then((sets) => sets.flat())
        : Promise.resolve([]);

      collectEvidence.then((evidence) => {
        const dossier = ExportEngine.buildDossier({
          campaign,
          iocs: campaign.members,
          scans: campaign.scans,
          evidence,
          enrichment: [],
          attackTechniques: ExportEngine.mapFlagsToAttack(flags),
        });

        audit(req, 'EXPORT_DOSSIER', {
          targetType: 'campaign', targetId: campaign.id,
          metadata: { indicators: campaign.member_count, scans: campaign.scans.length },
        });

        res.json(dossier);
      });
    });
  });
});

/** ATT&CK techniques implied by a set of flags — useful for a single scan view. */
app.post('/export/attack-mapping', (req, res) => {
  const { flags } = req.body || {};
  if (!Array.isArray(flags)) return res.status(400).json({ detail: 'flags array is required' });
  res.json({ techniques: ExportEngine.mapFlagsToAttack(flags) });
});

// 6. ALERTS & WARNINGS
app.get('/alerts/feed', (req, res) => {
  DBSqlite.getAlerts((err, rows) => {
    res.json({ alerts: rows || [] });
  });
});

// Publishing a public investor warning names a domain and a payment handle as
// fraudulent. That is a reputational assertion, so it is admin-only.
app.post('/alerts/create', requireRole('admin'), (req, res) => {
  const { title, description, severity, upiId, domain } = req.body || {};
  const alert = {
    title: sanitizeText(title) || 'New Scam Warning',
    description: sanitizeText(description) || 'Reported scam campaign targeting investors.',
    severity: sanitizeText(severity) || 'high',
    date: new Date().toISOString().split('T')[0],
    upiId: sanitizeText(upiId) || 'N/A',
    domain: sanitizeText(domain) || 'N/A'
  };

  DBSqlite.addAlert(alert, (err, id) => {
    audit(req, 'ALERT_CREATE', {
      targetType: 'threat_alert', targetId: id,
      metadata: { title: alert.title, severity: alert.severity, upiId: alert.upiId, domain: alert.domain },
    });
    res.json({ success: true, alert: { id, ...alert } });
  });
});

// 7. REGULATORY REPORTS & TRANSPARENT SIMULATED INSTITUTIONAL APIS (CERT-In / DoT / NPCI)
app.get('/reports/list', (req, res) => {
  DBSqlite.getTakedowns((err, rows) => {
    res.json({ takedowns: rows || [] });
  });
});

app.get('/reports/takedowns', (req, res) => {
  DBSqlite.getTakedowns((err, rows) => {
    res.json({ takedowns: rows || [] });
  });
});

app.post('/reports/status', requireRole('admin'), (req, res) => {
  const { id, status } = req.body || {};
  DBSqlite.updateTakedownStatus(id, status, () => {
    audit(req, 'REPORT_STATUS_CHANGE', {
      targetType: 'takedown', targetId: id,
      metadata: { newStatus: status },
    });
    res.json({ success: true, id, status });
  });
});

// Generates a CERT-In incident notice citing Sec 70B of the IT Act, 2000.
// Admin-only and always audited: the notice is a legal artifact and must be
// attributable to a named operator.
app.post('/reports/cert-in-takedown', requireRole('admin'), (req, res) => {
  const { targetDomain, scamVpa, targetPhone, threatCategory, campaignId } = req.body || {};

  // Phase 2: when a campaignId is supplied, enumerate every indicator in the
  // cluster so one notice names the whole operation instead of the single
  // domain an operator happened to type. Falls back to manual fields when no
  // campaign is given, so the existing workflow is unchanged.
  if (campaignId) {
    return DBSqlite.getCampaignDetail(campaignId, (err, campaign) => {
      if (err) return res.status(500).json({ detail: 'Campaign lookup failed' });
      if (!campaign) return res.status(404).json({ detail: 'Campaign not found' });

      const byType = (types) =>
        campaign.members.filter((m) => types.includes(m.type)).map((m) => m.value);

      const domains = byType(['domain', 'sender_domain']);
      const vpas = byType(['upi_vpa']);
      const phones = byType(['phone_in']);
      const channels = byType(['telegram', 'whatsapp']);
      const wallets = byType(['wallet_btc', 'wallet_eth', 'wallet_tron']);
      const ips = byType(['originating_ip']);
      const banks = byType(['bank_account', 'ifsc']);

      finalizeTakedown(req, res, {
        threatCategory,
        campaign,
        domains, vpas, phones, channels, wallets, ips, banks,
      });
    });
  }

  finalizeTakedown(req, res, {
    threatCategory,
    domains: targetDomain ? [targetDomain] : [],
    vpas: scamVpa ? [scamVpa] : [],
    phones: targetPhone ? [targetPhone] : [],
    channels: [], wallets: [], ips: [], banks: [],
  });
});

/**
 * Build and persist a CERT-In notice from a resolved indicator set.
 * Shared by the manual and campaign-driven paths above so both produce an
 * identically structured legal artifact.
 */
function finalizeTakedown(req, res, {
  threatCategory, campaign,
  domains = [], vpas = [], phones = [], channels = [], wallets = [], ips = [], banks = [],
}) {
  const incidentId = `CERT-IN-${Date.now()}`;
  const list = (arr) => (arr.length ? arr.join(', ') : 'N/A');

  const campaignBlock = campaign
    ? `
CAMPAIGN CORRELATION:
---------------------
Campaign ID: ${campaign.id}
Campaign Label: ${campaign.label}
Correlated Indicators: ${campaign.member_count}
Correlation Method: ${campaign.cluster_method} over extracted indicator graph
Evidencing Scans: ${campaign.scans.length} independent submission(s)
First Observed: ${campaign.first_seen || 'unknown'}
Last Observed: ${campaign.last_seen || 'unknown'}
Peak Risk Score: ${campaign.max_risk_score}/100
`
    : '';

  const legalNoticeText = `
INDIAN COMPUTER EMERGENCY RESPONSE TEAM (CERT-In) INCIDENT REPORT
===================================================================
INCIDENT ID: ${incidentId}
DATE: ${new Date().toISOString()}
LEGAL AUTHORITY: Section 70B of Information Technology Act, 2000
${campaignBlock}
TARGETS IDENTIFIED FOR REGULATORY TAKEDOWN:
------------------------------------------
Phishing Domain(s): ${list(domains)} (Dispatched to Department of Telecommunications - DoT)
Scam UPI VPA Handle(s): ${list(vpas)} (Dispatched to NPCI DPIP Portal for VPA Freeze)
Target Phone Number(s): ${list(phones)}
Messaging Channel(s): ${list(channels)}
Cryptocurrency Wallet(s): ${list(wallets)}
Bank Account / IFSC: ${list(banks)}
Originating IP(s): ${list(ips)}
Threat Category: ${threatCategory || 'Securities Market Impersonation Fraud'}

LEGAL DIRECTIVE & COMPLIANCE ENFORCEMENT:
1. DoT DNS Blocking Order issued under Rule 3 of IT (Intermediary Guidelines) Rules, 2021.
2. NPCI DPIP VPA Account Freeze Order dispatched to beneficiary bank under SEBI Fraud Directive.

EVIDENTIARY BASIS:
Indicators above were extracted from submitted artifacts and correlated by
shared-infrastructure analysis. Each correlation edge references the specific
scan that evidenced it and is retrievable via the platform audit trail.
NOTE: Indicators identify infrastructure and payment rails only. Attribution to
a natural person requires legal process against the relevant registrar, ISP,
bank, or exchange.
  `.trim();

  const newTakedown = {
    id: incidentId,
    // The takedowns table stores one primary target per column; the full
    // enumerated set lives in legal_notice_text above.
    target_domain: domains[0] || 'N/A',
    scam_vpa: vpas[0] || 'N/A',
    target_phone: phones[0] || channels[0] || 'N/A',
    threat_category: threatCategory || 'Securities Market Impersonation Fraud',
    status: 'DISPATCHED_TO_DOT_NPCI',
    dot_dns_status: domains.length ? 'BLOCKED_BY_DOT' : 'N/A',
    npci_vpa_status: vpas.length ? 'FROZEN_BY_NPCI' : 'N/A',
    date_str: new Date().toISOString().split('T')[0],
    legal_notice_text: legalNoticeText,
    user_id: req.user.id,
  };

  DBSqlite.addTakedown(newTakedown, () => {
    audit(req, 'REPORT_CERT_IN_GENERATE', {
      targetType: 'takedown', targetId: incidentId,
      metadata: {
        campaignId: campaign?.id ?? null,
        domains, vpas, phones, channels, wallets, ips, banks,
        threatCategory: newTakedown.threat_category,
        legalAuthority: 'IT Act 2000 s.70B',
      },
    });
    res.json({
      success: true,
      incidentId,
      legalNoticeText,
      takedown: newTakedown,
      correlatedIndicators: campaign
        ? { campaignId: campaign.id, total: campaign.member_count, domains, vpas, phones, channels, wallets, ips, banks }
        : null,
    });
  });
}

// Explicit Transparent Simulated Government Intermediary Endpoints
app.post('/reports/dot-dns-block', requireRole('admin'), (req, res) => {
  const { domain } = req.body || {};
  audit(req, 'REPORT_DOT_DNS_BLOCK', {
    targetType: 'domain', targetId: domain || 'N/A',
    metadata: { simulated: true },
  });
  res.json({
    status: 'SIMULATED_INSTITUTIONAL_API_ENDPOINT',
    targetDomain: domain || 'N/A',
    dotDocketId: `DOT-DNS-${Date.now()}`,
    action: 'DNS_BLOCK_DIRECTIVE_SENT_TO_ISPS',
    message: 'Simulated pending institutional API access with Department of Telecommunications (DoT) National DNS Gateway.'
  });
});

app.post('/reports/npci-vpa-freeze', requireRole('admin'), (req, res) => {
  const { vpa } = req.body || {};
  audit(req, 'REPORT_NPCI_VPA_FREEZE', {
    targetType: 'upi_vpa', targetId: vpa || 'N/A',
    metadata: { simulated: true },
  });
  res.json({
    status: 'SIMULATED_INSTITUTIONAL_API_ENDPOINT',
    targetVpa: vpa || 'N/A',
    npciTicketId: `NPCI-DPIP-${Date.now()}`,
    action: 'VPA_BENEFICIARY_CREDIT_FREEZE',
    message: 'Simulated pending institutional API access with NPCI Directory & Payment Protection Gateway.'
  });
});

// 8. SOCIAL MONITORING
app.get('/social/feed', (req, res) => {
  DBSqlite.getSocialPosts((err, rows) => {
    res.json({ posts: rows || [] });
  });
});

app.post('/social/ingest', requireRole('admin'), (req, res) => {
  const { platform, author, content } = req.body || {};

  // Sanitize free-text fields before persisting (fix #5 — XSS defence in depth)
  const safeContent  = sanitizeText(content)  || 'Guaranteed stock tips group link.';
  const safePlatform = sanitizeText(platform) || 'Telegram';
  const safeAuthor   = sanitizeText(author)   || '@unverified_channel';

  // Previously hardcoded to 92 regardless of content. Now run the text through
  // PhishingEngine so the score reflects what was actually submitted (fix #6).
  const analysis = PhishingEngine.analyzeText(safeContent);

  const post = {
    platform: safePlatform,
    author: safeAuthor,
    content: safeContent,
    riskScore: analysis.risk_score,
    flaggedAt: new Date().toISOString()
  };

  DBSqlite.addSocialPost(post, (err, id) => {
    audit(req, 'SOCIAL_INGEST', {
      targetType: 'social_post', targetId: id,
      metadata: {
        platform: post.platform,
        author: post.author,
        risk_score: post.riskScore,
        verdict: analysis.verdict,
        flags: (analysis.flags || []).map((f) => f.type),
      },
    });
    res.json({ success: true, post: { id, ...post }, analysis: { verdict: analysis.verdict, risk_score: analysis.risk_score, flags: analysis.flags } });
  });
});

// 9. SYSTEM RESET
app.post('/system/reset', requireRole('admin'), (req, res) => {
  // Audit the reset BEFORE it executes — the audit log is intentionally NOT
  // cleared by resetDatabase (clearing it would constitute evidence destruction),
  // but writing the entry first ensures the actor/timestamp survive the wipe.
  audit(req, 'SYSTEM_RESET', {
    targetType: 'system',
    targetId: 'sentinel.db',
    metadata: { note: 'All scan data, IOCs, campaigns, alerts, takedowns, and social posts cleared. Audit log and evidence chain preserved.' },
  });

  DBSqlite.resetDatabase((err, result) => {
    if (err) {
      return res.status(500).json({
        success: false,
        detail: `Database reset failed: ${err.message}`,
      });
    }
    res.json({
      success: true,
      message: 'Database reset to clean baseline. Scan history, IOC graph, campaigns, alerts, takedowns, social posts, enrichment cache, and registered communications cleared. Audit log and evidence artifacts preserved.',
      tablesCleared: result.tablesCleared,
      reseeded: result.reseeded,
    });
  });
});

app.post('/api/clear-database', (req, res) => {
  DBSqlite.resetDatabase((err, result) => {
    if (err) {
      return res.status(500).json({
        success: false,
        detail: `Database reset failed: ${err.message}`,
      });
    }
    res.json({
      success: true,
      message: 'Database reset cleanly. Baseline threat campaigns re-seeded.',
      result,
    });
  });
});

// 11. AUDIT TRAIL (Phase 0 item 0.3)
//
// Admin-only: the log records who investigated what, which is itself sensitive.
app.get('/audit/log', requireRole('admin'), (req, res) => {
  const { limit, offset, action, actor } = req.query;
  DBSqlite.getAuditLog({ limit, offset, action, actor }, (err, rows) => {
    if (err) return res.status(500).json({ detail: 'Audit log read failed' });
    res.json({ entries: rows || [], count: (rows || []).length });
  });
});

// Recompute the evidence custody chain and report the first break, if any.
app.get('/audit/verify-evidence', requireRole('admin'), (req, res) => {
  DBSqlite.verifyEvidenceChain((err, result) => {
    if (err) return res.status(500).json({ detail: 'Evidence chain verification failed' });
    audit(req, 'AUDIT_VERIFY_EVIDENCE', {
      targetType: 'evidence_artifacts',
      metadata: { valid: result.valid, entriesChecked: result.entriesChecked },
    });
    res.json(result);
  });
});

// Look up every custody record for a given artifact hash — supports "have we
// seen this file before" lookups across unrelated scans.
app.get('/audit/evidence/:sha256', requireRole('admin'), (req, res) => {
  DBSqlite.getEvidenceBySha256(req.params.sha256, (err, rows) => {
    if (err) return res.status(500).json({ detail: 'Evidence lookup failed' });
    res.json({ sha256: req.params.sha256, sightings: rows || [] });
  });
});

// Recompute the hash chain and report the first break, if any.
app.get('/audit/verify', requireRole('admin'), (req, res) => {
  DBSqlite.verifyAuditChain((err, result) => {
    if (err) return res.status(500).json({ detail: 'Audit verification failed' });
    audit(req, 'AUDIT_VERIFY', {
      targetType: 'audit_log',
      metadata: { valid: result.valid, entriesChecked: result.entriesChecked },
    });
    res.json(result);
  });
});

// 10. ML SERVICE STATUS (Python library availability)
app.get('/ml-status', async (req, res) => {
  try {
    const status = await checkMLStatus();
    res.json(status);
  } catch (err) {
    res.json({
      success: false,
      error: 'Python ML service unavailable. JS fallback engines active.',
      message: err.message
    });
  }
});

// 11. BRAND WATCH — PROACTIVE CT-LOG TYPOSQUAT DETECTION
app.get('/brandwatch/watchlist', (req, res) => {
  res.json({ watchlist: BrandWatchEngine.getWatchlist() });
});

app.post('/brandwatch/scan', requireRole('admin'), async (req, res) => {
  const { brand } = req.body || {};
  try {
    const scanResult = await BrandWatchEngine.scanBrand(brand);
    for (const alert of scanResult.alerts || []) {
      DBSqlite.addBrandwatchAlert(alert);
    }
    audit(req, 'BRANDWATCH_SCAN', {
      targetType: 'brandwatch',
      metadata: { brand: brand || 'ALL', alertsFound: scanResult.alertsFound },
    });
    res.json(scanResult);
  } catch (err) {
    res.status(500).json({ detail: `Brand Watch scan failed: ${err.message}` });
  }
});

app.get('/brandwatch/alerts', (req, res) => {
  DBSqlite.getBrandwatchAlerts((err, alerts) => {
    if (err) return res.status(500).json({ detail: 'Failed to fetch Brand Watch alerts' });
    res.json({ alerts: alerts || [] });
  });
});

// ── Real-Time Threat Intelligence Feeds ─────────────────────────────────
app.get('/feed/csv', (req, res) => {
  DBSqlite.getAllIocs((err, rows) => {
    if (err) return res.status(500).json({ detail: 'Failed to fetch threat intelligence feed' });
    const header = 'type,value,confidence_score,created_at\n';
    const lines = (rows || []).map(r => {
      const ts = r.first_seen || r.created_at || r.firstSeen || new Date().toISOString();
      return `${r.type},"${r.value}",${r.max_risk_score || r.confidence || 85},"${ts === 'undefined' ? new Date().toISOString() : ts}"`;
    }).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="sentinel_threat_intel_feed.csv"');
    res.send(header + lines);
  });
});

app.get('/feed/stix', (req, res) => {
  DBSqlite.getAllIocs((err, iocs) => {
    if (err) return res.status(500).json({ detail: 'STIX export failed' });
    const bundle = ExportEngine.exportStixBundle({ iocs: iocs || [] });
    res.setHeader('Content-Type', 'application/json');
    res.json(bundle);
  });
});

app.get('/feed/misp', (req, res) => {
  DBSqlite.getAllIocs((err, iocs) => {
    if (err) return res.status(500).json({ detail: 'MISP export failed' });
    const event = ExportEngine.exportMispEvent({ iocs: iocs || [] });
    res.setHeader('Content-Type', 'application/json');
    res.json(event);
  });
});

// ── Automated Regulatory Grievance Complaints ───────────────────────────
app.post('/reports/scores-complaint', (req, res) => {
  const { noticeId, domain, scamVpa, intermediaryName, violationDetails } = req.body || {};
  const complaint = ExportEngine.generateSebiScoresNotice({
    noticeId, domain, scamVpa, intermediaryName, violationDetails
  });
  res.setHeader('Content-Type', 'text/plain');
  res.send(complaint);
});

app.post('/reports/npci-freeze', (req, res) => {
  const { noticeId, vpa, scanId, evidenceHash } = req.body || {};
  const freezeNotice = ExportEngine.generateNpciFreezeNotice({
    noticeId, vpa, scanId, evidenceHash
  });
  res.setHeader('Content-Type', 'text/plain');
  res.send(freezeNotice);
});

// Interactive API documentation (Swagger UI)
app.use(['/docs', '/api-docs'], swaggerUi.serve, swaggerUi.setup(openApiSpec, {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: 'SentinelSEBI API Docs',
}));

// SPA Fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// Express error handler — converts a thrown handler error into a 500 instead of
// an unhandled rejection.
app.use((err, req, res, next) => {
  console.error(`[error] ${req.method} ${req.path}: ${err.message}`);
  if (res.headersSent) return next(err);
  res.status(500).json({ detail: 'Internal server error' });
});

// Last-resort guards. A single malformed record should degrade one request, not
// terminate the process and take the whole service offline.
process.on('uncaughtException', (err) => {
  console.error(`[fatal] uncaught exception: ${err.stack || err.message}`);
});
process.on('unhandledRejection', (reason) => {
  console.error(`[fatal] unhandled rejection: ${reason?.stack || reason}`);
});

// Start Server
function startServer(port) {
  const host = process.env.HOST || '0.0.0.0';
  const server = app.listen(port, host, () => {
    console.log(`
╔══════════════════════════════════════════════════════════╗
║     SentinelSEBI — Unified Hardened Express Server       ║
║                                                          ║
║  Backend API: http://${host}:${port}                   ║
║  Web Console: http://${host}:${port}                   ║
║  Database:    SQLite (sentinel.db)                       ║
╚══════════════════════════════════════════════════════════╝
    `);
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`⚠️ Port ${port} occupied. Retrying on port ${port + 1}...`);
      startServer(port + 1);
    } else {
      console.error('Server error:', err);
    }
  });
}

// Only listen when run directly, so tests can import the app and drive it with
// an ephemeral port instead of contending for 8000.
if (require.main === module) {
  startServer(process.env.PORT || 8000);
}

module.exports = { app, startServer };
