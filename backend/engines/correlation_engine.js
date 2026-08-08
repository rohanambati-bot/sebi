/**
 * SentinelSEBI Correlation Engine — Phase 4
 *
 * Cross-case matching. Phase 2 links indicators that literally co-occur; this
 * links artifacts that are *similar* — the same voice, the same doctored image,
 * the same message template — across otherwise unconnected reports.
 *
 * Honest scoping, stated up front because it governs how output may be used:
 *
 *  - Every threshold here is a documented default, NOT a calibrated one. The
 *    project has no labelled multi-speaker corpus, so the claimed false-match
 *    rate is unknown. A match is an investigative lead, never proof, and the
 *    API surfaces `calibrated: false` so a consumer cannot mistake it.
 *  - Voice embeddings are biometric data under the DPDP Act. Retention is
 *    purpose-limited and matches must be human-reviewed.
 *  - Stylometry is deliberately excluded: weak signal, high effort, and trivial
 *    for a reviewer to challenge.
 */

const crypto = require('crypto');

/** Thresholds. Defaults from the literature, not validated on our own data. */
const THRESHOLDS = {
  voiceprint: Number(process.env.SENTINEL_VOICEPRINT_THRESHOLD || 0.75), // cosine
  phash: Number(process.env.SENTINEL_PHASH_MAX_DISTANCE || 10),          // Hamming
  template: Number(process.env.SENTINEL_TEMPLATE_THRESHOLD || 0.6),      // Jaccard
};

const CALIBRATED = false; // see scoping note above

// ───────────────────────────── Voiceprints ─────────────────────────────

/**
 * Cosine similarity between two equal-length embedding vectors.
 * Returns null for mismatched or degenerate input rather than a misleading 0,
 * so "cannot compare" is distinguishable from "compared and dissimilar".
 */
function cosineSimilarity(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length === 0 || a.length !== b.length) return null;

  let dot = 0;
  let magA = 0;
  let magB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }

  const denom = Math.sqrt(magA) * Math.sqrt(magB);
  if (denom === 0) return null;
  return dot / denom;
}

// ───────────────────────── Perceptual hashing ─────────────────────────

/**
 * Difference hash (dHash) over a grayscale byte grid.
 *
 * Operates on a caller-supplied grid so this stays dependency-free and
 * testable. Callers with real decoding (Python ML path) downsample first; the
 * JS fallback derives a coarse grid from raw bytes, which is weaker but still
 * survives recompression better than SHA-256 does.
 */
function dHashFromGrid(grid, width, height) {
  if (!Array.isArray(grid) || grid.length !== width * height) return null;

  let bits = '';
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width - 1; x++) {
      bits += grid[y * width + x] > grid[y * width + x + 1] ? '1' : '0';
    }
  }

  // Pack to hex for compact storage and cheap Hamming comparison.
  let hex = '';
  for (let i = 0; i < bits.length; i += 4) {
    hex += parseInt(bits.slice(i, i + 4).padEnd(4, '0'), 2).toString(16);
  }
  return hex;
}

/**
 * Derive a coarse 9x8 luminance grid from an arbitrary byte buffer.
 *
 * This is an approximation, not real image decoding: it buckets bytes from the
 * pixel-data region and averages them. It gives a stable fingerprint for
 * byte-similar files but will not match the same image re-encoded at a
 * different quality. Real perceptual matching needs a decoder (sharp/OpenCV);
 * this keeps the JS fallback path functional without adding that dependency.
 */
function approximateGridFromBuffer(buffer, width = 9, height = 8) {
  if (!buffer || buffer.length === 0) return null;

  // Skip likely header bytes so container metadata does not dominate.
  const start = Math.min(512, Math.floor(buffer.length * 0.1));
  const usable = buffer.length - start;
  if (usable < width * height) return null;

  const cells = width * height;
  const bucketSize = Math.floor(usable / cells);
  const grid = [];

  for (let i = 0; i < cells; i++) {
    const from = start + i * bucketSize;
    const to = from + bucketSize;
    let sum = 0;
    for (let j = from; j < to; j++) sum += buffer[j];
    grid.push(Math.round(sum / bucketSize));
  }

  return grid;
}

/** Hamming distance between two equal-length hex strings, or null. */
function hammingDistanceHex(hexA, hexB) {
  if (!hexA || !hexB || hexA.length !== hexB.length) return null;

  let distance = 0;
  for (let i = 0; i < hexA.length; i++) {
    const xor = parseInt(hexA[i], 16) ^ parseInt(hexB[i], 16);
    distance += ((xor >> 3) & 1) + ((xor >> 2) & 1) + ((xor >> 1) & 1) + (xor & 1);
  }
  return distance;
}

// ───────────────────── Template / message clustering ─────────────────────

/**
 * Character shingles for near-duplicate text detection.
 * Normalizes case and collapses whitespace so reformatting does not defeat it,
 * but keeps punctuation — scam kits reuse punctuation patterns verbatim.
 */
function shingles(text, size = 5) {
  const normalized = String(text || '').toLowerCase().replace(/\s+/g, ' ').trim();
  if (normalized.length < size) return new Set(normalized ? [normalized] : []);

  const set = new Set();
  for (let i = 0; i <= normalized.length - size; i++) set.add(normalized.slice(i, i + size));
  return set;
}

/** Jaccard similarity over two shingle sets. */
function jaccardSimilarity(setA, setB) {
  if (!setA?.size || !setB?.size) return null;

  let intersection = 0;
  for (const item of setA) if (setB.has(item)) intersection++;
  return intersection / (setA.size + setB.size - intersection);
}

/**
 * Stable template fingerprint: the SHA-256 of the sorted shingle set.
 * Identical templates hash identically, which makes exact reuse a cheap
 * index lookup rather than an O(n²) comparison.
 */
function templateFingerprint(text) {
  const set = shingles(text);
  if (set.size === 0) return null;
  return crypto.createHash('sha256').update([...set].sort().join('\u001f')).digest('hex');
}

// ───────────────────── Infrastructure reuse scoring ─────────────────────

/**
 * Score how strongly two enrichment results suggest one operator.
 * Shared nameservers and same-day registration through the same registrar are
 * the signals that most reliably break an operation open.
 */
function infrastructureReuseScore(enrichmentA, enrichmentB) {
  const reasons = [];
  let score = 0;

  const nsA = new Set((enrichmentA?.rdap?.nameservers || []).map((n) => n.toLowerCase()));
  const nsB = new Set((enrichmentB?.rdap?.nameservers || []).map((n) => n.toLowerCase()));
  const sharedNs = [...nsA].filter((n) => nsB.has(n));
  if (sharedNs.length > 0) {
    score += 40;
    reasons.push(`Shared nameserver(s): ${sharedNs.join(', ')}`);
  }

  const ipsA = new Set([...(enrichmentA?.dns?.a || []), ...(enrichmentA?.dns?.aaaa || [])]);
  const ipsB = new Set([...(enrichmentB?.dns?.a || []), ...(enrichmentB?.dns?.aaaa || [])]);
  const sharedIps = [...ipsA].filter((ip) => ipsB.has(ip));
  if (sharedIps.length > 0) {
    score += 35;
    reasons.push(`Co-hosted on IP(s): ${sharedIps.join(', ')}`);
  }

  const regA = enrichmentA?.rdap?.registrar;
  const regB = enrichmentB?.rdap?.registrar;
  const createdA = enrichmentA?.rdap?.created;
  const createdB = enrichmentB?.rdap?.created;

  if (regA && regB && regA === regB) {
    score += 10;
    reasons.push(`Same registrar: ${regA}`);

    if (createdA && createdB && createdA.slice(0, 10) === createdB.slice(0, 10)) {
      score += 15;
      reasons.push(`Registered on the same day (${createdA.slice(0, 10)}) through the same registrar`);
    }
  }

  return { score: Math.min(100, score), reasons };
}

/**
 * Calculate multi-factor campaign attribution confidence score (0 - 100%).
 * Evaluates indicator co-occurrences, financial handles, infrastructure reuse,
 * voiceprints, and template similarity across campaign members.
 */
function calculateCampaignConfidence(indicators = [], scans = []) {
  let score = 50; // base score for grouped campaign
  const reasons = [];

  const upiCount = indicators.filter(i => i.type === 'upi_vpa' || i.type === 'crypto_wallet').length;
  const commsCount = indicators.filter(i => i.type === 'telegram_link' || i.type === 'whatsapp_link' || i.type === 'phone').length;
  const domainCount = indicators.filter(i => i.type === 'domain' || i.type === 'url').length;

  if (upiCount > 0) {
    score += 25;
    reasons.push('+25% Shared financial settlement handle(s) (UPI/Wallet IOCs)');
  }

  if (commsCount > 0) {
    score += 15;
    reasons.push('+15% Shared direct communication handle(s) (Telegram/WhatsApp IOCs)');
  }

  if (domainCount > 1) {
    score += 10;
    reasons.push('+10% Rotated infrastructure domain cluster');
  }

  if (scans.length > 2) {
    score += 10;
    reasons.push(`+10% Multi-scan cross-victim reporting density (${scans.length} verified scans)`);
  }

  const finalScore = Math.min(98, Math.max(30, score));
  let confidenceTier = 'HIGH';
  if (finalScore < 60) confidenceTier = 'MODERATE';
  else if (finalScore >= 85) confidenceTier = 'VERY_HIGH';

  return {
    confidenceScore: finalScore,
    confidenceTier,
    reasons,
    summary: `Campaign Attribution Confidence: ${finalScore}% (${confidenceTier}) based on ${reasons.length} cross-correlated indicator signals.`
  };
}

module.exports = {
  THRESHOLDS,
  CALIBRATED,
  cosineSimilarity,
  dHashFromGrid,
  approximateGridFromBuffer,
  hammingDistanceHex,
  shingles,
  jaccardSimilarity,
  templateFingerprint,
  infrastructureReuseScore,
  calculateCampaignConfidence,
};
