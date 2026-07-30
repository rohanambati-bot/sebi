/**
 * SentinelSEBI — Evidence Retention & Chain of Custody
 *
 * Phase 1 item 1D. Previously every upload (.eml, image, audio, video) was
 * written to a temp file, analyzed, and deleted — the original was gone and
 * nothing proved what was actually submitted. This module makes retention the
 * default: every upload is hashed and stored content-addressed before analysis
 * runs, so the evidence exists independently of whatever the analysis engine
 * concludes.
 *
 * Design choices:
 *  - Content-addressed storage (path derived from SHA-256) means an identical
 *    file submitted twice is stored once. Re-submission is itself a signal
 *    (the same lure sent to a different victim) and is captured naturally by
 *    the evidence_artifacts row rather than by file duplication.
 *  - Hashing happens synchronously before any analysis engine sees the buffer,
 *    so what gets hashed is provably the bytes that were analyzed.
 *  - The chain-of-custody hash reuses the same append-only linking pattern as
 *    the Phase 0 audit log: each artifact's hash covers the previous
 *    artifact's hash, so removing or altering a stored record breaks the
 *    chain from that point forward.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const EVIDENCE_DIR = process.env.SENTINEL_EVIDENCE_DIR || path.join(__dirname, 'data', 'evidence');
const GENESIS_HASH = '0'.repeat(64);

fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

function hashBuffer(buffer, algorithm) {
  return crypto.createHash(algorithm).update(buffer).digest('hex');
}

/** Content-addressed path: sha256 sharded into a two-level directory to avoid one giant flat folder. */
function pathForHash(sha256) {
  const dir = path.join(EVIDENCE_DIR, sha256.slice(0, 2), sha256.slice(2, 4));
  return { dir, file: path.join(dir, sha256) };
}

/**
 * Canonical serialization for the custody chain hash. Mirrors audit.js's
 * approach so both logs are auditable the same way.
 */
function canonicalize(record) {
  return [
    record.sha256 || '',
    record.md5 || '',
    String(record.size_bytes ?? ''),
    record.mime_type || '',
    record.original_filename || '',
    String(record.user_id ?? ''),
    record.source_ip || '',
    record.created_at || '',
    record.prev_hash || '',
  ].join('\u001f');
}

function computeEntryHash(record) {
  return crypto.createHash('sha256').update(canonicalize(record), 'utf8').digest('hex');
}

/**
 * Hash and persist a buffer to content-addressed storage.
 * Idempotent: submitting the same bytes twice writes the file once (fs write
 * is skipped if it already exists) but still returns fresh hash metadata so
 * the caller can record a new evidence_artifacts row for the new submission
 * event.
 *
 * Returns { sha256, md5, sizeBytes, storedPath } — never throws for a normal
 * buffer; a disk write failure is logged and storedPath comes back null so
 * the caller can still proceed with analysis using the in-memory buffer.
 */
function retain(buffer, { mimeType, originalFilename } = {}) {
  const sha256 = hashBuffer(buffer, 'sha256');
  const md5 = hashBuffer(buffer, 'md5');
  const { dir, file } = pathForHash(sha256);

  let storedPath = null;
  try {
    fs.mkdirSync(dir, { recursive: true });
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, buffer);
    }
    storedPath = file;
  } catch (err) {
    console.error(`[evidence] failed to persist artifact ${sha256}: ${err.message}`);
  }

  return {
    sha256,
    md5,
    sizeBytes: buffer.length,
    mimeType: mimeType || null,
    originalFilename: originalFilename || null,
    storedPath,
  };
}

/** Read back a retained artifact by its hash, or null if not present on disk. */
function readByHash(sha256) {
  const { file } = pathForHash(sha256);
  try {
    return fs.readFileSync(file);
  } catch {
    return null;
  }
}

module.exports = {
  EVIDENCE_DIR,
  GENESIS_HASH,
  retain,
  readByHash,
  canonicalize,
  computeEntryHash,
};
