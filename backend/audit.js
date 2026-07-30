/**
 * SentinelSEBI — Tamper-Evident Audit Log
 *
 * Phase 0 (Trust Foundation) item 0.3.
 *
 * Every mutating action appends a record whose hash covers both the record's
 * own content and the hash of the previous record. Altering or deleting any
 * historical entry breaks the chain from that point onward, which `verifyChain`
 * detects and reports.
 *
 * Scope, stated plainly: this proves internal consistency. It does not prove
 * the log was not rewritten wholesale by someone with write access to the
 * database file. Independent time/existence proof needs an external anchor
 * (RFC 3161 timestamp authority), which is deliberately out of Phase 0 scope.
 */

const crypto = require('crypto');

const GENESIS_HASH = '0'.repeat(64);

/**
 * Canonical serialization for hashing.
 * Key order is fixed explicitly so the digest never depends on JS property
 * enumeration order or on JSON.stringify implementation details.
 */
function canonicalize(entry) {
  return [
    entry.actor_id === null || entry.actor_id === undefined ? '' : String(entry.actor_id),
    entry.actor_username || '',
    entry.actor_role || '',
    entry.action || '',
    entry.target_type || '',
    entry.target_id === null || entry.target_id === undefined ? '' : String(entry.target_id),
    entry.outcome || '',
    entry.source_ip || '',
    entry.user_agent || '',
    entry.metadata_json || '',
    entry.created_at || '',
    entry.prev_hash || '',
  ].join('\u001f'); // unit separator — cannot appear in the source values
}

function computeHash(entry) {
  return crypto.createHash('sha256').update(canonicalize(entry), 'utf8').digest('hex');
}

/**
 * Serialize metadata defensively.
 * Audit writes must never throw, so a circular or unserializable payload
 * degrades to a marker rather than taking down the request.
 */
function serializeMetadata(metadata) {
  if (metadata === null || metadata === undefined) return '{}';
  try {
    return JSON.stringify(metadata);
  } catch {
    return '{"_error":"metadata_not_serializable"}';
  }
}

/** Truncate free-text fields so a hostile client cannot bloat the log. */
function clamp(value, max) {
  if (value === null || value === undefined) return null;
  const str = String(value);
  return str.length > max ? str.slice(0, max) : str;
}

module.exports = {
  GENESIS_HASH,
  canonicalize,
  computeHash,
  serializeMetadata,
  clamp,
};
