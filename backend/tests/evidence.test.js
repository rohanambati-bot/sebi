/**
 * Phase 1 item 1D — Evidence retention and chain of custody.
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const TMP_DB = path.join(os.tmpdir(), `sentinel_evidence_test_${process.pid}.db`);
const TMP_EVIDENCE_DIR = path.join(os.tmpdir(), `sentinel_evidence_files_${process.pid}`);
process.env.SENTINEL_DB_PATH = TMP_DB;
process.env.SENTINEL_EVIDENCE_DIR = TMP_EVIDENCE_DIR;
process.env.JWT_SECRET = 'test_secret_at_least_thirty_two_chars_long_xx';

const Evidence = require('../evidence');
const DBSqlite = require('../db_sqlite');

test.before(async () => {
  await DBSqlite.ready;
});

test.after(() => {
  try { fs.unlinkSync(TMP_DB); } catch {}
  try { fs.rmSync(TMP_EVIDENCE_DIR, { recursive: true, force: true }); } catch {}
});

// ─────────────────────────── Retention & hashing ───────────────────────────

test('retain() computes correct sha256 and md5 for known content', () => {
  const buf = Buffer.from('sentinel evidence test payload');
  const result = Evidence.retain(buf, { mimeType: 'text/plain', originalFilename: 'a.txt' });

  const expectedSha256 = require('crypto').createHash('sha256').update(buf).digest('hex');
  const expectedMd5 = require('crypto').createHash('md5').update(buf).digest('hex');

  assert.strictEqual(result.sha256, expectedSha256);
  assert.strictEqual(result.md5, expectedMd5);
  assert.strictEqual(result.sizeBytes, buf.length);
});

test('retain() persists the file and it is byte-identical on read-back', () => {
  const buf = Buffer.from('roundtrip test content, byte for byte');
  const result = Evidence.retain(buf, { mimeType: 'application/octet-stream' });

  const readBack = Evidence.readByHash(result.sha256);
  assert.ok(readBack, 'file must exist on disk after retain()');
  assert.ok(buf.equals(readBack), 'stored bytes must exactly match the submitted bytes');
});

test('retain() is idempotent for identical content (content-addressed dedup)', () => {
  const buf = Buffer.from('duplicate submission content');
  const first = Evidence.retain(buf, { originalFilename: 'first.eml' });
  const second = Evidence.retain(buf, { originalFilename: 'resubmitted.eml' });

  assert.strictEqual(first.sha256, second.sha256, 'identical bytes must hash identically');
  // Only one copy on disk regardless of how many times it is submitted.
  assert.strictEqual(first.storedPath, second.storedPath);
});

test('readByHash() returns null for a hash that was never retained', () => {
  assert.strictEqual(Evidence.readByHash('0'.repeat(64)), null);
});

// ─────────────────────────── Custody chain ───────────────────────────

test('evidence custody chain: appends link correctly and verifies clean', async () => {
  for (let i = 0; i < 4; i++) {
    const buf = Buffer.from(`custody chain test artifact ${i}`);
    const retained = Evidence.retain(buf);
    await DBSqlite.addEvidenceArtifact({
      sha256: retained.sha256,
      md5: retained.md5,
      size_bytes: retained.sizeBytes,
      mime_type: 'text/plain',
      original_filename: `artifact_${i}.txt`,
      stored_path: retained.storedPath,
      user_id: null,
      source_ip: '127.0.0.1',
    });
  }

  const result = await new Promise((resolve, reject) =>
    DBSqlite.verifyEvidenceChain((err, r) => (err ? reject(err) : resolve(r)))
  );

  assert.strictEqual(result.valid, true, result.detail);
  assert.ok(result.entriesChecked >= 4);
});

test('evidence custody chain: detects tampering with a stored hash', async () => {
  const buf = Buffer.from('tamper target artifact');
  const retained = Evidence.retain(buf);
  await DBSqlite.addEvidenceArtifact({
    sha256: retained.sha256, md5: retained.md5, size_bytes: retained.sizeBytes,
    mime_type: 'text/plain', original_filename: 'tamper.txt', stored_path: retained.storedPath,
  });

  const before = await new Promise((resolve, reject) =>
    DBSqlite.verifyEvidenceChain((err, r) => (err ? reject(err) : resolve(r)))
  );
  assert.strictEqual(before.valid, true);

  const sqlite3 = require('sqlite3');
  await new Promise((resolve, reject) => {
    const raw = new sqlite3.Database(TMP_DB);
    raw.run(
      `UPDATE evidence_artifacts SET original_filename = 'renamed_to_hide_origin.txt' WHERE sha256 = ?`,
      [retained.sha256],
      (err) => { raw.close(); err ? reject(err) : resolve(); }
    );
  });

  const after = await new Promise((resolve, reject) =>
    DBSqlite.verifyEvidenceChain((err, r) => (err ? reject(err) : resolve(r)))
  );
  assert.strictEqual(after.valid, false, 'renaming a custody record in place must be detected');
  assert.strictEqual(after.reason, 'ENTRY_HASH_MISMATCH');
});

test('getEvidenceBySha256 finds every scan that submitted the same artifact', async () => {
  const buf = Buffer.from('reused lure sent to two victims');
  const retained = Evidence.retain(buf);

  // evidence_artifacts.scan_id is a real foreign key (Phase 0 enforces
  // PRAGMA foreign_keys = ON), so the fixture needs genuine scans rows rather
  // than arbitrary integers.
  const makeScan = () =>
    new Promise((resolve, reject) =>
      DBSqlite.addScan(
        {
          content_type: 'eml', text_or_filename: 'reused_lure.eml', sender: 'scam@example.com',
          channel: 'email', risk_score: 90, verdict: 'HIGH_RISK_PHISHING', flags: [],
        },
        (err, id) => (err ? reject(err) : resolve(id))
      )
    );

  const scanId1 = await makeScan();
  const scanId2 = await makeScan();

  await DBSqlite.addEvidenceArtifact({
    sha256: retained.sha256, md5: retained.md5, size_bytes: retained.sizeBytes,
    scan_id: scanId1, original_filename: 'victim1.eml', stored_path: retained.storedPath,
  });
  await DBSqlite.addEvidenceArtifact({
    sha256: retained.sha256, md5: retained.md5, size_bytes: retained.sizeBytes,
    scan_id: scanId2, original_filename: 'victim2.eml', stored_path: retained.storedPath,
  });

  const sightings = await new Promise((resolve, reject) =>
    DBSqlite.getEvidenceBySha256(retained.sha256, (err, rows) => (err ? reject(err) : resolve(rows)))
  );

  assert.strictEqual(sightings.length, 2, 'the same lure reused across victims must be discoverable by hash');
  const scanIds = sightings.map((s) => s.scan_id).sort((a, b) => a - b);
  assert.deepStrictEqual(scanIds, [scanId1, scanId2].sort((a, b) => a - b));
});
