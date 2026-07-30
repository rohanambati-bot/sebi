/**
 * Phase 4 — Cross-case correlation (voiceprint, perceptual hash, templates).
 *
 * These tests verify the maths and the storage contract. They deliberately do
 * NOT assert a false-match rate: no labelled corpus exists for this dataset, so
 * any such claim would be unfounded. What is asserted is that thresholds are
 * applied consistently, that "cannot compare" is distinguishable from
 * "dissimilar", and that matches are recorded with the threshold that produced
 * them so a decision can be audited later.
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const TMP_DB = path.join(os.tmpdir(), `sentinel_corr_test_${process.pid}.db`);
process.env.SENTINEL_DB_PATH = TMP_DB;
process.env.JWT_SECRET = 'test_secret_at_least_thirty_two_chars_long_xx';

const Correlation = require('../engines/correlation_engine');
const DBSqlite = require('../db_sqlite');

test.before(async () => {
  await DBSqlite.ready;
});

test.after(() => {
  try { fs.unlinkSync(TMP_DB); } catch {}
});

// ───────────────────────── Voiceprint similarity ─────────────────────────

test('cosineSimilarity returns 1 for identical vectors', () => {
  const v = [0.1, 0.5, -0.3, 0.8];
  assert.ok(Math.abs(Correlation.cosineSimilarity(v, v) - 1) < 1e-9);
});

test('cosineSimilarity returns ~0 for orthogonal vectors', () => {
  assert.ok(Math.abs(Correlation.cosineSimilarity([1, 0], [0, 1])) < 1e-9);
});

test('cosineSimilarity returns -1 for opposed vectors', () => {
  assert.ok(Math.abs(Correlation.cosineSimilarity([1, 2], [-1, -2]) + 1) < 1e-9);
});

test('cosineSimilarity is scale invariant', () => {
  // Embedding magnitude varies with recording length/volume; only direction
  // should matter for speaker identity.
  const a = [1, 2, 3];
  const b = [10, 20, 30];
  assert.ok(Math.abs(Correlation.cosineSimilarity(a, b) - 1) < 1e-9);
});

test('cosineSimilarity returns null rather than 0 when comparison is impossible', () => {
  // A misleading 0 would read as "different speaker"; null reads as "unknown".
  assert.strictEqual(Correlation.cosineSimilarity([1, 2], [1, 2, 3]), null, 'length mismatch');
  assert.strictEqual(Correlation.cosineSimilarity([], []), null, 'empty vectors');
  assert.strictEqual(Correlation.cosineSimilarity([0, 0], [0, 0]), null, 'zero magnitude');
  assert.strictEqual(Correlation.cosineSimilarity(null, [1]), null, 'null input');
  assert.strictEqual(Correlation.cosineSimilarity('nope', [1]), null, 'non-array input');
});

test('voiceprint threshold is exposed and flagged as uncalibrated', () => {
  assert.ok(Correlation.THRESHOLDS.voiceprint > 0 && Correlation.THRESHOLDS.voiceprint < 1);
  // This must stay false until a labelled speaker corpus is available.
  assert.strictEqual(Correlation.CALIBRATED, false);
});

// ───────────────────────── Perceptual hashing ─────────────────────────

test('dHashFromGrid produces a stable hash for the same grid', () => {
  const grid = Array.from({ length: 72 }, (_, i) => (i * 7) % 256);
  const first = Correlation.dHashFromGrid(grid, 9, 8);
  const second = Correlation.dHashFromGrid(grid, 9, 8);

  assert.ok(first);
  assert.strictEqual(first, second);
});

test('dHashFromGrid rejects a grid of the wrong size', () => {
  assert.strictEqual(Correlation.dHashFromGrid([1, 2, 3], 9, 8), null);
  assert.strictEqual(Correlation.dHashFromGrid(null, 9, 8), null);
});

test('dHash distance is zero for identical grids and non-zero for different ones', () => {
  const gridA = Array.from({ length: 72 }, (_, i) => i * 3);
  const gridB = Array.from({ length: 72 }, (_, i) => (i * 3 + 128) % 256);

  const hashA = Correlation.dHashFromGrid(gridA, 9, 8);
  const hashB = Correlation.dHashFromGrid(gridB, 9, 8);

  assert.strictEqual(Correlation.hammingDistanceHex(hashA, hashA), 0);
  assert.ok(Correlation.hammingDistanceHex(hashA, hashB) > 0);
});

test('hammingDistanceHex counts single-bit differences correctly', () => {
  assert.strictEqual(Correlation.hammingDistanceHex('0', '1'), 1);
  assert.strictEqual(Correlation.hammingDistanceHex('0', 'f'), 4);
  assert.strictEqual(Correlation.hammingDistanceHex('ff', 'ff'), 0);
  assert.strictEqual(Correlation.hammingDistanceHex('00', 'ff'), 8);
});

test('hammingDistanceHex returns null for incomparable inputs', () => {
  assert.strictEqual(Correlation.hammingDistanceHex('abc', 'ab'), null);
  assert.strictEqual(Correlation.hammingDistanceHex(null, 'ab'), null);
});

test('approximateGridFromBuffer handles small and empty buffers safely', () => {
  assert.strictEqual(Correlation.approximateGridFromBuffer(Buffer.alloc(0)), null);
  assert.strictEqual(Correlation.approximateGridFromBuffer(Buffer.alloc(10)), null);

  const big = Buffer.alloc(5000, 120);
  const grid = Correlation.approximateGridFromBuffer(big);
  assert.ok(Array.isArray(grid));
  assert.strictEqual(grid.length, 72);
});

test('approximateGridFromBuffer is deterministic for identical bytes', () => {
  const buf = Buffer.from(Array.from({ length: 4000 }, (_, i) => i % 256));
  const a = Correlation.dHashFromGrid(Correlation.approximateGridFromBuffer(buf), 9, 8);
  const b = Correlation.dHashFromGrid(Correlation.approximateGridFromBuffer(Buffer.from(buf)), 9, 8);

  assert.strictEqual(a, b);
});

// ───────────────────── Template / near-duplicate text ─────────────────────

test('identical text yields an identical template fingerprint', () => {
  const text = 'Dear Investor, guaranteed 500% returns. Pay to scam@oksbi now!';
  assert.strictEqual(Correlation.templateFingerprint(text), Correlation.templateFingerprint(text));
});

test('template fingerprint ignores case and whitespace reformatting', () => {
  const a = 'Guaranteed returns, act now!';
  const b = 'guaranteed   returns,    ACT NOW!';
  assert.strictEqual(Correlation.templateFingerprint(a), Correlation.templateFingerprint(b));
});

test('different templates yield different fingerprints', () => {
  const a = Correlation.templateFingerprint('Guaranteed returns, act now');
  const b = Correlation.templateFingerprint('Your contract note is available');
  assert.notStrictEqual(a, b);
});

test('templateFingerprint returns null for empty input rather than a constant hash', () => {
  // A constant hash for empty input would cluster every empty message together.
  assert.strictEqual(Correlation.templateFingerprint(''), null);
  assert.strictEqual(Correlation.templateFingerprint(null), null);
});

test('jaccardSimilarity scores near-duplicates high and unrelated text low', () => {
  const base = Correlation.shingles('Guaranteed 500% returns, pay to scam@oksbi immediately');
  const tweaked = Correlation.shingles('Guaranteed 500% returns, pay to fraud@ybl immediately');
  const unrelated = Correlation.shingles('Nifty 50 closed marginally higher on Tuesday');

  const near = Correlation.jaccardSimilarity(base, tweaked);
  const far = Correlation.jaccardSimilarity(base, unrelated);

  assert.ok(near > far, `near-duplicate (${near}) should score above unrelated (${far})`);
  assert.ok(near > 0.5, `a one-handle edit should still read as the same template, got ${near}`);
});

test('jaccardSimilarity returns null for empty sets', () => {
  assert.strictEqual(Correlation.jaccardSimilarity(new Set(), new Set(['a'])), null);
});

// ───────────────────── Infrastructure reuse scoring ─────────────────────

test('shared nameservers raise the infrastructure reuse score', () => {
  const a = { rdap: { nameservers: ['ns1.bulkhost.example', 'ns2.bulkhost.example'] }, dns: {} };
  const b = { rdap: { nameservers: ['ns1.bulkhost.example'] }, dns: {} };

  const { score, reasons } = Correlation.infrastructureReuseScore(a, b);
  assert.ok(score >= 40);
  assert.ok(reasons.some((r) => /Shared nameserver/.test(r)));
});

test('co-hosting on the same IP raises the score', () => {
  const a = { rdap: {}, dns: { a: ['203.0.113.9'] } };
  const b = { rdap: {}, dns: { a: ['203.0.113.9', '203.0.113.10'] } };

  const { score, reasons } = Correlation.infrastructureReuseScore(a, b);
  assert.ok(score >= 35);
  assert.ok(reasons.some((r) => /Co-hosted/.test(r)));
});

test('same registrar plus same-day registration is scored above registrar alone', () => {
  const sameDay = Correlation.infrastructureReuseScore(
    { rdap: { registrar: 'BulkReg', created: '2026-07-01T10:00:00Z' }, dns: {} },
    { rdap: { registrar: 'BulkReg', created: '2026-07-01T18:00:00Z' }, dns: {} }
  );
  const registrarOnly = Correlation.infrastructureReuseScore(
    { rdap: { registrar: 'BulkReg', created: '2020-01-01T00:00:00Z' }, dns: {} },
    { rdap: { registrar: 'BulkReg', created: '2026-07-01T00:00:00Z' }, dns: {} }
  );

  assert.ok(sameDay.score > registrarOnly.score);
  assert.ok(sameDay.reasons.some((r) => /same day/.test(r)));
});

test('unrelated infrastructure scores zero with no reasons', () => {
  const { score, reasons } = Correlation.infrastructureReuseScore(
    { rdap: { nameservers: ['ns1.a.example'], registrar: 'RegA' }, dns: { a: ['1.2.3.4'] } },
    { rdap: { nameservers: ['ns1.b.example'], registrar: 'RegB' }, dns: { a: ['5.6.7.8'] } }
  );

  assert.strictEqual(score, 0);
  assert.strictEqual(reasons.length, 0);
});

test('infrastructureReuseScore handles missing enrichment without throwing', () => {
  assert.doesNotThrow(() => Correlation.infrastructureReuseScore({}, {}));
  assert.doesNotThrow(() => Correlation.infrastructureReuseScore(null, null));
});

// ───────────────────────── Persistence ─────────────────────────

test('a voiceprint vector round-trips through storage', async () => {
  const vector = Array.from({ length: 256 }, (_, i) => Math.sin(i) / 2);

  const id = await DBSqlite.addFingerprint({
    scanId: null, kind: 'voiceprint', vector, dimensions: vector.length,
  });
  assert.ok(id, 'fingerprint should persist');

  const rows = await new Promise((resolve, reject) =>
    DBSqlite.getFingerprintsByKind('voiceprint', (e, r) => (e ? reject(e) : resolve(r)))
  );
  const stored = rows.find((r) => r.id === id);

  assert.ok(stored);
  assert.strictEqual(stored.dimensions, 256);

  const restored = JSON.parse(stored.vector_json);
  assert.strictEqual(restored.length, vector.length);
  // The stored vector must still match itself — otherwise cross-case matching
  // would silently compare corrupted data.
  assert.ok(Math.abs(Correlation.cosineSimilarity(restored, vector) - 1) < 1e-9);
});

test('a match records the threshold that produced it', async () => {
  const v1 = Array.from({ length: 64 }, (_, i) => Math.cos(i));
  const v2 = v1.map((x) => x * 1.01); // near-identical direction

  const idA = await DBSqlite.addFingerprint({ kind: 'voiceprint', vector: v1, dimensions: 64 });
  const idB = await DBSqlite.addFingerprint({ kind: 'voiceprint', vector: v2, dimensions: 64 });

  const score = Correlation.cosineSimilarity(v1, v2);
  assert.ok(score >= Correlation.THRESHOLDS.voiceprint);

  await DBSqlite.recordFingerprintMatch({
    kind: 'voiceprint', a: idA, b: idB,
    score, threshold: Correlation.THRESHOLDS.voiceprint, method: 'cosine_similarity',
  });

  const matches = await new Promise((resolve, reject) =>
    DBSqlite.getFingerprintMatches((e, r) => (e ? reject(e) : resolve(r)))
  );
  const match = matches.find((m) => m.fingerprint_a === Math.min(idA, idB));

  assert.ok(match, 'match should be recorded');
  assert.strictEqual(match.threshold, Correlation.THRESHOLDS.voiceprint,
    'the threshold must be stored so the decision can be audited later');
  assert.strictEqual(match.method, 'cosine_similarity');
});

test('a match pair is stored once regardless of argument order', async () => {
  const idA = await DBSqlite.addFingerprint({ kind: 'phash', hashValue: 'aabbccdd' });
  const idB = await DBSqlite.addFingerprint({ kind: 'phash', hashValue: 'aabbccde' });

  await DBSqlite.recordFingerprintMatch({ kind: 'phash', a: idA, b: idB, score: 1, threshold: 10, method: 'dhash_hamming' });
  await DBSqlite.recordFingerprintMatch({ kind: 'phash', a: idB, b: idA, score: 1, threshold: 10, method: 'dhash_hamming' });

  const matches = await new Promise((resolve, reject) =>
    DBSqlite.getFingerprintMatches((e, r) => (e ? reject(e) : resolve(r)))
  );
  const forPair = matches.filter(
    (m) => m.kind === 'phash' && m.fingerprint_a === Math.min(idA, idB) && m.fingerprint_b === Math.max(idA, idB)
  );

  assert.strictEqual(forPair.length, 1, 'reversed pairs must collapse to one row');
});
