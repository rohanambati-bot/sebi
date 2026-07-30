/**
 * Phase 0 items 0.2 / 0.3 — attribution columns and the tamper-evident log.
 *
 * The tampering tests write directly to the SQLite file to simulate an attacker
 * with database access, then assert the chain verification detects it. That is
 * the whole point of the hash chain, so it must be proven, not assumed.
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const sqlite3 = require('sqlite3');

const TMP_DB = path.join(os.tmpdir(), `sentinel_audit_test_${process.pid}.db`);
process.env.SENTINEL_DB_PATH = TMP_DB;
process.env.JWT_SECRET = 'test_secret_at_least_thirty_two_chars_long_xx';

const { app } = require('../server');
const DBSqlite = require('../db_sqlite');
const Audit = require('../audit');

let baseUrl;
let server;
let adminToken;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      baseUrl = `http://127.0.0.1:${server.address().port}`;
      resolve();
    });
  });
  await new Promise((r) => setTimeout(r, 400));

  const res = await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'sebi_admin_2026' }),
  });
  adminToken = (await res.json()).access_token;
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  try { fs.unlinkSync(TMP_DB); } catch {}
});

const verifyChain = () =>
  new Promise((resolve, reject) =>
    DBSqlite.verifyAuditChain((err, result) => (err ? reject(err) : resolve(result)))
  );

/**
 * Poll for an audit entry rather than sleeping a fixed interval.
 *
 * Audit appends are intentionally fire-and-forget and serialized through a
 * shared queue, so their completion time depends on how much other work is
 * queued ahead of them. A fixed sleep encodes an assumption about unrelated
 * request cost and breaks whenever the request path gains work.
 */
async function waitForAudit(filter, { timeoutMs = 5000, intervalMs = 50 } = {}) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const rows = await new Promise((resolve, reject) =>
      DBSqlite.getAuditLog({ ...filter, limit: 50 }, (err, r) => (err ? reject(err) : resolve(r || [])))
    );
    if (rows.length > 0) return rows;
    await new Promise((r) => setTimeout(r, intervalMs));
  }

  return [];
}

// ── Chain construction ──

test('genesis entry links to the all-zero hash', async () => {
  await DBSqlite.appendAudit({
    actor_username: 'test', actor_role: 'admin', action: 'TEST_GENESIS', outcome: 'SUCCESS',
  });

  const entries = await new Promise((resolve, reject) =>
    DBSqlite.getAuditLog({ limit: 1000 }, (err, rows) => (err ? reject(err) : resolve(rows)))
  );

  const first = entries[entries.length - 1];
  assert.strictEqual(first.prev_hash, Audit.GENESIS_HASH);
});

test('each entry chains to its predecessor and the chain verifies', async () => {
  for (let i = 0; i < 5; i++) {
    await DBSqlite.appendAudit({
      actor_username: 'chain_test', actor_role: 'admin',
      action: 'TEST_CHAIN', target_id: String(i), outcome: 'SUCCESS',
      metadata: { index: i },
    });
  }

  const result = await verifyChain();
  assert.strictEqual(result.valid, true, result.detail);
  assert.ok(result.entriesChecked >= 5);
});

test('concurrent appends do not fork the chain', async () => {
  // Without serialization, parallel appends read the same tail row and write
  // duplicate prev_hash values, which would break verification.
  await Promise.all(
    Array.from({ length: 20 }, (_, i) =>
      DBSqlite.appendAudit({
        actor_username: 'concurrent', actor_role: 'admin',
        action: 'TEST_CONCURRENT', target_id: String(i), outcome: 'SUCCESS',
      })
    )
  );

  const result = await verifyChain();
  assert.strictEqual(result.valid, true, `chain forked under concurrency: ${result.detail}`);
});

test('audit writes never throw on unserializable metadata', async () => {
  const circular = { name: 'loop' };
  circular.self = circular;

  const written = await DBSqlite.appendAudit({
    actor_username: 'test', actor_role: 'admin',
    action: 'TEST_CIRCULAR', outcome: 'SUCCESS', metadata: circular,
  });

  assert.ok(written.id, 'append should succeed despite bad metadata');
  assert.strictEqual((await verifyChain()).valid, true);
});

// ── Tamper detection ──

function rawUpdate(sql, params) {
  return new Promise((resolve, reject) => {
    const raw = new sqlite3.Database(TMP_DB);
    raw.run(sql, params, (err) => {
      raw.close();
      err ? reject(err) : resolve();
    });
  });
}

test('editing an entry in place is detected', async () => {
  await DBSqlite.appendAudit({
    actor_username: 'victim', actor_role: 'admin',
    action: 'TEST_TAMPER_EDIT', outcome: 'SUCCESS',
  });

  assert.strictEqual((await verifyChain()).valid, true, 'chain should be clean before tampering');

  const target = await new Promise((resolve, reject) => {
    const raw = new sqlite3.Database(TMP_DB);
    raw.get(`SELECT id FROM audit_log WHERE action = 'TEST_TAMPER_EDIT' LIMIT 1`, (err, row) => {
      raw.close();
      err ? reject(err) : resolve(row);
    });
  });

  // Simulate an insider rewriting history to hide who acted.
  await rawUpdate(`UPDATE audit_log SET actor_username = 'someone_else' WHERE id = ?`, [target.id]);

  const result = await verifyChain();
  assert.strictEqual(result.valid, false, 'in-place edit must be detected');
  assert.strictEqual(result.reason, 'ENTRY_HASH_MISMATCH');
  assert.strictEqual(result.brokenAtId, target.id);

  // Restore so later assertions in this file are not affected by ordering.
  await rawUpdate(`UPDATE audit_log SET actor_username = 'victim' WHERE id = ?`, [target.id]);
  assert.strictEqual((await verifyChain()).valid, true);
});

test('deleting an entry is detected', async () => {
  await DBSqlite.appendAudit({
    actor_username: 'to_delete', actor_role: 'admin',
    action: 'TEST_TAMPER_DELETE', outcome: 'SUCCESS',
  });
  await DBSqlite.appendAudit({
    actor_username: 'successor', actor_role: 'admin',
    action: 'TEST_AFTER_DELETE', outcome: 'SUCCESS',
  });

  const doomed = await new Promise((resolve, reject) => {
    const raw = new sqlite3.Database(TMP_DB);
    raw.get(`SELECT id FROM audit_log WHERE action = 'TEST_TAMPER_DELETE' LIMIT 1`, (err, row) => {
      raw.close();
      err ? reject(err) : resolve(row);
    });
  });

  await rawUpdate(`DELETE FROM audit_log WHERE id = ?`, [doomed.id]);

  const result = await verifyChain();
  assert.strictEqual(result.valid, false, 'deletion must break the chain');
  assert.strictEqual(result.reason, 'PREV_HASH_MISMATCH');
});

// ── Attribution wiring (item 0.2) ──

test('privileged actions are recorded with the acting admin', async () => {
  await fetch(`${baseUrl}/alerts/create`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ title: 'Audit wiring check', domain: 'audit-check.example' }),
  });

  const entries = await waitForAudit({ action: 'ALERT_CREATE' });

  assert.ok(entries.length > 0, 'ALERT_CREATE should be audited');
  const entry = entries[0];
  assert.strictEqual(entry.actor_username, 'admin');
  assert.strictEqual(entry.actor_role, 'admin');
  assert.ok(entry.source_ip, 'source IP should be captured');
  assert.match(entry.metadata_json, /audit-check\.example/);
});

test('failed logins are audited', async () => {
  await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'definitely_wrong' }),
  });

  // Poll until the specific FAILURE entry lands, not just any AUTH_LOGIN row.
  const deadline = Date.now() + 5000;
  let entries = [];
  while (Date.now() < deadline) {
    entries = await new Promise((resolve, reject) =>
      DBSqlite.getAuditLog({ action: 'AUTH_LOGIN', limit: 50 }, (err, rows) =>
        err ? reject(err) : resolve(rows || [])
      )
    );
    if (entries.some((e) => e.outcome === 'FAILURE' && /bad_password/.test(e.metadata_json))) break;
    await new Promise((r) => setTimeout(r, 50));
  }

  assert.ok(
    entries.some((e) => e.outcome === 'FAILURE' && /bad_password/.test(e.metadata_json)),
    'a failed login attempt must appear in the audit log'
  );
});

test('anonymous scans are attributed to the anonymous actor with a source IP', async () => {
  await fetch(`${baseUrl}/phishing/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: 'Guaranteed returns, act now' }),
  });

  const entries = await waitForAudit({ action: 'SCAN_TEXT' });

  assert.ok(entries.length > 0);
  assert.strictEqual(entries[0].actor_username, 'anonymous');
  assert.ok(entries[0].source_ip, 'anonymous submissions still record network provenance');
});
