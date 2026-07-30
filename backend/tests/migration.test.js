/**
 * Phase 0 — legacy schema migration.
 *
 * Reproduces the schema found in the deployed sentinel.db: users(id, username,
 * password, role) with cleartext passwords and the role value 'sebi_admin'.
 *
 * That schema caused two real failures:
 *   1. `CREATE TABLE IF NOT EXISTS` skipped the table, so login reached
 *      pbkdf2Sync with salt=undefined, which threw and killed the process —
 *      a remotely triggerable DoS requiring no credentials.
 *   2. The role 'sebi_admin' did not match the 'admin' value checked by RBAC,
 *      which would have locked the real administrator out of every report route.
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const sqlite3 = require('sqlite3');

const TMP_DB = path.join(os.tmpdir(), `sentinel_migration_test_${process.pid}.db`);

// Build the legacy database *before* db_sqlite is loaded, so the module sees it.
function createLegacyDb() {
  return new Promise((resolve, reject) => {
    const raw = new sqlite3.Database(TMP_DB);
    raw.serialize(() => {
      raw.run(`
        CREATE TABLE users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL,
          role TEXT NOT NULL
        )
      `);
      raw.run(`INSERT INTO users (username, password, role) VALUES ('investor', 'investor123', 'investor')`);
      raw.run(`INSERT INTO users (username, password, role) VALUES ('sebi_admin', 'sebi123', 'sebi_admin')`, (err) => {
        raw.close();
        err ? reject(err) : resolve();
      });
    });
  });
}

let app;
let DBSqlite;
let server;
let baseUrl;

test.before(async () => {
  try { fs.unlinkSync(TMP_DB); } catch {}
  await createLegacyDb();

  process.env.SENTINEL_DB_PATH = TMP_DB;
  process.env.JWT_SECRET = 'test_secret_at_least_thirty_two_chars_long_xx';

  ({ app } = require('../server'));
  DBSqlite = require('../db_sqlite');
  await DBSqlite.ready;

  await new Promise((resolve) => {
    server = app.listen(0, () => {
      baseUrl = `http://127.0.0.1:${server.address().port}`;
      resolve();
    });
  });
});

test.after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  try { fs.unlinkSync(TMP_DB); } catch {}
});

const query = (sql) =>
  new Promise((resolve, reject) => {
    const raw = new sqlite3.Database(TMP_DB);
    raw.all(sql, (err, rows) => {
      raw.close();
      err ? reject(err) : resolve(rows);
    });
  });

test('cleartext password column is replaced by salt + password_hash', async () => {
  const cols = (await query('PRAGMA table_info(users)')).map((c) => c.name);

  assert.ok(!cols.includes('password'), 'cleartext password column must be gone');
  assert.ok(cols.includes('password_hash'), 'password_hash must exist');
  assert.ok(cols.includes('salt'), 'salt must exist');
});

test('no cleartext passwords remain anywhere in the users table', async () => {
  const rows = await query('SELECT * FROM users');
  const serialized = JSON.stringify(rows);

  assert.ok(!serialized.includes('investor123'), 'investor cleartext password must not persist');
  assert.ok(!serialized.includes('sebi123'), 'admin cleartext password must not persist');
});

test('legacy backup table is dropped so cleartext does not linger on disk', async () => {
  const tables = await query("SELECT name FROM sqlite_master WHERE type='table'");
  assert.ok(
    !tables.some((t) => t.name === 'users_legacy_backup'),
    'the temporary backup table must be removed'
  );
});

test('legacy sebi_admin role is normalized to admin', async () => {
  const rows = await query("SELECT username, role FROM users WHERE username = 'sebi_admin'");

  assert.strictEqual(rows.length, 1);
  // Without this, RBAC would reject the real administrator on every report route.
  assert.strictEqual(rows[0].role, 'admin');
});

test('migrated users authenticate with their original passwords', async () => {
  for (const [username, password] of [['sebi_admin', 'sebi123'], ['investor', 'investor123']]) {
    const res = await fetch(`${baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    assert.strictEqual(res.status, 200, `${username} should still authenticate after migration`);
  }
});

test('the migrated admin can reach admin-only routes', async () => {
  const login = await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'sebi_admin', password: 'sebi123' }),
  });
  const { access_token: token } = await login.json();

  const res = await fetch(`${baseUrl}/audit/verify`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.strictEqual(res.status, 200, 'normalized admin role must satisfy requireRole("admin")');
});

test('a user row missing its salt does not crash the server', async () => {
  // The original defect: pbkdf2Sync(password, undefined) throws, and an uncaught
  // throw in the login handler terminates the process.
  await new Promise((resolve, reject) => {
    const raw = new sqlite3.Database(TMP_DB);
    raw.run(
      `INSERT INTO users (username, password_hash, salt, role, created_at) VALUES ('broken_row', '', '', 'investor', ?)`,
      [new Date().toISOString()],
      (err) => { raw.close(); err ? reject(err) : resolve(); }
    );
  });

  const res = await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'broken_row', password: 'anything' }),
  });
  assert.strictEqual(res.status, 401, 'malformed credential record should be a 401, not a crash');

  // Prove the process survived and still serves traffic.
  const health = await fetch(`${baseUrl}/dashboard/stats`);
  assert.strictEqual(health.status, 200, 'server must remain available');
});

/**
 * Phase 2 addendum — legacy `scans` table migration.
 *
 * The deployed database defined the flags column as `explanation TEXT NOT NULL`
 * and `created_at REAL`. Because CREATE TABLE IF NOT EXISTS skips an existing
 * table, every addScan INSERT failed with "no column named flags_json" — and
 * failed *silently*, since the callback error was ignored. The visible symptom
 * was an empty IOC graph despite scans appearing to succeed.
 *
 * A second, subtler defect surfaced while fixing the first: modern SQLite
 * ALTER TABLE ... RENAME rewrites other tables' foreign keys to follow the
 * rename, so renaming `scans` repointed ioc_links.evidence_scan_id at the
 * temporary backup table. Dropping the backup then broke every edge insert.
 * The migration sets PRAGMA legacy_alter_table to prevent that.
 */

const test2 = require('node:test');
const assert2 = require('node:assert');
const path2 = require('node:path');
const fs2 = require('node:fs');
const os2 = require('node:os');
const sqlite3b = require('sqlite3');

const LEGACY_SCANS_DB = path2.join(os2.tmpdir(), `sentinel_legacy_scans_${process.pid}.db`);

function createLegacyScansDb() {
  return new Promise((resolve, reject) => {
    const raw = new sqlite3b.Database(LEGACY_SCANS_DB);
    raw.serialize(() => {
      raw.run(`
        CREATE TABLE users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
          salt TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL
        )
      `);
      // The legacy shape: `explanation` instead of flags_json, REAL created_at.
      raw.run(`
        CREATE TABLE scans (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          content_type TEXT NOT NULL,
          text_or_filename TEXT NOT NULL,
          sender TEXT,
          channel TEXT,
          risk_score INTEGER NOT NULL,
          verdict TEXT NOT NULL,
          explanation TEXT NOT NULL,
          created_at REAL NOT NULL
        )
      `);
      raw.run(
        `INSERT INTO scans (content_type, text_or_filename, sender, channel, risk_score, verdict, explanation, created_at)
         VALUES ('text', 'legacy row', 'legacy@example.com', 'email', 77, 'HIGH_RISK_PHISHING', '[{"type":"legacy_flag"}]', 1721642400)`,
        (err) => { raw.close(); err ? reject(err) : resolve(); }
      );
    });
  });
}

test2('legacy scans table migrates to flags_json and preserves existing rows', async () => {
  try { fs2.unlinkSync(LEGACY_SCANS_DB); } catch {}
  await createLegacyScansDb();

  // Run the verification in a child process.
  //
  // db_sqlite resolves its database path once at module load, so exercising a
  // second database in-process would require mutating both SENTINEL_DB_PATH and
  // the module cache. Doing that leaks into sibling suites running in the same
  // process (it previously broke auth.test.js, whose users table does not exist
  // in this fixture). A child process is the only genuinely isolated option.
  const { execFileSync } = require('node:child_process');
  const script = `
    const assert = require('node:assert');
    const sqlite3 = require('sqlite3');
    const DB = require(${JSON.stringify(path2.join(__dirname, '..', 'db_sqlite'))});

    (async () => {
      await DB.ready;

      const cols = await new Promise((resolve, reject) => {
        const raw = new sqlite3.Database(process.env.SENTINEL_DB_PATH);
        raw.all('PRAGMA table_info(scans)', (e, r) => { raw.close(); e ? reject(e) : resolve(r.map(c => c.name)); });
      });
      assert.ok(cols.includes('flags_json'), 'flags_json must exist after migration');
      assert.ok(!cols.includes('explanation'), 'legacy explanation column should be gone');

      // A write must now succeed — this is exactly what silently failed before.
      const newId = await new Promise((resolve, reject) =>
        DB.addScan({
          content_type: 'text', text_or_filename: 'post-migration write', sender: 'x@y.com',
          channel: 'email', risk_score: 50, verdict: 'MODERATE_RISK_SUSPICIOUS', flags: [{ type: 't' }],
        }, (e, id) => (e ? reject(e) : resolve(id)))
      );
      assert.ok(newId, 'addScan must succeed after migration');

      // Historic rows must survive, with REAL epochs normalized to ISO-8601.
      const rows = await new Promise((resolve, reject) =>
        DB.getRecentScans(50, (e, r) => (e ? reject(e) : resolve(r)))
      );
      const legacy = rows.find(r => r.text_or_filename === 'legacy row');
      assert.ok(legacy, 'the pre-existing scan row must be preserved');
      assert.match(legacy.created_at, /^\\d{4}-\\d{2}-\\d{2}T/, 'REAL epoch should convert to ISO-8601');
      assert.match(legacy.flags_json, /legacy_flag/, 'explanation payload should carry into flags_json');

      // The FK-rewrite defect: ALTER TABLE RENAME repointed ioc_links at the
      // temporary backup table, so edge inserts must still work afterwards.
      const iocA = await DB.upsertIoc({ type: 'domain', value: 'fk-check-a.example', riskScore: 80 });
      const iocB = await DB.upsertIoc({ type: 'upi_vpa', value: 'fk.check@oksbi', riskScore: 80 });
      const linked = await DB.linkIocs({
        sourceIocId: iocA, targetIocId: iocB, relationship: 'COLLECTS_TO', evidenceScanId: newId,
      });
      assert.strictEqual(linked, true, 'ioc_links FK must still reference scans, not the dropped backup');

      console.log('MIGRATION_OK');
      process.exit(0);
    })().catch((err) => { console.error(err.message); process.exit(1); });
  `;

  const output = execFileSync(process.execPath, ['-e', script], {
    env: { ...process.env, SENTINEL_DB_PATH: LEGACY_SCANS_DB },
    encoding: 'utf8',
  });

  assert2.match(output, /MIGRATION_OK/, 'child-process migration verification should succeed');

  try { fs2.unlinkSync(LEGACY_SCANS_DB); } catch {}
});
