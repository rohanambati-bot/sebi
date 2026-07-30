/**
 * Phase 0 items 0.1 / 0.5 / 0.6 — auth enforcement and RBAC.
 *
 * Drives the real Express app over an ephemeral port. Uses an isolated
 * temporary database so the suite never mutates sentinel.db.
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

// Must be set before db_sqlite is required, since it resolves the path on load.
const TMP_DB = path.join(os.tmpdir(), `sentinel_auth_test_${process.pid}.db`);
process.env.SENTINEL_DB_PATH = TMP_DB;
process.env.JWT_SECRET = 'test_secret_at_least_thirty_two_chars_long_xx';

const { app } = require('../server');

let baseUrl;
let server;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      baseUrl = `http://127.0.0.1:${server.address().port}`;
      resolve();
    });
  });
  // Allow the async table creation + seeding in db_sqlite to settle.
  await new Promise((r) => setTimeout(r, 400));
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  try { fs.unlinkSync(TMP_DB); } catch {}
});

function req(method, endpoint, { token, body } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers['Content-Type'] = 'application/json';
  return fetch(`${baseUrl}${endpoint}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
}

async function login(username, password) {
  const res = await req('POST', '/auth/login', { body: { username, password } });
  assert.strictEqual(res.status, 200, `login failed for ${username}`);
  return (await res.json()).access_token;
}

// ── The core Phase 0 regression: these routes were publicly callable ──

const PROTECTED_ROUTES = [
  ['POST', '/reports/cert-in-takedown'],
  ['POST', '/reports/status'],
  ['POST', '/reports/dot-dns-block'],
  ['POST', '/reports/npci-vpa-freeze'],
  ['POST', '/alerts/create'],
  ['POST', '/verify/register'],
  ['POST', '/social/ingest'],
  ['POST', '/system/reset'],
  ['GET', '/audit/log'],
  ['GET', '/audit/verify'],
];

test('unauthenticated requests to privileged routes are rejected', async () => {
  for (const [method, endpoint] of PROTECTED_ROUTES) {
    const res = await req(method, endpoint, { body: method === 'POST' ? {} : undefined });
    assert.strictEqual(res.status, 401, `${method} ${endpoint} should require auth`);
  }
});

test('a malformed or forged token is rejected', async () => {
  const res = await req('POST', '/reports/cert-in-takedown', {
    token: 'not.a.real.token',
    body: { targetDomain: 'evil.example' },
  });
  assert.strictEqual(res.status, 401);
});

test('investor role cannot reach regulatory or admin routes', async () => {
  const token = await login('investor', 'investor123');

  for (const [method, endpoint] of PROTECTED_ROUTES) {
    const res = await req(method, endpoint, { token, body: method === 'POST' ? {} : undefined });
    assert.strictEqual(res.status, 403, `${method} ${endpoint} should be forbidden for investor`);
  }
});

test('admin can generate a CERT-In notice and it is attributed', async () => {
  const token = await login('admin', 'sebi_admin_2026');

  const res = await req('POST', '/reports/cert-in-takedown', {
    token,
    body: { targetDomain: 'sebi-fake-tips.xyz', scamVpa: 'scam@oksbi', threatCategory: 'Impersonation' },
  });

  assert.strictEqual(res.status, 200);
  const data = await res.json();
  assert.ok(data.incidentId.startsWith('CERT-IN-'));
  assert.match(data.legalNoticeText, /Section 70B/);
  // Phase 0 item 0.2 — the artifact records who created it.
  assert.ok(data.takedown.user_id, 'takedown must carry the creating user_id');
});

test('login rejects bad credentials without revealing which field was wrong', async () => {
  const noUser = await req('POST', '/auth/login', {
    body: { username: 'ghost_user', password: 'whatever' },
  });
  const badPass = await req('POST', '/auth/login', {
    body: { username: 'admin', password: 'wrong_password' },
  });

  assert.strictEqual(noUser.status, 401);
  assert.strictEqual(badPass.status, 401);
  // Identical messages prevent username enumeration.
  assert.strictEqual((await noUser.json()).detail, (await badPass.json()).detail);
});

test('/auth/me reflects the authenticated identity', async () => {
  const token = await login('sebi', 'sebi_official_2026');
  const res = await req('GET', '/auth/me', { token });

  assert.strictEqual(res.status, 200);
  const me = await res.json();
  assert.strictEqual(me.username, 'sebi');
  assert.strictEqual(me.role, 'admin');
});

test('public scan and verify endpoints remain open to investors', async () => {
  // Investor protection tooling must not require an account.
  const scan = await req('POST', '/phishing/analyze', {
    body: { text: 'Visit sebi-official-tips.xyz for guaranteed returns, act now' },
  });
  assert.strictEqual(scan.status, 200);

  const result = await scan.json();
  assert.ok(typeof result.risk_score === 'number', 'scan must return a numeric risk score');
  assert.ok(result.verdict, 'scan must return a verdict');
  assert.ok(result.risk_score > 0, 'a typosquat plus guaranteed-returns lure should score above zero');

  for (const endpoint of ['/dashboard/stats', '/alerts/feed', '/reports/list']) {
    const res = await req('GET', endpoint);
    assert.strictEqual(res.status, 200, `${endpoint} should stay public`);
  }
});
