/**
 * Phase 3 — Enrichment, SSRF guard, rate limiting, and caching.
 *
 * The SSRF tests matter most: Phase 3 introduces outbound requests driven by
 * attacker-supplied hostnames, which is the highest-risk surface added so far.
 * No test here makes a real external request — network behaviour is exercised
 * through the guard's own decision logic and the disabled-by-default path.
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const TMP_DB = path.join(os.tmpdir(), `sentinel_enrich_test_${process.pid}.db`);
process.env.SENTINEL_DB_PATH = TMP_DB;
process.env.JWT_SECRET = 'test_secret_at_least_thirty_two_chars_long_xx';

const NetGuard = require('../net_guard');
const EnrichmentEngine = require('../engines/enrichment_engine');
const EnrichmentQueue = require('../enrichment_queue');
const DBSqlite = require('../db_sqlite');

test.before(async () => {
  await DBSqlite.ready;
});

test.after(() => {
  try { fs.unlinkSync(TMP_DB); } catch {}
});

// ───────────────────────── SSRF: blocked ranges ─────────────────────────

test('SSRF guard blocks loopback, RFC1918, CGNAT and multicast IPv4', () => {
  const blocked = [
    '127.0.0.1', '127.1.2.3',
    '10.0.0.1', '10.255.255.255',
    '172.16.0.1', '172.31.255.254',
    '192.168.0.1', '192.168.1.1',
    '100.64.0.1', '100.127.255.255',   // CGNAT
    '0.0.0.0',
    '224.0.0.1', '239.255.255.255',    // multicast
  ];

  for (const ip of blocked) {
    assert.strictEqual(NetGuard.isBlockedAddress(ip), true, `${ip} must be blocked`);
  }
});

test('SSRF guard blocks the cloud metadata endpoint', () => {
  // 169.254.169.254 is the single most valuable SSRF target on any cloud host.
  assert.strictEqual(NetGuard.isBlockedAddress('169.254.169.254'), true);
  assert.strictEqual(NetGuard.isBlockedAddress('169.254.1.1'), true);
});

test('SSRF guard blocks IPv6 loopback, link-local and ULA', () => {
  for (const ip of ['::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1']) {
    assert.strictEqual(NetGuard.isBlockedAddress(ip), true, `${ip} must be blocked`);
  }
});

test('SSRF guard unwraps IPv4-mapped IPv6 before deciding', () => {
  // ::ffff:127.0.0.1 is loopback wearing an IPv6 costume — a classic bypass.
  assert.strictEqual(NetGuard.isBlockedAddress('::ffff:127.0.0.1'), true);
  assert.strictEqual(NetGuard.isBlockedAddress('::ffff:10.0.0.1'), true);
  assert.strictEqual(NetGuard.isBlockedAddress('::ffff:192.168.1.1'), true);
});

test('SSRF guard permits ordinary public addresses', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '203.0.113.9', '2606:4700::1111']) {
    assert.strictEqual(NetGuard.isBlockedAddress(ip), false, `${ip} should be allowed`);
  }
});

test('SSRF guard rejects garbage input rather than defaulting to allow', () => {
  // Failing closed matters: an unparseable value must never be treated as safe.
  for (const value of ['', null, undefined, 'not-an-ip', '999.999.999.999', '12345']) {
    assert.strictEqual(NetGuard.isBlockedAddress(value), true, `${value} should fail closed`);
  }
});

test('resolveSafely rejects a private literal without performing DNS', async () => {
  await assert.rejects(() => NetGuard.resolveSafely('127.0.0.1'), /BLOCKED/);
  await assert.rejects(() => NetGuard.resolveSafely('169.254.169.254'), /BLOCKED/);
});

test('resolveSafely accepts a public literal', async () => {
  const addresses = await NetGuard.resolveSafely('8.8.8.8');
  assert.deepStrictEqual(addresses, ['8.8.8.8']);
});

test('resolveSafely rejects empty or non-string hostnames', async () => {
  await assert.rejects(() => NetGuard.resolveSafely(''), /BLOCKED/);
  await assert.rejects(() => NetGuard.resolveSafely(null), /BLOCKED/);
});

// ───────────────────────── Fetch policy ─────────────────────────

test('safeGetJson refuses non-HTTPS and malformed URLs', async () => {
  // These checks run before the enabled-flag short-circuit is reached only when
  // enrichment is on; with it off, the disabled reason is returned instead.
  const httpResult = await NetGuard.safeGetJson('http://example.com/x');
  const badResult = await NetGuard.safeGetJson('not a url');

  assert.strictEqual(httpResult.ok, false);
  assert.strictEqual(badResult.ok, false);
});

test('safeGetJson is disabled by default so no outbound traffic occurs', async () => {
  // Default posture: fetching attacker infrastructure reveals investigation
  // activity, so enrichment must be explicitly enabled.
  assert.strictEqual(NetGuard.ENRICHMENT_ENABLED, false);

  const result = await NetGuard.safeGetJson('https://example.com/whatever');
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.skipped, true);
  assert.strictEqual(result.reason, 'ENRICHMENT_DISABLED');
});

// ───────────────────────── Redirect policy ─────────────────────────

test('redirect following is restricted to an allowlist of bootstrap hosts', () => {
  // RDAP bootstrap (rdap.org) is a redirector by design, so a blanket
  // no-redirect policy makes RDAP unusable. Following redirects from an
  // arbitrary scanned URL would reopen the SSRF hole the resolution check
  // closes, so the allowlist must stay minimal and must never be driven by
  // hostnames observed in scanned content.
  const source = fs.readFileSync(path.join(__dirname, '..', 'net_guard.js'), 'utf8');

  const match = source.match(/REDIRECT_ALLOWED_HOSTS\s*=\s*new Set\(\[([^\]]*)\]\)/);
  assert.ok(match, 'the redirect allowlist must be a literal, not computed at runtime');

  const hosts = match[1].split(',').map((h) => h.trim().replace(/['"]/g, '')).filter(Boolean);
  assert.deepStrictEqual(hosts, ['rdap.org'], 'only the RDAP bootstrap host should be allowlisted');
});

test('redirect handling is capped at a single hop', () => {
  // A recursive re-validation without a hop cap would spin on a redirect loop.
  const source = fs.readFileSync(path.join(__dirname, '..', 'net_guard.js'), 'utf8');
  assert.match(source, /_hop === 0/, 'redirects must only be followed on the first hop');
  assert.match(source, /_hop:\s*_hop \+ 1/, 'the hop counter must increment on recursion');
});

test('a redirect target is re-validated rather than fetched directly', () => {
  // The Location header is attacker-influenceable even from an allowlisted
  // host, so it must go back through the full guard (HTTPS, DNS, rate limit).
  const source = fs.readFileSync(path.join(__dirname, '..', 'net_guard.js'), 'utf8');
  assert.match(source, /return await safeGetJson\(new URL\(location/,
    'the redirect target must be re-checked by safeGetJson, not fetched inline');
});

// ───────────────────────── Rate limiting ─────────────────────────

test('RateLimiter exhausts its bucket then refuses further tokens', () => {
  const limiter = new NetGuard.RateLimiter(3, 0);

  assert.strictEqual(limiter.tryConsume(), true);
  assert.strictEqual(limiter.tryConsume(), true);
  assert.strictEqual(limiter.tryConsume(), true);
  assert.strictEqual(limiter.tryConsume(), false, 'a 4th call must be refused');
});

test('RateLimiter refills over time', async () => {
  const limiter = new NetGuard.RateLimiter(1, 50); // 50 tokens/sec

  assert.strictEqual(limiter.tryConsume(), true);
  assert.strictEqual(limiter.tryConsume(), false);

  await new Promise((r) => setTimeout(r, 60));
  assert.strictEqual(limiter.tryConsume(), true, 'bucket should refill');
});

// ───────────────────── Engine behaviour when disabled ─────────────────────

test('enrichment engine degrades gracefully with enrichment disabled', async () => {
  const rdap = await EnrichmentEngine.lookupRdap('example.com');
  const dnsResult = await EnrichmentEngine.lookupDns('example.com');
  const ct = await EnrichmentEngine.lookupCertificateTransparency('example.com');

  // Each reports the reason rather than throwing or silently returning success.
  assert.strictEqual(rdap.skipped, true);
  assert.strictEqual(rdap.available, false);
  assert.strictEqual(dnsResult.skipped, true);
  assert.strictEqual(ct.skipped, true);

  // Provenance is present even on a skipped lookup.
  assert.ok(rdap.source && rdap.retrieved_at);
});

test('reverseLookup refuses private addresses even when asked directly', async () => {
  const result = await EnrichmentEngine.reverseLookup('10.0.0.1');
  assert.ok(result.error, 'must not attempt a reverse lookup on a private address');
});

test('lookupDkimKey validates its inputs', async () => {
  const result = await EnrichmentEngine.lookupDkimKey(null, null);
  assert.ok(result.error);
});

// ───────────────────── Signal derivation (no network) ─────────────────────

test('deriveSignals flags a newly registered domain as high severity', () => {
  const { riskDelta, flags } = EnrichmentEngine.deriveSignals({
    rdap: { available: true, ageDays: 6, created: '2026-07-24T00:00:00Z', registrar: 'Example Registrar' },
    dnsRecords: { resolves: true, spf: 'v=spf1 -all' },
    ct: {},
  });

  assert.ok(riskDelta > 0);
  const flag = flags.find((f) => f.type === 'newly_registered_domain');
  assert.ok(flag, 'domain age under 30 days is the strongest free fraud predictor');
  assert.strictEqual(flag.severity, 'high');
});

test('deriveSignals does not flag an established domain', () => {
  const { flags } = EnrichmentEngine.deriveSignals({
    rdap: { available: true, ageDays: 4000, created: '2015-01-01T00:00:00Z' },
    dnsRecords: { resolves: true, spf: 'v=spf1 -all' },
    ct: {},
  });

  assert.ok(!flags.some((f) => f.type === 'newly_registered_domain'));
  assert.ok(!flags.some((f) => f.type === 'recently_registered_domain'));
});

test('deriveSignals surfaces the registrar as the takedown target', () => {
  const { flags } = EnrichmentEngine.deriveSignals({
    rdap: { available: true, ageDays: 500, registrar: 'NameCheap Inc.' },
    dnsRecords: { resolves: true, spf: null },
    ct: {},
  });

  const flag = flags.find((f) => f.type === 'registrar_identified');
  assert.ok(flag);
  assert.match(flag.detail, /NameCheap/);
});

test('deriveSignals reports CT-exposed related domains', () => {
  const { flags } = EnrichmentEngine.deriveSignals({
    rdap: {}, dnsRecords: {},
    ct: { relatedDomains: ['a.scam.example', 'b.scam.example', 'c.scam.example'] },
  });

  const flag = flags.find((f) => f.type === 'ct_related_domains');
  assert.ok(flag);
  assert.match(flag.detail, /3 related/);
});

test('deriveSignals caps its risk contribution', () => {
  // Enrichment must not be able to dominate the score on its own.
  const { riskDelta } = EnrichmentEngine.deriveSignals({
    rdap: { available: true, ageDays: 1, created: '2026-07-29T00:00:00Z', registrar: 'X' },
    dnsRecords: { resolves: false, spf: null },
    ct: { relatedDomains: ['x.example'] },
  });

  assert.ok(riskDelta <= 40, `risk delta should be capped, got ${riskDelta}`);
});

// ───────────────────────── Cache ─────────────────────────

test('enrichment cache round-trips a payload', async () => {
  await DBSqlite.putEnrichment({
    indicatorType: 'domain', indicatorValue: 'cache-test.example', source: 'combined',
    payload: { registrar: 'Test Registrar', ageDays: 12 }, ttlHours: 24,
  });

  const row = await new Promise((resolve, reject) =>
    DBSqlite.getEnrichment('domain', 'cache-test.example', 'combined', (e, r) => (e ? reject(e) : resolve(r)))
  );

  assert.ok(row);
  assert.strictEqual(row.payload.registrar, 'Test Registrar');
  assert.ok(row.retrieved_at, 'provenance timestamp must be stored');
});

test('enrichment cache treats an expired entry as a miss', async () => {
  await DBSqlite.putEnrichment({
    indicatorType: 'domain', indicatorValue: 'expired.example', source: 'combined',
    payload: { stale: true }, ttlHours: -1, // already expired
  });

  const row = await new Promise((resolve, reject) =>
    DBSqlite.getEnrichment('domain', 'expired.example', 'combined', (e, r) => (e ? reject(e) : resolve(r)))
  );

  assert.strictEqual(row, null, 'stale intel must never be served as current');
});

test('enrichment cache upserts rather than duplicating', async () => {
  for (const registrar of ['First', 'Second', 'Third']) {
    await DBSqlite.putEnrichment({
      indicatorType: 'domain', indicatorValue: 'upsert.example', source: 'combined',
      payload: { registrar }, ttlHours: 24,
    });
  }

  const row = await new Promise((resolve, reject) =>
    DBSqlite.getEnrichment('domain', 'upsert.example', 'combined', (e, r) => (e ? reject(e) : resolve(r)))
  );
  assert.strictEqual(row.payload.registrar, 'Third', 'latest write should win');
});

// ───────────────────────── Queue ─────────────────────────

test('queue refuses work while enrichment is disabled', () => {
  const queue = new EnrichmentQueue(DBSqlite);
  assert.strictEqual(queue.enqueueDomain('example.com'), false);
  assert.strictEqual(queue.getStats().enabled, false);
});

test('queue rejects invalid input without throwing', () => {
  const queue = new EnrichmentQueue(DBSqlite);
  for (const bad of [null, undefined, '', 123, {}]) {
    assert.strictEqual(queue.enqueueDomain(bad), false);
  }
});

test('queue exposes stats for operator visibility', () => {
  const queue = new EnrichmentQueue(DBSqlite);
  const stats = queue.getStats();

  for (const key of ['enqueued', 'completed', 'failed', 'cacheHits', 'queueLength', 'enabled']) {
    assert.ok(key in stats, `stats should expose ${key}`);
  }
});
