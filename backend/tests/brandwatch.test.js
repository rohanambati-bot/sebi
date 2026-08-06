const test = require('node:test');
const assert = require('node:assert');
const BrandWatchEngine = require('../engines/brandwatch_engine');
const { app } = require('../server');

let baseUrl;
let server;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${server.address().port}`;
      resolve();
    });
  });
});

test.after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
});

test('Brand Watch Engine & API Test Suite', async (t) => {
  await t.test('1. Variant generation produces expected homoglyph, hyphen, and TLD variants', () => {
    const variants = BrandWatchEngine.generateVariants('zerodha.com');
    assert.ok(Array.isArray(variants), 'Variants must be an array');
    assert.ok(variants.length > 10, 'Must generate multiple typosquat variants');
    assert.ok(variants.includes('zer0dha.com'), 'Must contain 0-for-o homoglyph variant zer0dha.com');
    assert.ok(variants.includes('zerodha-kyc.com'), 'Must contain hyphenated impersonation variant zerodha-kyc.com');
    assert.ok(variants.includes('zerodha.in'), 'Must contain TLD swap variant zerodha.in');
  });

  await t.test('2. Watchlist lists protected brands with sample variants', () => {
    const watchlist = BrandWatchEngine.getWatchlist();
    assert.ok(Array.isArray(watchlist), 'Watchlist must be an array');
    assert.ok(watchlist.length >= 9, 'Must cover protected brands');
    const zerodha = watchlist.find(b => b.domain === 'zerodha.com');
    assert.ok(zerodha, 'Zerodha must be in protected watchlist');
    assert.ok(zerodha.generatedVariantCount > 0, 'Must include variant count');
  });

  await t.test('3. Scan brand returns proactive threat alerts', async () => {
    const result = await BrandWatchEngine.scanBrand('zerodha.com');
    assert.strictEqual(result.success, true, 'Scan must succeed');
    assert.ok(result.alertsFound > 0, 'Must discover proactive alerts');
    assert.ok(Array.isArray(result.alerts), 'Alerts must be an array');
    assert.ok(result.alerts[0].domain_variant.includes('zerodha') || result.alerts[0].domain_variant.includes('zer0dha'), 'Alert variant must reference brand');
  });

  await t.test('4. GET /brandwatch/watchlist returns watchlist via HTTP', async () => {
    const res = await fetch(`${baseUrl}/brandwatch/watchlist`);
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data.watchlist));
  });

  await t.test('5. GET /brandwatch/alerts returns proactive alerts feed via HTTP', async () => {
    const res = await fetch(`${baseUrl}/brandwatch/alerts`);
    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data.alerts));
  });
});
