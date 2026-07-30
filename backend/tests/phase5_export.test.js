/**
 * Phase 5 — Interoperability and regulatory output.
 *
 * The most important assertions here are about honesty, not format: that the
 * dossier states its limitations, that non-standard indicators are not coerced
 * into ill-fitting STIX types, and that ATT&CK coverage is not invented for
 * flags that do not map to a real technique.
 */

const test = require('node:test');
const assert = require('node:assert');

const { ExportEngine, stixId, stixPatternFor, ATTACK_TECHNIQUES } = require('../engines/export_engine');

const sampleIocs = [
  { id: 1, type: 'sender_domain', value: 'sebi-fake.xyz', first_seen: '2026-07-01T00:00:00.000Z', last_seen: '2026-07-05T00:00:00.000Z', sighting_count: 3, confidence: 70, max_risk_score: 95 },
  { id: 2, type: 'upi_vpa', value: 'fraud@oksbi', first_seen: '2026-07-01T00:00:00.000Z', last_seen: '2026-07-06T00:00:00.000Z', sighting_count: 5, confidence: 80, max_risk_score: 95 },
  { id: 3, type: 'originating_ip', value: '203.0.113.9', first_seen: '2026-07-02T00:00:00.000Z', last_seen: '2026-07-02T00:00:00.000Z', sighting_count: 1, confidence: 55, max_risk_score: 90 },
];

const sampleLinks = [
  { source_ioc_id: 1, target_ioc_id: 2, relationship: 'COLLECTS_TO', evidence_scan_id: 42, confidence: 65, first_seen: '2026-07-01T00:00:00.000Z' },
  { source_ioc_id: 1, target_ioc_id: 3, relationship: 'SENT_FROM', evidence_scan_id: 42, confidence: 65, first_seen: '2026-07-02T00:00:00.000Z' },
];

const sampleCampaign = {
  id: 7, label: 'sebi-fake.xyz (+1 payment/contact rail)', cluster_method: 'connected_components',
  member_count: 3, max_risk_score: 95, first_seen: '2026-07-01T00:00:00.000Z',
  last_seen: '2026-07-06T00:00:00.000Z', status: 'ACTIVE', created_at: '2026-07-06T00:00:00.000Z',
};

// ───────────────────────── STIX identifiers ─────────────────────────

test('stixId is deterministic for the same logical object', () => {
  // Re-exporting must not create duplicates in the consumer's store.
  assert.strictEqual(stixId('indicator', 'domain:a.example'), stixId('indicator', 'domain:a.example'));
});

test('stixId differs across objects and types', () => {
  assert.notStrictEqual(stixId('indicator', 'domain:a.example'), stixId('indicator', 'domain:b.example'));
  assert.notStrictEqual(stixId('indicator', 'x'), stixId('campaign', 'x'));
});

test('stixId is shaped as a valid STIX identifier', () => {
  assert.match(stixId('indicator', 'seed'), /^indicator--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

// ───────────────────────── STIX patterns ─────────────────────────

test('standard observable types map to real STIX patterns', () => {
  assert.strictEqual(stixPatternFor('domain', 'a.example'), "[domain-name:value = 'a.example']");
  assert.strictEqual(stixPatternFor('originating_ip', '1.2.3.4'), "[ipv4-addr:value = '1.2.3.4']");
  assert.strictEqual(stixPatternFor('originating_ip', '2606:4700::1'), "[ipv6-addr:value = '2606:4700::1']");
  assert.strictEqual(stixPatternFor('file_hash', 'abc123'), "[file:hashes.'SHA-256' = 'abc123']");
});

test('non-standard indicator types return null instead of a forced mapping', () => {
  // Coercing a UPI handle into email-addr would corrupt a consumer's data model.
  for (const type of ['upi_vpa', 'phone_in', 'telegram', 'wallet_btc', 'ifsc']) {
    assert.strictEqual(stixPatternFor(type, 'x'), null, `${type} must not be force-mapped`);
  }
});

test('stixPatternFor escapes quotes to prevent pattern injection', () => {
  const pattern = stixPatternFor('domain', "evil'.example");
  assert.ok(pattern.includes("\\'"), 'single quotes must be escaped');
});

// ───────────────────────── STIX bundle ─────────────────────────

test('bundle contains an identity, indicators and relationships', () => {
  const bundle = ExportEngine.buildStixBundle({ iocs: sampleIocs, links: sampleLinks, campaigns: [] });

  assert.strictEqual(bundle.type, 'bundle');
  assert.match(bundle.id, /^bundle--/);

  const types = bundle.objects.map((o) => o.type);
  assert.ok(types.includes('identity'));
  assert.strictEqual(types.filter((t) => t === 'indicator').length, 3);
  assert.strictEqual(types.filter((t) => t === 'relationship').length, 2);
});

test('every bundle object declares spec_version 2.1', () => {
  const bundle = ExportEngine.buildStixBundle({ iocs: sampleIocs, links: sampleLinks, campaigns: [sampleCampaign], campaignMembers: new Map([[7, [1, 2, 3]]]) });

  for (const obj of bundle.objects) {
    if (obj.type === 'bundle') continue;
    assert.strictEqual(obj.spec_version, '2.1', `${obj.type} must declare spec_version`);
  }
});

test('indicators carry validity, confidence and sighting provenance', () => {
  const bundle = ExportEngine.buildStixBundle({ iocs: sampleIocs, links: [], campaigns: [] });
  const indicator = bundle.objects.find((o) => o.type === 'indicator' && o.x_sentinel_value === 'fraud@oksbi');

  assert.ok(indicator);
  assert.strictEqual(indicator.valid_from, '2026-07-01T00:00:00.000Z');
  assert.strictEqual(indicator.confidence, 80);
  assert.strictEqual(indicator.x_sentinel_sighting_count, 5);
});

test('a non-standard indicator uses a custom pattern_type, not a fake STIX one', () => {
  const bundle = ExportEngine.buildStixBundle({ iocs: sampleIocs, links: [], campaigns: [] });
  const upi = bundle.objects.find((o) => o.x_sentinel_indicator_type === 'upi_vpa');

  assert.strictEqual(upi.pattern_type, 'sentinel-custom');
  assert.ok(upi.x_sentinel_value, 'the raw observable must still be preserved');
});

test('relationships reference indicator ids that exist in the bundle', () => {
  const bundle = ExportEngine.buildStixBundle({ iocs: sampleIocs, links: sampleLinks, campaigns: [] });
  const ids = new Set(bundle.objects.filter((o) => o.type === 'indicator').map((o) => o.id));

  for (const rel of bundle.objects.filter((o) => o.type === 'relationship')) {
    assert.ok(ids.has(rel.source_ref) || rel.target_ref.startsWith('campaign--'),
      'dangling source_ref');
  }
});

test('relationships preserve the evidencing scan id', () => {
  const bundle = ExportEngine.buildStixBundle({ iocs: sampleIocs, links: sampleLinks, campaigns: [] });
  const rel = bundle.objects.find((o) => o.type === 'relationship' && o.x_sentinel_relationship === 'COLLECTS_TO');

  assert.strictEqual(rel.x_sentinel_evidence_scan_id, 42,
    'an unsourced relationship cannot be defended in a dossier');
});

test('a link referencing an absent indicator is skipped rather than dangling', () => {
  const bundle = ExportEngine.buildStixBundle({
    iocs: [sampleIocs[0]],
    links: [{ source_ioc_id: 1, target_ioc_id: 999, relationship: 'COLLECTS_TO', confidence: 50, first_seen: '2026-07-01T00:00:00.000Z' }],
    campaigns: [],
  });

  assert.strictEqual(bundle.objects.filter((o) => o.type === 'relationship').length, 0);
});

test('campaigns emit indicates relationships for their members', () => {
  const bundle = ExportEngine.buildStixBundle({
    iocs: sampleIocs, links: [], campaigns: [sampleCampaign],
    campaignMembers: new Map([[7, [1, 2, 3]]]),
  });

  const campaign = bundle.objects.find((o) => o.type === 'campaign');
  assert.ok(campaign);
  assert.strictEqual(campaign.name, sampleCampaign.label);

  const indicates = bundle.objects.filter((o) => o.type === 'relationship' && o.relationship_type === 'indicates');
  assert.strictEqual(indicates.length, 3);
});

test('an empty graph still produces a valid bundle', () => {
  const bundle = ExportEngine.buildStixBundle({});
  assert.strictEqual(bundle.type, 'bundle');
  assert.ok(bundle.objects.some((o) => o.type === 'identity'));
});

// ───────────────────────── ATT&CK mapping ─────────────────────────

test('known flags map to real ATT&CK techniques', () => {
  const techniques = ExportEngine.mapFlagsToAttack([
    { type: 'typosquatting_domain' },
    { type: 'sender_spoofing' },
    { type: 'unverified_payment_ask' },
  ]);

  const ids = techniques.map((t) => t.id);
  assert.ok(ids.includes('T1583.001'));
  assert.ok(ids.includes('T1656'));
  assert.ok(ids.includes('T1657'));
});

test('unknown flags do not invent ATT&CK coverage', () => {
  // Fabricated coverage would mislead an analyst pivoting on the technique.
  const techniques = ExportEngine.mapFlagsToAttack([
    { type: 'some_flag_with_no_technique' },
    { type: 'another_unmapped_flag' },
  ]);
  assert.strictEqual(techniques.length, 0);
});

test('duplicate techniques are collapsed', () => {
  const techniques = ExportEngine.mapFlagsToAttack([
    { type: 'sender_spoofing' },
    { type: 'missing_dkim_signature' }, // also T1656
  ]);
  assert.strictEqual(techniques.length, 1);
});

test('mapFlagsToAttack tolerates empty and malformed input', () => {
  assert.deepStrictEqual(ExportEngine.mapFlagsToAttack([]), []);
  assert.deepStrictEqual(ExportEngine.mapFlagsToAttack(), []);
});

test('every mapped technique has an id and a name', () => {
  for (const [flag, technique] of Object.entries(ATTACK_TECHNIQUES)) {
    assert.match(technique.id, /^T\d{4}(\.\d{3})?$/, `${flag} has a malformed technique id`);
    assert.ok(technique.name && technique.name.length > 0, `${flag} is missing a technique name`);
  }
});

// ───────────────────────── MISP export ─────────────────────────

test('MISP event maps indicator types and restricts distribution', () => {
  const event = ExportEngine.buildMispEvent({ campaign: sampleCampaign, iocs: sampleIocs });

  assert.ok(event.Event);
  // Distribution 0 = your organisation only. These are unvalidated leads and
  // must not default to community-wide sharing.
  assert.strictEqual(event.Event.distribution, '0');
  assert.strictEqual(event.Event.Attribute.length, 3);

  const domainAttr = event.Event.Attribute.find((a) => a.value === 'sebi-fake.xyz');
  assert.strictEqual(domainAttr.type, 'domain');
  assert.strictEqual(domainAttr.to_ids, true);
});

test('MISP export handles an empty indicator set', () => {
  const event = ExportEngine.buildMispEvent({ campaign: null, iocs: [] });
  assert.strictEqual(event.Event.Attribute.length, 0);
});

// ───────────────────────── Dossier ─────────────────────────

test('dossier includes campaign, indicators, scans and custody', () => {
  const dossier = ExportEngine.buildDossier({
    campaign: sampleCampaign,
    iocs: sampleIocs,
    scans: [{ id: 42, content_type: 'eml', sender: 'x@sebi-fake.xyz', verdict: 'HIGH_RISK_PHISHING', risk_score: 95, created_at: '2026-07-01T00:00:00.000Z' }],
    evidence: [{ sha256: 'a'.repeat(64), md5: 'b'.repeat(32), size_bytes: 1024, original_filename: 'scam.eml', created_at: '2026-07-01T00:00:00.000Z', entry_hash: 'c'.repeat(64) }],
    attackTechniques: [{ id: 'T1566', name: 'Phishing' }],
  });

  assert.strictEqual(dossier.campaign.id, 7);
  assert.strictEqual(dossier.indicators.length, 3);
  assert.strictEqual(dossier.evidencing_scans.length, 1);
  assert.strictEqual(dossier.chain_of_custody.length, 1);
  assert.strictEqual(dossier.chain_of_custody[0].custody_hash, 'c'.repeat(64));
  assert.ok(dossier.generated_at);
});

test('dossier always states its limitations', () => {
  const dossier = ExportEngine.buildDossier({ campaign: null, iocs: [], scans: [] });

  assert.ok(Array.isArray(dossier.limitations));
  assert.ok(dossier.limitations.length >= 5, 'limitations must not be trimmed away');

  const combined = dossier.limitations.join(' ');
  // Each of these is a claim the platform must NOT be read as making.
  assert.match(combined, /legal process/i, 'must state identity attribution needs legal process');
  assert.match(combined, /CGNAT|VPN/i, 'must state an IP alone is insufficient');
  assert.match(combined, /uncalibrated|unmeasured/i, 'must disclose uncalibrated similarity thresholds');
  assert.match(combined, /held-out/i, 'must disclose the benchmark caveat');
  assert.match(combined, /timestamp authority/i, 'must bound what the hash chain proves');
});

test('dossier records enrichment provenance with a staleness caveat', () => {
  const dossier = ExportEngine.buildDossier({
    campaign: sampleCampaign, iocs: [], scans: [],
    enrichment: [{ indicator_value: 'sebi-fake.xyz', source: 'rdap', retrieved_at: '2026-07-06T00:00:00.000Z' }],
  });

  assert.strictEqual(dossier.enrichment_provenance.length, 1);
  assert.match(dossier.enrichment_provenance[0].note, /at retrieval time/i);
});

test('dossier is generated without a campaign for ad-hoc indicator sets', () => {
  const dossier = ExportEngine.buildDossier({ iocs: sampleIocs, scans: [] });
  assert.strictEqual(dossier.campaign, null);
  assert.strictEqual(dossier.indicators.length, 3);
});
