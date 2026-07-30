/**
 * Phase 2 — IOC Graph & Campaign Clustering
 *
 * Covers the graph engine's pure logic (node/edge derivation, connected
 * components, labelling) and the persistence layer (upsert semantics, edge
 * evidencing, campaign rebuild, cross-scan correlation).
 */

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const TMP_DB = path.join(os.tmpdir(), `sentinel_graph_test_${process.pid}.db`);
process.env.SENTINEL_DB_PATH = TMP_DB;
process.env.SENTINEL_EVIDENCE_DIR = path.join(os.tmpdir(), `sentinel_graph_ev_${process.pid}`);
process.env.JWT_SECRET = 'test_secret_at_least_thirty_two_chars_long_xx';

const GraphEngine = require('../engines/graph_engine');
const DBSqlite = require('../db_sqlite');

test.before(async () => {
  await DBSqlite.ready;
});

test.after(() => {
  try { fs.unlinkSync(TMP_DB); } catch {}
  try { fs.rmSync(process.env.SENTINEL_EVIDENCE_DIR, { recursive: true, force: true }); } catch {}
});

const promisify = (fn) => (...args) =>
  new Promise((resolve, reject) => fn(...args, (err, r) => (err ? reject(err) : resolve(r))));

const rebuildCampaigns = promisify(DBSqlite.rebuildCampaigns.bind(DBSqlite));
const getCampaigns = promisify(DBSqlite.getCampaigns.bind(DBSqlite));
const getGraph = (opts = {}) => promisify(DBSqlite.getIocGraph.bind(DBSqlite))(opts);

let scanCounter = 0;
const makeScan = (riskScore = 90) =>
  new Promise((resolve, reject) =>
    DBSqlite.addScan(
      {
        content_type: 'text', text_or_filename: `graph test scan ${++scanCounter}`,
        sender: 'test@example.com', channel: 'email',
        risk_score: riskScore, verdict: 'HIGH_RISK_PHISHING', flags: [],
      },
      (err, id) => (err ? reject(err) : resolve(id))
    )
  );

// ───────────────────────── Graph engine (pure logic) ─────────────────────────

test('buildScanGraph: derives nodes for sender domain, IP, domains and IOCs', () => {
  const { nodes } = GraphEngine.buildScanGraph({
    senderDomain: 'sebi-govin.com',
    originatingIp: '45.33.32.156',
    domains: ['scam-payout.xyz'],
    iocs: [
      { type: 'upi_vpa', value: 'fraud@oksbi' },
      { type: 'phone_in', value: '9876543210' },
    ],
    riskScore: 95,
  });

  const keys = nodes.map((n) => `${n.type}:${n.value}`);
  assert.ok(keys.includes('sender_domain:sebi-govin.com'));
  assert.ok(keys.includes('originating_ip:45.33.32.156'));
  assert.ok(keys.includes('domain:scam-payout.xyz'));
  assert.ok(keys.includes('upi_vpa:fraud@oksbi'));
  assert.ok(keys.includes('phone_in:9876543210'));
});

test('buildScanGraph: does not duplicate the sender domain as a plain domain', () => {
  const { nodes } = GraphEngine.buildScanGraph({
    senderDomain: 'scam.example',
    domains: ['scam.example'],
    iocs: [],
  });

  assert.strictEqual(nodes.filter((n) => n.value === 'scam.example').length, 1);
  assert.strictEqual(nodes[0].type, 'sender_domain');
});

test('buildScanGraph: labels payment rails with COLLECTS_TO and contacts with CONTACT_FOR', () => {
  const { edges } = GraphEngine.buildScanGraph({
    senderDomain: 'scam.example',
    iocs: [
      { type: 'upi_vpa', value: 'fraud@ybl' },
      { type: 'telegram', value: 't.me/fraudgroup' },
    ],
  });

  const upiEdge = edges.find((e) => e.target.value === 'fraud@ybl');
  const tgEdge = edges.find((e) => e.target.value === 't.me/fraudgroup');

  assert.strictEqual(upiEdge.relationship, GraphEngine.REL.COLLECTS_TO);
  assert.strictEqual(tgEdge.relationship, GraphEngine.REL.CONTACT_FOR);
});

test('buildScanGraph: does not invent direct rail-to-rail edges', () => {
  // Two VPAs in one message are related *through* the message. A direct
  // VPA<->VPA edge would overstate what the evidence shows.
  const { edges } = GraphEngine.buildScanGraph({
    senderDomain: 'scam.example',
    iocs: [
      { type: 'upi_vpa', value: 'a@oksbi' },
      { type: 'upi_vpa', value: 'b@ybl' },
    ],
  });

  const railToRail = edges.filter(
    (e) => GraphEngine.RAIL_TYPES.has(e.source.type) && GraphEngine.RAIL_TYPES.has(e.target.type)
  );
  assert.strictEqual(railToRail.length, 0);
});

test('buildScanGraph: links sender domain to originating IP as SENT_FROM', () => {
  const { edges } = GraphEngine.buildScanGraph({
    senderDomain: 'scam.example',
    originatingIp: '203.0.113.9',
    iocs: [],
  });

  const edge = edges.find((e) => e.target.type === 'originating_ip' || e.source.type === 'originating_ip');
  assert.ok(edge);
  assert.strictEqual(edge.relationship, GraphEngine.REL.SENT_FROM);
});

test('buildScanGraph: empty input yields no nodes rather than throwing', () => {
  const { nodes, edges } = GraphEngine.buildScanGraph({});
  assert.strictEqual(nodes.length, 0);
  assert.strictEqual(edges.length, 0);
});

test('findConnectedComponents: separates unrelated clusters and merges linked ones', () => {
  const adjacency = new Map([
    [1, [2]], [2, [1, 3]], [3, [2]],   // cluster A
    [4, [5]], [5, [4]],                 // cluster B
    [6, []],                            // isolated
  ]);

  const components = GraphEngine.findConnectedComponents([1, 2, 3, 4, 5, 6], adjacency);
  const sizes = components.map((c) => c.length).sort((a, b) => b - a);

  assert.deepStrictEqual(sizes, [3, 2, 1]);
});

test('findConnectedComponents: handles a large chain without stack overflow', () => {
  // Recursive DFS would blow the call stack here; the implementation is iterative.
  const n = 20000;
  const ids = Array.from({ length: n }, (_, i) => i);
  const adjacency = new Map(ids.map((i) => [i, i < n - 1 ? [i + 1] : []]));
  for (let i = 1; i < n; i++) adjacency.get(i).push(i - 1);

  const components = GraphEngine.findConnectedComponents(ids, adjacency);
  assert.strictEqual(components.length, 1);
  assert.strictEqual(components[0].length, n);
});

test('labelForCampaign: prefers a domain anchor and counts payment rails', () => {
  const label = GraphEngine.labelForCampaign([
    { type: 'upi_vpa', value: 'fraud@oksbi' },
    { type: 'sender_domain', value: 'sebi-fake.xyz' },
    { type: 'phone_in', value: '9876543210' },
  ]);

  assert.match(label, /sebi-fake\.xyz/);
  assert.match(label, /2 payment\/contact rails/);
});

// ───────────────────────── Persistence & correlation ─────────────────────────

test('upsertIoc: re-sighting increments count instead of duplicating the row', async () => {
  const first = await DBSqlite.upsertIoc({ type: 'upi_vpa', value: 'dedup@oksbi', riskScore: 80 });
  const second = await DBSqlite.upsertIoc({ type: 'upi_vpa', value: 'dedup@oksbi', riskScore: 95 });

  assert.strictEqual(first, second, 'the same indicator must map to one row id');

  const row = await promisify(DBSqlite.getIocByValue.bind(DBSqlite))('upi_vpa', 'dedup@oksbi');
  assert.strictEqual(row.sighting_count, 2);
  assert.strictEqual(row.max_risk_score, 95, 'max risk should rise to the highest observed');
  assert.ok(row.confidence > 50, 'corroboration should raise confidence');
});

test('upsertIoc: confidence is capped so one extractor cannot reach certainty', async () => {
  for (let i = 0; i < 30; i++) {
    await DBSqlite.upsertIoc({ type: 'phone_in', value: '9000000001', riskScore: 50 });
  }
  const row = await promisify(DBSqlite.getIocByValue.bind(DBSqlite))('phone_in', '9000000001');
  assert.ok(row.confidence <= 95, `confidence must stay capped, got ${row.confidence}`);
});

test('ingestScanGraph: persists nodes, edges, and the scan association', async () => {
  const scanId = await makeScan(92);

  const { nodes, edges } = GraphEngine.buildScanGraph({
    senderDomain: 'ingest-test.example',
    originatingIp: '198.51.100.7',
    iocs: [{ type: 'upi_vpa', value: 'ingest@ybl' }],
    riskScore: 92,
  });

  const result = await DBSqlite.ingestScanGraph({ scanId, nodes, edges });

  assert.strictEqual(result.nodesWritten, 3);
  assert.ok(result.edgesWritten > 0);

  // The scan must be discoverable from the indicator — the "how do you know" path.
  const ioc = await promisify(DBSqlite.getIocByValue.bind(DBSqlite))('upi_vpa', 'ingest@ybl');
  const scans = await promisify(DBSqlite.getScansForIoc.bind(DBSqlite))(ioc.id);
  assert.ok(scans.some((s) => s.id === scanId));
});

test('correlation: two scans sharing one VPA cluster into a single campaign', async () => {
  // Distinct domains, shared payment rail — the real-world pattern where an
  // operator rotates domains but reuses the collection account.
  const scanA = await makeScan(95);
  const scanB = await makeScan(88);

  const graphA = GraphEngine.buildScanGraph({
    senderDomain: 'campaign-a.example',
    iocs: [{ type: 'upi_vpa', value: 'shared.rail@oksbi' }],
    riskScore: 95,
  });
  const graphB = GraphEngine.buildScanGraph({
    senderDomain: 'campaign-b.example',
    iocs: [{ type: 'upi_vpa', value: 'shared.rail@oksbi' }],
    riskScore: 88,
  });

  await DBSqlite.ingestScanGraph({ scanId: scanA, ...graphA });
  await DBSqlite.ingestScanGraph({ scanId: scanB, ...graphB });
  await rebuildCampaigns();

  const campaigns = await getCampaigns();
  const merged = campaigns.find((c) =>
    c.label.includes('campaign-a.example') || c.label.includes('campaign-b.example') || c.label.includes('shared.rail@oksbi')
  );

  assert.ok(merged, 'the two scans must be clustered together');
  const detail = await promisify(DBSqlite.getCampaignDetail.bind(DBSqlite))(merged.id);
  const values = detail.members.map((m) => m.value);

  assert.ok(values.includes('campaign-a.example'));
  assert.ok(values.includes('campaign-b.example'));
  assert.ok(values.includes('shared.rail@oksbi'));
  assert.ok(detail.scans.length >= 2, 'campaign must cite both evidencing scans');
});

test('correlation: unrelated indicators are not clustered together', async () => {
  const scanId = await makeScan(85);
  const graph = GraphEngine.buildScanGraph({
    senderDomain: 'totally-isolated-domain.example',
    iocs: [{ type: 'upi_vpa', value: 'isolated.rail@axl' }],
    riskScore: 85,
  });

  await DBSqlite.ingestScanGraph({ scanId, ...graph });
  await rebuildCampaigns();

  const campaigns = await getCampaigns();
  const isolated = campaigns.find((c) => c.label.includes('totally-isolated-domain.example'));
  assert.ok(isolated, 'the isolated pair should form its own campaign');

  const detail = await promisify(DBSqlite.getCampaignDetail.bind(DBSqlite))(isolated.id);
  const values = detail.members.map((m) => m.value);
  assert.ok(!values.includes('shared.rail@oksbi'), 'must not absorb an unrelated cluster');
});

test('campaigns: a lone unlinked indicator is not promoted to a campaign', async () => {
  await DBSqlite.upsertIoc({ type: 'wallet_btc', value: 'bc1qlonelyaddressnotlinkedtoanything', riskScore: 75 });
  await rebuildCampaigns();

  const campaigns = await getCampaigns();
  assert.ok(
    !campaigns.some((c) => c.label.includes('bc1qlonelyaddress')),
    'a single observation is not an operation and must not inflate campaign counts'
  );
});

test('campaigns: rebuild is idempotent and does not duplicate clusters', async () => {
  const before = await getCampaigns();
  await rebuildCampaigns();
  await rebuildCampaigns();
  const after = await getCampaigns();

  assert.strictEqual(after.length, before.length);
});

test('getIocGraph: minRisk filters out low-risk indicators', async () => {
  await DBSqlite.upsertIoc({ type: 'domain', value: 'benign-mention.example', riskScore: 5 });

  const all = await getGraph({ minRisk: 0 });
  const highOnly = await getGraph({ minRisk: 70 });

  assert.ok(all.nodes.some((n) => n.value === 'benign-mention.example'));
  assert.ok(!highOnly.nodes.some((n) => n.value === 'benign-mention.example'));
});

test('getIocGraph: every returned link references nodes present in the node set', async () => {
  const graph = await getGraph({ minRisk: 0 });
  const ids = new Set(graph.nodes.map((n) => n.id));

  for (const link of graph.links) {
    assert.ok(ids.has(link.source_ioc_id), 'dangling link source');
    assert.ok(ids.has(link.target_ioc_id), 'dangling link target');
  }
});

test('ioc_links: each edge records the scan that evidenced it', async () => {
  const scanId = await makeScan(91);
  const graph = GraphEngine.buildScanGraph({
    senderDomain: 'evidence-edge.example',
    iocs: [{ type: 'upi_vpa', value: 'evidence.edge@ibl' }],
    riskScore: 91,
  });
  await DBSqlite.ingestScanGraph({ scanId, ...graph });

  const full = await getGraph({ minRisk: 0 });
  const ioc = await promisify(DBSqlite.getIocByValue.bind(DBSqlite))('upi_vpa', 'evidence.edge@ibl');
  const edge = full.links.find((l) => l.target_ioc_id === ioc.id || l.source_ioc_id === ioc.id);

  assert.ok(edge, 'edge should exist');
  assert.strictEqual(edge.evidence_scan_id, scanId, 'an unsourced edge is a liability in a dossier');
});

test('getGraphStats: reports counts and a per-type breakdown', async () => {
  const stats = await promisify(DBSqlite.getGraphStats.bind(DBSqlite))();

  assert.ok(stats.iocCount > 0);
  assert.ok(stats.linkCount > 0);
  assert.ok(Array.isArray(stats.byType));
  assert.ok(stats.byType.some((t) => t.type === 'upi_vpa'));
});
