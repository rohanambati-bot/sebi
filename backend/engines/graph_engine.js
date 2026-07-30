/**
 * SentinelSEBI IOC Graph Engine — Phase 2
 *
 * Turns the per-scan indicators extracted in Phase 1 into a persistent,
 * queryable entity graph, then clusters that graph into campaigns.
 *
 * Why this matters: a single scan identifies nobody. Ten scans sharing one UPID
 * VPA, one host, or one template identify an operation. This module is what
 * converts "risk_score: 85" into "this indicator appears in 11 other reports,
 * all clustering to one actor".
 *
 * Design notes:
 *  - Node identity is (type, value). The same VPA seen in 40 scans is one node
 *    with sighting_count=40, not 40 rows.
 *  - Edges are derived from co-occurrence within a single scan: if a message
 *    contains a domain and a VPA, those two are linked by that scan. The scan id
 *    is stored on the edge as its evidence.
 *  - Campaign clustering is connected-components over the edge set. This is
 *    deliberately simple and explainable: an investigator can always answer
 *    "why are these in the same campaign" by walking the edges. Fancier
 *    community detection (Louvain etc.) would cluster better but is far harder
 *    to defend in a regulatory context.
 */

/** Edge semantics. Chosen to be readable in a dossier, not just machine-usable. */
const REL = {
  COLLECTS_TO: 'COLLECTS_TO',       // domain/message → payment handle
  CONTACT_FOR: 'CONTACT_FOR',       // domain/message → phone/telegram
  CO_OCCURS: 'CO_OCCURS',           // generic same-message co-occurrence
  SENT_FROM: 'SENT_FROM',           // sender domain → originating IP
  SENDER_OF: 'SENDER_OF',           // sender domain → other indicators
  DELIVERED_VIA: 'DELIVERED_VIA',   // originating IP → indicators
};

/**
 * Node types that make a meaningful "hub" in a fraud graph — i.e. the entity
 * other indicators hang off. Ordered by attribution value.
 */
const HUB_TYPES = ['sender_domain', 'originating_ip', 'domain'];

/** Payment/contact rails — the endpoints a takedown actually targets. */
const RAIL_TYPES = new Set([
  'upi_vpa', 'phone_in', 'telegram', 'whatsapp',
  'wallet_btc', 'wallet_eth', 'wallet_tron', 'bank_account', 'ifsc',
]);

/**
 * Pick the relationship label for an edge based on what it connects.
 * Keeping this explicit means the graph reads as English in a report rather
 * than as a uniform blob of CO_OCCURS edges.
 */
function relationshipFor(sourceType, targetType) {
  if (sourceType === 'sender_domain' && targetType === 'originating_ip') return REL.SENT_FROM;

  if (HUB_TYPES.includes(sourceType)) {
    if (['upi_vpa', 'wallet_btc', 'wallet_eth', 'wallet_tron', 'bank_account', 'ifsc'].includes(targetType)) {
      return REL.COLLECTS_TO;
    }
    if (['phone_in', 'telegram', 'whatsapp'].includes(targetType)) return REL.CONTACT_FOR;
    if (sourceType === 'originating_ip') return REL.DELIVERED_VIA;
    return REL.SENDER_OF;
  }

  return REL.CO_OCCURS;
}

/**
 * Build the node/edge set implied by a single scan.
 *
 * Inputs are the pieces Phase 1 already produces: the analysis result (iocs,
 * domains, senderDomain) and, for email, the parsed forensic headers
 * (originatingIp). Returns plain objects; persistence is the caller's job so
 * this stays unit-testable without a database.
 */
function buildScanGraph({ iocs = [], domains = [], senderDomain = null, originatingIp = null, riskScore = 0 }) {
  const nodes = [];
  const seen = new Set();

  const addNode = (type, value) => {
    if (!type || !value) return null;
    const key = `${type}:${value}`;
    if (seen.has(key)) return key;
    seen.add(key);
    nodes.push({ type, value, riskScore });
    return key;
  };

  // Hubs first so edge direction is stable regardless of extraction order.
  if (senderDomain) addNode('sender_domain', senderDomain);
  if (originatingIp) addNode('originating_ip', originatingIp);
  for (const d of domains) {
    // A sender domain is already represented as its own, more specific type.
    if (d && d !== senderDomain) addNode('domain', d);
  }
  for (const ioc of iocs) addNode(ioc.type, ioc.value);

  // Edges: connect each hub to every rail/indicator sighted in the same scan.
  // Rails are not linked to each other directly — two VPAs in one message are
  // related *through* the message, and inventing a direct VPA↔VPA edge would
  // overstate what the evidence shows.
  const edges = [];
  const hubs = nodes.filter((n) => HUB_TYPES.includes(n.type));
  const others = nodes.filter((n) => !HUB_TYPES.includes(n.type));

  for (const hub of hubs) {
    for (const other of others) {
      edges.push({
        source: { type: hub.type, value: hub.value },
        target: { type: other.type, value: other.value },
        relationship: relationshipFor(hub.type, other.type),
      });
    }
  }

  // Link hubs to each other so a sender domain and the IP it arrived from are
  // connected — this is what makes single-indicator scans still join a cluster.
  for (let i = 0; i < hubs.length; i++) {
    for (let j = i + 1; j < hubs.length; j++) {
      edges.push({
        source: { type: hubs[i].type, value: hubs[i].value },
        target: { type: hubs[j].type, value: hubs[j].value },
        relationship: relationshipFor(hubs[i].type, hubs[j].type),
      });
    }
  }

  // A scan with exactly one rail and no hub (e.g. a bare SMS with only a VPA)
  // still contributes a node, which is correct — it can join a campaign later
  // when another scan links that VPA to a domain.

  return { nodes, edges };
}

/**
 * Connected-components clustering over an adjacency map.
 * Returns an array of arrays of node ids.
 *
 * Iterative (explicit stack) rather than recursive: a large campaign would
 * blow the call stack with a recursive DFS.
 */
function findConnectedComponents(nodeIds, adjacency) {
  const visited = new Set();
  const components = [];

  for (const start of nodeIds) {
    if (visited.has(start)) continue;

    const component = [];
    const stack = [start];
    visited.add(start);

    while (stack.length) {
      const current = stack.pop();
      component.push(current);

      for (const neighbour of adjacency.get(current) || []) {
        if (!visited.has(neighbour)) {
          visited.add(neighbour);
          stack.push(neighbour);
        }
      }
    }

    components.push(component);
  }

  return components;
}

/**
 * Human-readable campaign label derived from its highest-value members.
 * Prefers a domain (what gets DNS-blocked) then a payment rail (what gets
 * frozen), because those are the two things a notice actually names.
 */
function labelForCampaign(members) {
  const byType = (t) => members.find((m) => m.type === t);
  const anchor =
    byType('sender_domain') || byType('domain') || byType('originating_ip') ||
    members.find((m) => RAIL_TYPES.has(m.type)) || members[0];

  if (!anchor) return 'Unclustered indicators';

  const railCount = members.filter((m) => RAIL_TYPES.has(m.type)).length;
  const suffix = railCount > 0 ? ` (+${railCount} payment/contact ${railCount === 1 ? 'rail' : 'rails'})` : '';
  return `${anchor.value}${suffix}`;
}

module.exports = {
  REL,
  HUB_TYPES,
  RAIL_TYPES,
  relationshipFor,
  buildScanGraph,
  findConnectedComponents,
  labelForCampaign,
};
