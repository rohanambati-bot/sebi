/**
 * SentinelSEBI Export Engine — Phase 5
 *
 * Makes platform output consumable by systems that already exist, which is what
 * separates a demo from a platform.
 *
 *  - STIX 2.1 bundles for IOCs and campaigns. The Phase 2 iocs/ioc_links schema
 *    maps almost directly onto SDOs and SROs.
 *  - MITRE ATT&CK technique tagging so analysts can pivot in familiar terms.
 *  - A structured dossier combining custody, provenance, and confidence.
 */

const crypto = require('crypto');

/**
 * Deterministic STIX id.
 *
 * STIX ids should be stable for the same logical object so re-exporting does
 * not create duplicates in the consumer's store. A UUIDv5-style namespaced hash
 * of the indicator gives that stability without a uuid dependency.
 */
function stixId(type, seed) {
  const hash = crypto.createHash('sha1').update(`sentinel-sebi:${type}:${seed}`).digest('hex');
  const uuid = [
    hash.slice(0, 8),
    hash.slice(8, 12),
    // Version nibble set to 5 to signal a name-based UUID.
    '5' + hash.slice(13, 16),
    ((parseInt(hash.slice(16, 17), 16) & 0x3) | 0x8).toString(16) + hash.slice(17, 20),
    hash.slice(20, 32),
  ].join('-');
  return `${type}--${uuid}`;
}

/**
 * Map an internal IOC type to a STIX Cyber-observable pattern.
 * Returns null for types with no standard STIX representation (UPI handles,
 * IFSC codes) — those are emitted as custom properties instead of being forced
 * into an ill-fitting standard type.
 */
function stixPatternFor(type, value) {
  const escaped = String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'");

  switch (type) {
    case 'domain':
    case 'sender_domain':
      return `[domain-name:value = '${escaped}']`;
    case 'originating_ip':
      return value.includes(':')
        ? `[ipv6-addr:value = '${escaped}']`
        : `[ipv4-addr:value = '${escaped}']`;
    case 'url':
      return `[url:value = '${escaped}']`;
    case 'file_hash':
      return `[file:hashes.'SHA-256' = '${escaped}']`;
    case 'email':
      return `[email-addr:value = '${escaped}']`;
    default:
      return null;
  }
}

/**
 * MITRE ATT&CK technique mapping for our flag types.
 * Only techniques that genuinely describe the observed behaviour are mapped;
 * inventing coverage would mislead an analyst pivoting on them.
 */
const ATTACK_TECHNIQUES = {
  typosquatting_domain: { id: 'T1583.001', name: 'Acquire Infrastructure: Domains' },
  sender_spoofing: { id: 'T1656', name: 'Impersonation' },
  missing_dkim_signature: { id: 'T1656', name: 'Impersonation' },
  malformed_dkim_signature: { id: 'T1656', name: 'Impersonation' },
  scam_return_language: { id: 'T1566', name: 'Phishing' },
  urgency_manipulation: { id: 'T1566', name: 'Phishing' },
  credential_harvesting: { id: 'T1566.002', name: 'Phishing: Spearphishing Link' },
  unverified_payment_ask: { id: 'T1657', name: 'Financial Theft' },
  encrypted_unscannable_payload: { id: 'T1027', name: 'Obfuscated Files or Information' },
  high_entropy_obfuscation: { id: 'T1027', name: 'Obfuscated Files or Information' },
  newly_registered_domain: { id: 'T1583.001', name: 'Acquire Infrastructure: Domains' },
  ct_related_domains: { id: 'T1583.001', name: 'Acquire Infrastructure: Domains' },
};

class ExportEngine {
  /** Techniques implied by a set of flags, deduplicated. */
  static mapFlagsToAttack(flags = []) {
    const seen = new Map();
    for (const flag of flags) {
      const technique = ATTACK_TECHNIQUES[flag.type];
      if (technique && !seen.has(technique.id)) {
        seen.set(technique.id, { ...technique, matchedFlag: flag.type });
      }
    }
    return [...seen.values()];
  }

  /**
   * Build a STIX 2.1 bundle from IOCs, edges and campaigns.
   *
   * Indicators carry `valid_from` = first_seen and a confidence value so a
   * consumer can age and weight them rather than treating all as equally fresh.
   */
  static buildStixBundle({ iocs = [], links = [], campaigns = [], campaignMembers = new Map() }) {
    const objects = [];
    const identityId = stixId('identity', 'sentinel-sebi-platform');

    objects.push({
      type: 'identity',
      spec_version: '2.1',
      id: identityId,
      created: '2026-01-01T00:00:00.000Z',
      modified: '2026-01-01T00:00:00.000Z',
      name: 'SentinelSEBI',
      identity_class: 'system',
      description: 'AI-driven detection of synthetic media and phishing in securities markets.',
    });

    const indicatorIdByIocId = new Map();

    for (const ioc of iocs) {
      const pattern = stixPatternFor(ioc.type, ioc.value);
      const id = stixId('indicator', `${ioc.type}:${ioc.value}`);
      indicatorIdByIocId.set(ioc.id, id);

      const indicator = {
        type: 'indicator',
        spec_version: '2.1',
        id,
        created_by_ref: identityId,
        created: ioc.first_seen,
        modified: ioc.last_seen,
        name: `${ioc.type}: ${ioc.value}`,
        indicator_types: ['malicious-activity'],
        valid_from: ioc.first_seen,
        confidence: ioc.confidence,
        labels: [ioc.type],
        // Non-standard indicator types (upi_vpa, phone_in, wallets) have no
        // STIX pattern, so the raw observable is preserved in a custom property
        // rather than being coerced into a standard type it does not fit.
        x_sentinel_indicator_type: ioc.type,
        x_sentinel_value: ioc.value,
        x_sentinel_sighting_count: ioc.sighting_count,
        x_sentinel_max_risk_score: ioc.max_risk_score,
      };

      if (pattern) {
        indicator.pattern = pattern;
        indicator.pattern_type = 'stix';
      } else {
        indicator.pattern_type = 'sentinel-custom';
        indicator.pattern = `[x-sentinel:${ioc.type} = '${ioc.value}']`;
      }

      objects.push(indicator);
    }

    for (const link of links) {
      const sourceRef = indicatorIdByIocId.get(link.source_ioc_id);
      const targetRef = indicatorIdByIocId.get(link.target_ioc_id);
      if (!sourceRef || !targetRef) continue;

      objects.push({
        type: 'relationship',
        spec_version: '2.1',
        id: stixId('relationship', `${link.source_ioc_id}-${link.target_ioc_id}-${link.relationship}`),
        created_by_ref: identityId,
        created: link.first_seen,
        modified: link.first_seen,
        relationship_type: 'related-to',
        source_ref: sourceRef,
        target_ref: targetRef,
        confidence: link.confidence,
        description: link.relationship,
        x_sentinel_relationship: link.relationship,
        x_sentinel_evidence_scan_id: link.evidence_scan_id,
      });
    }

    for (const campaign of campaigns) {
      const campaignStixId = stixId('campaign', `campaign-${campaign.id}`);
      objects.push({
        type: 'campaign',
        spec_version: '2.1',
        id: campaignStixId,
        created_by_ref: identityId,
        created: campaign.first_seen || campaign.created_at,
        modified: campaign.last_seen || campaign.created_at,
        name: campaign.label,
        description: `Clustered by ${campaign.cluster_method} over extracted indicators. ${campaign.member_count} correlated indicators.`,
        first_seen: campaign.first_seen || undefined,
        last_seen: campaign.last_seen || undefined,
        x_sentinel_member_count: campaign.member_count,
        x_sentinel_max_risk_score: campaign.max_risk_score,
      });

      for (const iocId of campaignMembers.get(campaign.id) || []) {
        const indicatorRef = indicatorIdByIocId.get(iocId);
        if (!indicatorRef) continue;

        objects.push({
          type: 'relationship',
          spec_version: '2.1',
          id: stixId('relationship', `campaign-${campaign.id}-indicates-${iocId}`),
          created_by_ref: identityId,
          created: campaign.created_at,
          modified: campaign.created_at,
          relationship_type: 'indicates',
          source_ref: indicatorRef,
          target_ref: campaignStixId,
        });
      }
    }

    return {
      type: 'bundle',
      id: `bundle--${crypto.randomUUID()}`,
      objects,
    };
  }

  /**
   * MISP-format export. Pragmatic alternative for consumers that speak MISP
   * rather than TAXII.
   */
  static buildMispEvent({ campaign, iocs = [] }) {
    const typeMap = {
      domain: 'domain', sender_domain: 'domain', originating_ip: 'ip-src',
      upi_vpa: 'text', phone_in: 'phone-number', telegram: 'text', whatsapp: 'text',
      wallet_btc: 'btc', wallet_eth: 'text', wallet_tron: 'text',
      bank_account: 'bank-account-nr', ifsc: 'text', file_hash: 'sha256',
    };

    return {
      Event: {
        info: campaign ? `SentinelSEBI campaign: ${campaign.label}` : 'SentinelSEBI indicator export',
        threat_level_id: '1',
        analysis: '2',
        distribution: '0', // your organisation only — these are unvalidated leads
        date: new Date().toISOString().slice(0, 10),
        Attribute: iocs.map((ioc) => ({
          type: typeMap[ioc.type] || 'text',
          category: ['domain', 'sender_domain', 'originating_ip'].includes(ioc.type)
            ? 'Network activity'
            : 'Financial fraud',
          value: ioc.value,
          to_ids: ['domain', 'sender_domain', 'originating_ip'].includes(ioc.type),
          comment: `${ioc.type}; ${ioc.sighting_count} sighting(s); confidence ${ioc.confidence}`,
        })),
      },
    };
  }

  /**
   * Structured investigation dossier.
   *
   * Includes an explicit limitations section. A dossier that overstates what it
   * proves is worse than no dossier, because a single overreach discredits the
   * accurate parts alongside it.
   */
  static buildDossier({ campaign, iocs = [], scans = [], evidence = [], enrichment = [], attackTechniques = [] }) {
    return {
      generated_at: new Date().toISOString(),
      generator: 'SentinelSEBI Phase 5 Export Engine',

      campaign: campaign
        ? {
            id: campaign.id,
            label: campaign.label,
            correlation_method: campaign.cluster_method,
            indicator_count: campaign.member_count,
            peak_risk_score: campaign.max_risk_score,
            first_observed: campaign.first_seen,
            last_observed: campaign.last_seen,
          }
        : null,

      indicators: iocs.map((i) => ({
        type: i.type,
        value: i.value,
        first_seen: i.first_seen,
        last_seen: i.last_seen,
        sightings: i.sighting_count,
        confidence: i.confidence,
      })),

      evidencing_scans: scans.map((s) => ({
        scan_id: s.id,
        content_type: s.content_type,
        sender: s.sender,
        verdict: s.verdict,
        risk_score: s.risk_score,
        submitted_at: s.created_at,
      })),

      chain_of_custody: evidence.map((e) => ({
        sha256: e.sha256,
        md5: e.md5,
        size_bytes: e.size_bytes,
        original_filename: e.original_filename,
        retained_at: e.created_at,
        custody_hash: e.entry_hash,
      })),

      enrichment_provenance: enrichment.map((e) => ({
        indicator: e.indicator_value,
        source: e.source,
        retrieved_at: e.retrieved_at,
        note: 'Enrichment reflects the state of external records at retrieval time, not at the time of the offence.',
      })),

      attack_techniques: attackTechniques,

      limitations: [
        'Indicators identify infrastructure and payment rails only. Attribution to a natural person requires legal process against the relevant registrar, ISP, bank, or exchange.',
        'Correlation is based on shared infrastructure and co-occurrence within submitted artifacts. It establishes a relationship between indicators, not a shared operator with certainty.',
        'Biometric and perceptual similarity matches (voiceprint, perceptual hash) use uncalibrated default thresholds. False-match rates are unmeasured on this dataset. Such matches are investigative leads requiring human review, not evidence.',
        'IP addresses are recorded as observed in mail headers. CGNAT, VPNs, and proxies make an IP alone insufficient to identify a sender.',
        'Detection accuracy figures in project documentation are measured on a small development set and are not held-out benchmarks.',
        'The hash chain proves internal consistency of stored records. It does not prove the database was not rewritten wholesale; independent proof requires an external timestamp authority.',
      ],
    };
  }

  /**
   * Pre-formatted CERT-In Incident Report (Sec 70B IT Act 2000 compliant format).
   */
  static generateCertInReport({ incidentId, domain, scamVpa, targetPhone, threatCategory, summary, iocs = [] }) {
    const timestamp = new Date().toISOString();
    const id = incidentId || `CERT-IN-${Date.now()}`;
    const iocLines = iocs.length > 0
      ? iocs.map(i => `   - [${i.type.toUpperCase()}] ${i.value}`).join('\n')
      : `   - [DOMAIN] ${domain || 'N/A'}\n   - [UPI_VPA] ${scamVpa || 'N/A'}\n   - [PHONE] ${targetPhone || 'N/A'}`;

    return [
      '================================================================================',
      'CERT-In MANDATORY CYBER INCIDENT REPORT (Under Sec 70B IT Act 2000)',
      `Incident ID: ${id}`,
      `Report Generated: ${timestamp}`,
      `Threat Category: ${threatCategory || 'Securities Market Impersonation & Financial Fraud'}`,
      '================================================================================',
      '',
      '1. INCIDENT OVERVIEW',
      `   Target Domain / Host: ${domain || 'N/A'}`,
      `   Associated Payment Rail: ${scamVpa || 'N/A'}`,
      `   Associated Contact Phone: ${targetPhone || 'N/A'}`,
      `   Summary: ${summary || 'Unsolicited securities market fraud campaign detected by SentinelSEBI.'}`,
      '',
      '2. EXTRACTED INDICATORS OF COMPROMISE (IOCs)',
      iocLines,
      '',
      '3. MITRE ATT&CK MAPPING',
      '   - T1583.001 (Acquire Infrastructure: Domains)',
      '   - T1656 (Impersonation)',
      '   - T1657 (Financial Theft)',
      '',
      '4. MANDATORY REGULATORY ACTION REQUESTED',
      '   - DoT (Department of Telecommunications): Domain DNS Blocking & Takedown',
      '   - NPCI (National Payments Corporation of India): Freeze on linked UPI VPA',
      '================================================================================',
    ].join('\n');
  }

  /**
   * Pre-formatted SEBI SCORES Regulatory Complaint Notice.
   */
  static generateSebiScoresNotice({ noticeId, domain, scamVpa, intermediaryName, violationDetails }) {
    const timestamp = new Date().toISOString();
    const ref = noticeId || `SEBI-SCORES-${Date.now()}`;

    return [
      '================================================================================',
      'SEBI SCORES FORMAL COMPLAINT & REGULATORY NOTICE',
      `Ref No: ${ref}`,
      `Date: ${timestamp}`,
      'Regulation: SEBI (PFUTP) Regulations 2003 & Circular SEBI/HO/MIRSD/DOS3/CIR/P/2019/30',
      '================================================================================',
      '',
      '1. ENTITY & VIOLATION DETAILS',
      `   Alleged Impersonated Intermediary: ${intermediaryName || 'Securities Market Intermediary / SEBI Official'}`,
      `   Fraudulent Web Domain: ${domain || 'N/A'}`,
      `   Illegal Payment Rail: ${scamVpa || 'N/A'}`,
      `   Violation Details: ${violationDetails || 'Promising illegal guaranteed returns and operating unverified stock tip groups.'}`,
      '',
      '2. APPLICABLE STATUTORY CLAUSES',
      '   - SEBI (PFUTP) Regulation 3: Prohibition of Buying, Selling or Dealing in Securities in Fraudulent Manner',
      '   - SEBI (PFUTP) Regulation 4: Prohibition of Manipulative, Fraudulent and Deceptive Devices',
      '',
      '3. ENFORCEMENT DIRECTIVE',
      '   - Request NIXI / .IN Registry to revoke infringing domain name',
      '   - Request Financial Intelligence Unit (FIU-IND) for bank account freeze',
      '================================================================================',
    ].join('\n');
  }
}

module.exports = { ExportEngine, stixId, stixPatternFor, ATTACK_TECHNIQUES };
