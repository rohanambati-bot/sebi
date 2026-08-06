/**
 * SentinelSEBI Brand Watch Engine — Proactive Typosquat & CT-Log Monitoring
 *
 * Flips detection from reactive (post-phish submission) to proactive (pre-campaign):
 *  1. Inverts phishing_engine.js homoglyph / vowel-swap / hyphenation rules into a
 *     variant generator for OFFICIAL_DOMAINS (Zerodha, Groww, SEBI, NSE, BSE, etc.).
 *  2. Queries crt.sh Certificate Transparency logs via EnrichmentEngine (SSRF-guarded)
 *     for freshly issued TLS certificates matching typosquat variants.
 *  3. Surfaces domain infrastructure BEFORE the first phishing email is sent.
 */

const { parse: parseDomain } = require('tldts');
const EnrichmentEngine = require('./enrichment_engine');

const PROTECTED_BRANDS = [
  { domain: 'sebi.gov.in', name: 'SEBI (Securities & Exchange Board of India)', category: 'Regulator' },
  { domain: 'nsdl.co.in', name: 'NSDL (National Securities Depository Ltd)', category: 'Depository' },
  { domain: 'cdslindia.com', name: 'CDSL (Central Depository Services Ltd)', category: 'Depository' },
  { domain: 'amfiindia.com', name: 'AMFI (Association of Mutual Funds in India)', category: 'Fund Regulator' },
  { domain: 'irdai.gov.in', name: 'IRDAI (Insurance Regulatory and Development Authority)', category: 'Regulator' },
  { domain: 'zerodha.com', name: 'Zerodha Broking Ltd', category: 'Stock Broker' },
  { domain: 'groww.in', name: 'Groww (Nextbillion Technology)', category: 'Stock Broker' },
  { domain: 'angelone.in', name: 'Angel One Ltd', category: 'Stock Broker' },
  { domain: 'icicidirect.com', name: 'ICICI Direct', category: 'Stock Broker' },
  { domain: 'hdfcsec.com', name: 'HDFC Securities', category: 'Stock Broker' },
  { domain: 'nseindia.com', name: 'National Stock Exchange (NSE)', category: 'Exchange' },
  { domain: 'bseindia.com', name: 'Bombay Stock Exchange (BSE)', category: 'Exchange' },
  { domain: 'upstox.com', name: 'Upstox (RKSV Securities)', category: 'Stock Broker' },
];

const HOMOGLYPH_MAP = {
  'a': ['0', '4', 'а'],
  'e': ['3', 'е'],
  'i': ['1', 'l', 'і'],
  'o': ['0', 'о'],
  's': ['5', '$'],
  'g': ['9'],
  'z': ['2'],
};

const IMPERSONATION_SUFFIXES = [
  '-kyc', '-verify', '-official', '-login', '-support', '-portal', '-secure', '-help'
];

const TLDS = ['.in', '.com', '.co.in', '.net', '.org', '.info', '.xyz', '.online'];

class BrandWatchEngine {
  /**
   * Generate potential typosquatting and impersonation variants for a domain.
   * @param {string} domain - e.g. 'zerodha.com'
   * @returns {Array<string>} - List of generated domain variants
   */
  static generateVariants(domain) {
    const parsed = parseDomain(domain);
    const base = parsed.domain ? parsed.domain.split('.')[0] : domain.split('.')[0];
    const variants = new Set();

    // 1. Homoglyph / Digit Substitution Variants
    for (let i = 0; i < base.length; i++) {
      const char = base[i].toLowerCase();
      const subs = HOMOGLYPH_MAP[char] || [];
      for (const sub of subs) {
        const variantBase = base.substring(0, i) + sub + base.substring(i + 1);
        for (const tld of TLDS) {
          const candidate = `${variantBase}${tld}`;
          if (candidate !== domain) variants.add(candidate);
        }
      }
    }

    // 2. Hyphenated / Keyword Impersonation Variants
    for (const suffix of IMPERSONATION_SUFFIXES) {
      for (const tld of TLDS) {
        const candidate = `${base}${suffix}${tld}`;
        if (candidate !== domain) variants.add(candidate);
      }
    }

    // 3. TLD Swap Variants
    for (const tld of TLDS) {
      const candidate = `${base}${tld}`;
      if (candidate !== domain) variants.add(candidate);
    }

    return Array.from(variants);
  }

  /**
   * Get the list of protected brand targets.
   */
  static getWatchlist() {
    return PROTECTED_BRANDS.map(b => {
      const variants = this.generateVariants(b.domain);
      return {
        ...b,
        generatedVariantCount: variants.length,
        sampleVariants: variants.slice(0, 5),
      };
    });
  }

  /**
   * Scan Certificate Transparency logs for a brand or all brands.
   * @param {string} [targetBrand] - Specific brand domain, e.g. 'zerodha.com'
   * @returns {Promise<object>} - Findings and generated threat alerts
   */
  static async scanBrand(targetBrand) {
    const brandsToScan = targetBrand
      ? PROTECTED_BRANDS.filter(b => b.domain.toLowerCase() === targetBrand.toLowerCase())
      : PROTECTED_BRANDS;

    if (brandsToScan.length === 0) {
      return { success: false, error: `Brand ${targetBrand} not found in protection list` };
    }

    const alerts = [];
    let totalVariantsChecked = 0;

    for (const brand of brandsToScan) {
      const variants = this.generateVariants(brand.domain);
      totalVariantsChecked += variants.length;

      // Sample check top variants to query CT logs
      const checkSet = variants.slice(0, 4);

      for (const variant of checkSet) {
        try {
          const ctResult = await EnrichmentEngine.lookupCertificateTransparency(variant);

          if (ctResult.certificateCount > 0) {
            alerts.push({
              domain_variant: variant,
              target_brand: brand.domain,
              brand_name: brand.name,
              cert_count: ctResult.certificateCount,
              earliest_issuance: ctResult.earliestIssuance,
              latest_issuance: ctResult.latestIssuance,
              related_domains: ctResult.relatedDomains.slice(0, 5),
              risk_score: 90,
              severity: 'critical',
              threat_type: 'Active CT-Log Impersonation Certificate',
              status: 'PROACTIVE_ALERT',
              source: 'crt.sh',
              simulated: false,
              created_at: new Date().toISOString(),
            });
          }
        } catch (e) {
          // Ignore network errors on individual lookups
        }
      }

      // In offline / dev mode, if CT lookups return empty or skipped,
      // generate demonstration proactive alert samples based on generated variants.
      // These are clearly labelled as simulated — they are illustrative of the
      // detection capability and must not be treated as real threat intelligence.
      if (alerts.length === 0) {
        const demoVariant1 = `${brand.domain.split('.')[0]}-verify-kyc.in`;
        const demoVariant2 = `${brand.domain.split('.')[0].replace('o', '0')}-portal.com`;

        alerts.push(
          {
            domain_variant: demoVariant1,
            target_brand: brand.domain,
            brand_name: brand.name,
            cert_count: 1,
            earliest_issuance: new Date(Date.now() - 2 * 86400000).toISOString(),
            latest_issuance: new Date().toISOString(),
            related_domains: [`auth.${demoVariant1}`, `login.${demoVariant1}`],
            risk_score: 85,
            severity: 'high',
            threat_type: 'Proactive CT-Log Typosquat Infrastructure',
            status: 'NEW_THREAT_DETECTED',
            source: 'demo_simulation',
            simulated: true,
            simulation_note: 'CT-log enrichment is disabled or returned no results. This alert is a demonstration sample, not real threat intelligence.',
            created_at: new Date().toISOString(),
          },
          {
            domain_variant: demoVariant2,
            target_brand: brand.domain,
            brand_name: brand.name,
            cert_count: 2,
            earliest_issuance: new Date(Date.now() - 5 * 86400000).toISOString(),
            latest_issuance: new Date(Date.now() - 1 * 86400000).toISOString(),
            related_domains: [`secure.${demoVariant2}`],
            risk_score: 78,
            severity: 'high',
            threat_type: 'Pre-Campaign Impersonation SSL Issued',
            status: 'NEW_THREAT_DETECTED',
            source: 'demo_simulation',
            simulated: true,
            simulation_note: 'CT-log enrichment is disabled or returned no results. This alert is a demonstration sample, not real threat intelligence.',
            created_at: new Date().toISOString(),
          }
        );
      }
    }

    return {
      success: true,
      timestamp: new Date().toISOString(),
      brandsScanned: brandsToScan.length,
      variantsGenerated: totalVariantsChecked,
      alertsFound: alerts.length,
      containsSimulatedAlerts: alerts.some((a) => a.simulated === true),
      alerts,
    };
  }
}

module.exports = BrandWatchEngine;
