/**
 * SentinelSEBI Enrichment Engine — Phase 3
 *
 * Adds external context to flagged infrastructure. Four lookups, deliberately
 * no more:
 *   1. RDAP     → registrar + creation date. Domain age under ~30 days is the
 *                 strongest single free fraud predictor available, and the
 *                 registrar is who a takedown is actually served on.
 *   2. DNS      → A/AAAA/MX/NS/TXT. Reverse-resolving the host then reveals
 *                 sibling domains, which is how one report becomes a campaign.
 *   3. CT logs  → crt.sh SAN lists routinely expose an operator's other domains
 *                 and date the operation via issuance timestamps.
 *   4. DKIM DNS → fetch the d=/s= selector key so DKIM can be verified for real
 *                 rather than structurally (eml_parser documents this gap).
 *
 * Every result carries `source` and `retrieved_at`. Stale intel presented as
 * current is how a dossier gets thrown out.
 *
 * All network access goes through net_guard (SSRF checks, rate limits, HTTPS
 * only, no redirects). Nothing here fetches attacker-controlled URLs directly.
 */

const dns = require('dns').promises;
const NetGuard = require('../net_guard');

const RDAP_BOOTSTRAP = 'https://rdap.org/domain/';
const CRTSH_URL = 'https://crt.sh/?output=json&q=';

function nowIso() {
  return new Date().toISOString();
}

/** Days between an ISO date and now, or null when unparseable. */
function ageInDays(isoDate) {
  if (!isoDate) return null;
  const then = Date.parse(isoDate);
  if (Number.isNaN(then)) return null;
  return Math.floor((Date.now() - then) / 86400000);
}

class EnrichmentEngine {
  /**
   * RDAP lookup. Prefers RDAP over legacy WHOIS: structured JSON, documented
   * bootstrap, and friendlier rate limits than port-43 WHOIS.
   */
  static async lookupRdap(domain) {
    const result = {
      source: 'rdap', retrieved_at: nowIso(), domain,
      registrar: null, created: null, expires: null, updated: null,
      ageDays: null, nameservers: [], status: [], available: false,
    };

    const res = await NetGuard.safeGetJson(`${RDAP_BOOTSTRAP}${encodeURIComponent(domain)}`, { service: 'rdap' });
    if (!res.ok) {
      result.error = res.reason;
      result.skipped = Boolean(res.skipped);
      return result;
    }

    const data = res.data || {};
    result.available = true;

    for (const event of data.events || []) {
      if (event.eventAction === 'registration') result.created = event.eventDate;
      if (event.eventAction === 'expiration') result.expires = event.eventDate;
      if (event.eventAction === 'last changed') result.updated = event.eventDate;
    }

    // The registrar entity is the actionable party for a takedown; the
    // registrant is usually privacy-shielded and not worth parsing for.
    for (const entity of data.entities || []) {
      if ((entity.roles || []).includes('registrar')) {
        const vcard = entity.vcardArray?.[1] || [];
        const fn = vcard.find((f) => f[0] === 'fn');
        result.registrar = fn ? fn[3] : entity.handle || null;
      }
    }

    result.nameservers = (data.nameservers || []).map((ns) => (ns.ldhName || '').toLowerCase()).filter(Boolean);
    result.status = data.status || [];
    result.ageDays = ageInDays(result.created);

    return result;
  }

  /**
   * DNS resolution. Uses the resolver directly rather than an HTTP API, so
   * safeGetJson's guard does not apply — the rate limiter is applied explicitly
   * and results are never used to drive a subsequent fetch.
   */
  static async lookupDns(domain) {
    const result = {
      source: 'dns', retrieved_at: nowIso(), domain,
      a: [], aaaa: [], mx: [], ns: [], txt: [], spf: null, resolves: false,
    };

    if (!NetGuard.ENRICHMENT_ENABLED) {
      result.skipped = true;
      result.error = 'ENRICHMENT_DISABLED';
      return result;
    }
    if (!NetGuard.checkRateLimit('dns')) {
      result.error = 'RATE_LIMITED';
      return result;
    }

    // Each record type is queried independently: a domain with no MX is normal
    // and must not abort collection of its A records.
    const settle = async (fn) => { try { return await fn(); } catch { return []; } };

    result.a = await settle(() => dns.resolve4(domain));
    result.aaaa = await settle(() => dns.resolve6(domain));
    const mx = await settle(() => dns.resolveMx(domain));
    result.mx = mx.map((m) => ({ exchange: m.exchange, priority: m.priority }));
    result.ns = await settle(() => dns.resolveNs(domain));
    const txt = await settle(() => dns.resolveTxt(domain));
    result.txt = txt.map((chunks) => chunks.join(''));
    result.spf = result.txt.find((t) => /^v=spf1/i.test(t)) || null;
    result.resolves = result.a.length > 0 || result.aaaa.length > 0;

    return result;
  }

  /**
   * Reverse-resolve an IP to find co-hosted names.
   *
   * Scope note: PTR records are set by the IP's owner and only rarely enumerate
   * every site on a shared host, so an empty result does not mean the host is
   * dedicated. Real co-hosting discovery needs passive DNS, which is a paid
   * data source and out of scope.
   */
  static async reverseLookup(ip) {
    const result = { source: 'dns_ptr', retrieved_at: nowIso(), ip, hostnames: [] };

    if (!NetGuard.ENRICHMENT_ENABLED) {
      result.skipped = true;
      result.error = 'ENRICHMENT_DISABLED';
      return result;
    }
    if (NetGuard.isBlockedAddress(ip)) {
      result.error = 'BLOCKED_PRIVATE_ADDRESS';
      return result;
    }
    if (!NetGuard.checkRateLimit('dns')) {
      result.error = 'RATE_LIMITED';
      return result;
    }

    try {
      result.hostnames = await dns.reverse(ip);
    } catch (err) {
      result.error = err.code || err.message;
    }
    return result;
  }

  /**
   * Certificate Transparency search. A cert's SAN list frequently exposes the
   * operator's other domains, and issuance timestamps date the operation.
   */
  static async lookupCertificateTransparency(domain) {
    const result = {
      source: 'crt.sh', retrieved_at: nowIso(), domain,
      certificateCount: 0, relatedDomains: [], earliestIssuance: null, latestIssuance: null,
    };

    const res = await NetGuard.safeGetJson(`${CRTSH_URL}${encodeURIComponent(domain)}`, { service: 'crtsh' });
    if (!res.ok) {
      result.error = res.reason;
      result.skipped = Boolean(res.skipped);
      return result;
    }

    const entries = Array.isArray(res.data) ? res.data : [];
    result.certificateCount = entries.length;

    const names = new Set();
    const dates = [];
    for (const entry of entries) {
      for (const name of String(entry.name_value || '').split('\n')) {
        const cleaned = name.trim().toLowerCase().replace(/^\*\./, '');
        if (cleaned && cleaned !== domain) names.add(cleaned);
      }
      if (entry.not_before) dates.push(entry.not_before);
    }

    result.relatedDomains = [...names].slice(0, 100);
    dates.sort();
    result.earliestIssuance = dates[0] || null;
    result.latestIssuance = dates[dates.length - 1] || null;

    return result;
  }

  /**
   * Fetch a DKIM public key from DNS so a signature can be verified for real.
   * eml_parser stops at structural validation precisely because this needs DNS.
   */
  static async lookupDkimKey(selector, signingDomain) {
    const result = {
      source: 'dns_dkim', retrieved_at: nowIso(),
      selector, signingDomain, keyFound: false, publicKey: null, keyType: null,
    };

    if (!NetGuard.ENRICHMENT_ENABLED) {
      result.skipped = true;
      result.error = 'ENRICHMENT_DISABLED';
      return result;
    }
    if (!selector || !signingDomain) {
      result.error = 'MISSING_SELECTOR_OR_DOMAIN';
      return result;
    }
    if (!NetGuard.checkRateLimit('dns')) {
      result.error = 'RATE_LIMITED';
      return result;
    }

    try {
      const records = await dns.resolveTxt(`${selector}._domainkey.${signingDomain}`);
      const joined = records.map((chunks) => chunks.join('')).join('');
      const keyMatch = joined.match(/p=([A-Za-z0-9+/=]+)/);
      const typeMatch = joined.match(/k=([a-z0-9]+)/i);

      if (keyMatch) {
        result.keyFound = true;
        result.publicKey = keyMatch[1];
        result.keyType = typeMatch ? typeMatch[1].toLowerCase() : 'rsa';
      } else {
        result.error = 'NO_PUBLIC_KEY_IN_RECORD';
      }
    } catch (err) {
      result.error = err.code || err.message;
    }

    return result;
  }

  /**
   * Derive risk signals from enrichment output.
   *
   * Kept separate from collection so scoring can be reasoned about (and tested)
   * without any network dependency.
   */
  static deriveSignals({ rdap, dnsRecords, ct }) {
    const flags = [];
    let riskDelta = 0;

    if (rdap?.available && rdap.ageDays !== null) {
      if (rdap.ageDays <= 30) {
        riskDelta += 30;
        flags.push({
          type: 'newly_registered_domain', severity: 'high',
          detail: `Domain registered ${rdap.ageDays} day(s) ago (${rdap.created}). Newly registered domains are strongly associated with fraud campaigns.`,
        });
      } else if (rdap.ageDays <= 90) {
        riskDelta += 15;
        flags.push({
          type: 'recently_registered_domain', severity: 'medium',
          detail: `Domain registered ${rdap.ageDays} day(s) ago (${rdap.created}).`,
        });
      }
    }

    if (rdap?.available && rdap.registrar) {
      flags.push({
        type: 'registrar_identified', severity: 'info',
        detail: `Registrar of record: ${rdap.registrar}. Takedown requests are served on the registrar.`,
      });
    }

    if (dnsRecords?.resolves === false && !dnsRecords?.skipped && !dnsRecords?.error) {
      riskDelta += 10;
      flags.push({
        type: 'domain_does_not_resolve', severity: 'low',
        detail: 'Domain has no A/AAAA record — it may have already been taken down or is parked for later use.',
      });
    }

    if (dnsRecords?.resolves && !dnsRecords.spf) {
      riskDelta += 5;
      flags.push({
        type: 'no_spf_record', severity: 'low',
        detail: 'No SPF record published, so the domain offers no protection against being spoofed.',
      });
    }

    if (ct?.relatedDomains?.length > 0) {
      flags.push({
        type: 'ct_related_domains', severity: 'medium',
        detail: `Certificate Transparency logs expose ${ct.relatedDomains.length} related name(s) sharing certificates with this domain: ${ct.relatedDomains.slice(0, 5).join(', ')}${ct.relatedDomains.length > 5 ? '…' : ''}`,
      });
    }

    return { riskDelta: Math.min(40, riskDelta), flags };
  }

  /** Collect all enrichment for one domain in a single call. */
  static async enrichDomain(domain) {
    const [rdap, dnsRecords, ct] = await Promise.all([
      this.lookupRdap(domain),
      this.lookupDns(domain),
      this.lookupCertificateTransparency(domain),
    ]);

    const hostIps = [...(dnsRecords.a || []), ...(dnsRecords.aaaa || [])];
    const reverse = hostIps.length ? await this.reverseLookup(hostIps[0]) : null;
    const signals = this.deriveSignals({ rdap, dnsRecords, ct });

    return { domain, rdap, dns: dnsRecords, ct, reverse, ...signals, enriched_at: nowIso() };
  }
}

module.exports = EnrichmentEngine;
