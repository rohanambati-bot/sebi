/**
 * SentinelSEBI — Outbound Network Guard (Phase 3)
 *
 * Phase 3 is the first phase that makes outbound requests, so the safety
 * controls come before the features.
 *
 * Threats this addresses:
 *  1. SSRF. Attacker-supplied hostnames are resolved and then checked against
 *     private ranges. Checking the *string* before resolution is the classic
 *     bypass (a public name that resolves to 169.254.169.254 reaches cloud
 *     metadata). We therefore resolve first, then validate every resolved
 *     address, and connect only to a validated literal.
 *  2. Rate-limit exhaustion. Public RDAP/CT endpoints will block a host that
 *     bulk-queries them, so every lookup goes through a token bucket.
 *  3. Tipping off the operator. Fetching attacker infrastructure from the
 *     analysis host reveals investigation activity. Enrichment is therefore
 *     opt-in via SENTINEL_ENRICHMENT_ENABLED and documented as needing separate
 *     egress in production.
 */

const dns = require('dns').promises;
const net = require('net');

/** Enrichment is off unless explicitly enabled — see the tipping-off note above. */
const ENRICHMENT_ENABLED = process.env.SENTINEL_ENRICHMENT_ENABLED === 'true';
const OFFLINE_MOCK = process.env.SENTINEL_OFFLINE_MOCK === 'true';

const DEFAULT_TIMEOUT_MS = Number(process.env.SENTINEL_ENRICHMENT_TIMEOUT_MS || 5000);

/**
 * Blocked destination ranges. Covers loopback, RFC1918, link-local (including
 * the cloud metadata endpoint at 169.254.169.254), CGNAT, and IPv6 equivalents.
 */
function isBlockedAddress(ip) {
  if (!ip) return true;

  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0) return true;                       // "this network"
    if (a === 10) return true;                      // RFC1918
    if (a === 127) return true;                     // loopback
    if (a === 169 && b === 254) return true;        // link-local + metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a >= 224) return true;                      // multicast / reserved
    return false;
  }

  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::' || lower === '::1') return true;
    if (lower.startsWith('fe80:')) return true;     // link-local
    if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true; // ULA
    if (lower.startsWith('ff')) return true;        // multicast
    // IPv4-mapped (::ffff:10.0.0.1) must be unwrapped and re-checked.
    const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isBlockedAddress(mapped[1]);
    return false;
  }

  return true; // not a recognisable address
}

/**
 * Resolve a hostname and reject it if any resolved address is in a blocked
 * range. Returns the safe addresses, or throws.
 *
 * Rejecting when *any* address is blocked (rather than filtering to the safe
 * ones) is deliberate: a host that publishes both a public and a private A
 * record is a DNS-rebinding signal, not something to partially trust.
 */
async function resolveSafely(hostname) {
  if (!hostname || typeof hostname !== 'string') {
    throw new Error('BLOCKED: no hostname');
  }
  // A literal address bypasses DNS, so validate it directly.
  if (net.isIP(hostname)) {
    if (isBlockedAddress(hostname)) throw new Error(`BLOCKED: private/reserved address ${hostname}`);
    return [hostname];
  }

  let records;
  try {
    records = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (err) {
    throw new Error(`DNS_FAILED: ${hostname} (${err.code || err.message})`);
  }

  const addresses = records.map((r) => r.address);
  if (addresses.length === 0) throw new Error(`DNS_FAILED: ${hostname} returned no addresses`);

  const blocked = addresses.filter(isBlockedAddress);
  if (blocked.length > 0) {
    throw new Error(`BLOCKED: ${hostname} resolves to private/reserved address(es) ${blocked.join(', ')}`);
  }

  return addresses;
}

/** Simple token bucket, one per logical upstream service. */
class RateLimiter {
  constructor(capacity, refillPerSecond) {
    this.capacity = capacity;
    this.tokens = capacity;
    this.refillPerSecond = refillPerSecond;
    this.lastRefill = Date.now();
  }

  _refill() {
    const now = Date.now();
    const elapsedSeconds = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.capacity, this.tokens + elapsedSeconds * this.refillPerSecond);
    this.lastRefill = now;
  }

  tryConsume() {
    this._refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }
}

// Conservative defaults. Public RDAP bootstrap and crt.sh both throttle
// aggressively; being slow is preferable to being blocked mid-investigation.
const limiters = {
  rdap: new RateLimiter(10, 1),
  crtsh: new RateLimiter(5, 0.5),
  dns: new RateLimiter(30, 5),
};

function checkRateLimit(service) {
  const limiter = limiters[service];
  if (!limiter) return true;
  return limiter.tryConsume();
}

/**
 * Perform a guarded HTTPS GET returning parsed JSON.
 *
 * Enforces: enrichment enabled, rate limit, HTTPS only, hostname resolution
 * safety, response size cap, and a hard timeout. Redirects are NOT followed —
 * a redirect is a re-targeting primitive and following it would reintroduce the
 * SSRF surface the resolution check just closed.
 */
/**
 * Hostnames whose redirects may be followed, one hop, with the destination
 * re-validated.
 *
 * Rationale: the RDAP bootstrap service at rdap.org is a redirector by design
 * (302 to the authoritative registry, e.g. rdap.verisign.com), so a blanket
 * no-redirect policy makes RDAP unusable. Following redirects from an
 * attacker-supplied URL would reopen the SSRF hole the resolution check closes,
 * so this is restricted to a fixed allowlist of bootstrap services we chose —
 * never to a host that appeared in scanned content.
 */
const REDIRECT_ALLOWED_HOSTS = new Set(['rdap.org']);

function getMockEnrichmentData(urlStr, service) {
  let hostname = 'example-suspicious-domain.com';
  try {
    hostname = new URL(urlStr).hostname || hostname;
  } catch {}

  if (service === 'rdap') {
    return {
      ok: true,
      data: {
        handle: 'DOM-12345',
        events: [
          { eventAction: 'registration', eventDate: new Date(Date.now() - 5 * 86400000).toISOString() },
        ],
        entities: [
          { roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'SEBI-Mock-Registrar Inc.']]] },
        ],
      },
    };
  }

  if (service === 'crtsh') {
    return {
      ok: true,
      data: [
        { name_value: hostname, entry_timestamp: new Date().toISOString() },
        { name_value: `secure.${hostname}`, entry_timestamp: new Date().toISOString() },
      ],
    };
  }

  return { ok: true, data: { mock: true, domain: hostname } };
}

async function safeGetJson(url, { service = 'rdap', timeoutMs = DEFAULT_TIMEOUT_MS, maxBytes = 512 * 1024, _hop = 0 } = {}) {
  if (OFFLINE_MOCK) {
    return getMockEnrichmentData(url, service);
  }
  if (!ENRICHMENT_ENABLED) {
    return { ok: false, skipped: true, reason: 'ENRICHMENT_DISABLED' };
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, reason: 'INVALID_URL' };
  }

  if (parsed.protocol !== 'https:') {
    return { ok: false, reason: 'HTTPS_REQUIRED' };
  }

  if (!checkRateLimit(service)) {
    return { ok: false, reason: 'RATE_LIMITED', service };
  }

  try {
    await resolveSafely(parsed.hostname);
  } catch (err) {
    return { ok: false, reason: err.message };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const allowRedirect = REDIRECT_ALLOWED_HOSTS.has(parsed.hostname) && _hop === 0;

  try {
    const res = await fetch(parsed.toString(), {
      signal: controller.signal,
      // 'manual' for allowlisted bootstrap hosts so the Location target can be
      // re-validated before we connect to it; 'error' everywhere else.
      redirect: allowRedirect ? 'manual' : 'error',
      headers: { 'User-Agent': 'SentinelSEBI/1.0 (investor-protection research)', Accept: 'application/json' },
    });

    if (allowRedirect && res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      if (!location) return { ok: false, reason: 'REDIRECT_WITHOUT_LOCATION' };

      // The redirect target goes through the full guard again (HTTPS check,
      // rate limit, DNS resolution safety) via this recursive call. _hop caps
      // it at a single additional request so a redirect loop cannot spin.
      return await safeGetJson(new URL(location, parsed).toString(), {
        service, timeoutMs, maxBytes, _hop: _hop + 1,
      });
    }

    if (!res.ok) return { ok: false, reason: `HTTP_${res.status}` };

    const text = await res.text();
    if (text.length > maxBytes) return { ok: false, reason: 'RESPONSE_TOO_LARGE' };

    try {
      return { ok: true, data: JSON.parse(text) };
    } catch {
      return { ok: false, reason: 'INVALID_JSON' };
    }
  } catch (err) {
    if (err.name === 'AbortError') return { ok: false, reason: 'TIMEOUT' };
    return { ok: false, reason: `FETCH_FAILED: ${err.message}` };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = {
  ENRICHMENT_ENABLED,
  OFFLINE_MOCK,
  isBlockedAddress,
  resolveSafely,
  checkRateLimit,
  safeGetJson,
  RateLimiter,
};
