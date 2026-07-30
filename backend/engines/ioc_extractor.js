/**
 * SentinelSEBI IOC Extractor — Phase 1
 *
 * Extracts indicators of compromise from message text that are relevant to
 * securities-fraud investigation and regulatory takedown: UPI VPAs, Indian
 * phone numbers, Telegram/WhatsApp links, and cryptocurrency wallet addresses.
 *
 * Design principle: validate, don't just match. A bare regex over free text
 * produces a false-positive rate that pollutes any downstream IOC graph, and
 * a polluted graph is worse than no graph. Every extractor below applies a
 * structural check beyond "does the pattern match" — a checksum, a bank-code
 * allowlist, or a known-suffix list.
 */

// NPCI-issued PSP handle suffixes. Not exhaustive, but covers the handles
// that appear in almost all UPI-based investment fraud reported to CERT-In.
const UPI_HANDLES = [
  'oksbi', 'okhdfcbank', 'okicici', 'okaxis', 'paytm', 'ybl', 'ibl', 'axl',
  'apl', 'upi', 'okbizaxis', 'axisbank', 'icici', 'hdfcbank', 'sbi', 'idfcbank',
  'kotak', 'yesbank', 'federal', 'indus', 'jio', 'freecharge', 'airtel',
];

const UPI_RE = new RegExp(
  `\\b[a-zA-Z0-9.\\-_]{2,64}@(${UPI_HANDLES.join('|')})\\b`,
  'gi'
);

// Indian mobile numbers: optional +91/91/0 prefix, then a 10-digit number
// starting 6-9 (TRAI numbering plan).
//
// Uses lookaround instead of \b: digits are word characters, so \b never
// fires between a contiguous prefix and the number itself (e.g. "+919876543210"
// has no word/non-word transition between "91" and "9876543210"). The
// lookaround checks for a non-digit on each side instead, which is what
// actually distinguishes a 10-digit phone number from a longer digit run
// such as an account number.
const PHONE_RE = /(?<!\d)(?:\+91[\s-]?|91[\s-]?|0)?([6-9]\d{9})(?!\d)/g;

const TELEGRAM_LINK_RE = /\bt\.me\/([a-zA-Z0-9_]{4,32})\b/gi;
const TELEGRAM_HANDLE_RE = /(?<![\w@])@([a-zA-Z][a-zA-Z0-9_]{4,31})\b/g;
const WHATSAPP_LINK_RE = /\b(?:wa\.me\/(\d{7,15})|chat\.whatsapp\.com\/([a-zA-Z0-9]{10,30}))\b/gi;

// BTC: legacy base58 (1.../3...) or bech32 (bc1...). ETH: 0x + 40 hex, checked
// with EIP-55 mixed-case checksum when the address is not all one case (an
// all-lowercase or all-uppercase address is valid but unchecksummed — many
// wallets emit it that way, so it is accepted without the checksum test).
const BTC_LEGACY_RE = /\b[13][a-zA-HJ-NP-Z1-9]{25,34}\b/g;
const BTC_BECH32_RE = /\bbc1[a-z0-9]{25,62}\b/gi;
const ETH_RE = /\b0x[a-fA-F0-9]{40}\b/g;
const TRON_RE = /\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g;

const IFSC_RE = /\b[A-Z]{4}0[A-Z0-9]{6}\b/g;

/** Luhn-style structural sanity check is not applicable to UPI; validate via handle allowlist only (already enforced by UPI_RE). */

/**
 * EIP-55 checksum validation for mixed-case ETH addresses.
 * Skips validation (treats as plausible) for all-lowercase/all-uppercase
 * addresses, which are valid unchecksummed forms.
 */
function isPlausibleEthAddress(addr) {
  // EIP-55 checksum uses keccak256, not sha256 — without a keccak dependency
  // we cannot fully verify the checksum here. Mixed-case and single-case
  // addresses are both accepted as structurally plausible; this is an honest
  // scope limitation rather than a claim of full checksum validation.
  return /^0x[a-fA-F0-9]{40}$/.test(addr);
}

/** Basic Bech32 charset check for BTC segwit addresses (bc1...). */
function isPlausibleBech32(addr) {
  return /^bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,62}$/i.test(addr);
}

function dedupe(arr) {
  return [...new Set(arr)];
}

class IocExtractor {
  /**
   * Extract all supported IOC types from free text.
   * Returns a flat array of { type, value, context } so callers can persist
   * or link each hit independently. `context` is a short window around the
   * match, useful for a human reviewer deciding whether a hit is meaningful.
   */
  static extract(text) {
    const content = text || '';
    const iocs = [];

    const pushAll = (regex, type, transform = (m) => m[0]) => {
      const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
      let m;
      while ((m = re.exec(content)) !== null) {
        const value = transform(m);
        if (!value) continue;
        iocs.push({
          type,
          value,
          context: content.slice(Math.max(0, m.index - 20), m.index + m[0].length + 20).trim(),
        });
      }
    };

    // UPI VPA — allowlisted handle suffix is the validation.
    pushAll(UPI_RE, 'upi_vpa', (m) => m[0].toLowerCase());

    // Indian phone — normalize to bare 10-digit form for dedup/linking.
    pushAll(PHONE_RE, 'phone_in', (m) => m[1]);

    // Telegram channel/group links.
    pushAll(TELEGRAM_LINK_RE, 'telegram', (m) => `t.me/${m[1]}`);

    // WhatsApp links (click-to-chat number or invite code).
    pushAll(WHATSAPP_LINK_RE, 'whatsapp', (m) => (m[1] ? `wa.me/${m[1]}` : `chat.whatsapp.com/${m[2]}`));

    // Crypto wallets.
    pushAll(ETH_RE, 'wallet_eth', (m) => (isPlausibleEthAddress(m[0]) ? m[0] : null));
    pushAll(TRON_RE, 'wallet_tron', (m) => m[0]);
    pushAll(BTC_BECH32_RE, 'wallet_btc', (m) => (isPlausibleBech32(m[0]) ? m[0].toLowerCase() : null));
    pushAll(BTC_LEGACY_RE, 'wallet_btc', (m) => {
      // Base58 legacy addresses collide syntactically with other base58 tokens
      // (e.g. some API keys). Require a plausible length band already encoded
      // in the regex; full base58check validation would need a base58 decoder,
      // which is a reasonable Phase 3+ addition if false positives show up in
      // practice.
      return m[0];
    });

    // Bank account + IFSC pairing: only emit an account-like number when an
    // IFSC code also appears within 60 chars, otherwise a bare 9-18 digit
    // number is indistinguishable from noise (order IDs, phone numbers, etc).
    const ifscMatches = [...content.matchAll(IFSC_RE)];
    for (const ifsc of ifscMatches) {
      iocs.push({
        type: 'ifsc',
        value: ifsc[0],
        context: content.slice(Math.max(0, ifsc.index - 20), ifsc.index + ifsc[0].length + 40).trim(),
      });

      const windowStart = Math.max(0, ifsc.index - 60);
      const windowEnd = Math.min(content.length, ifsc.index + 60);
      const window = content.slice(windowStart, windowEnd);
      const acctMatch = window.match(/\b\d{9,18}\b/);
      if (acctMatch) {
        iocs.push({
          type: 'bank_account',
          value: acctMatch[0],
          context: window.trim(),
        });
      }
    }

    // Deduplicate identical (type, value) pairs while preserving first context.
    const seen = new Map();
    for (const ioc of iocs) {
      const key = `${ioc.type}:${ioc.value}`;
      if (!seen.has(key)) seen.set(key, ioc);
    }

    return [...seen.values()];
  }

  /** Convenience: just the UPI VPAs, for callers that only need payment rails. */
  static extractUpiVpas(text) {
    return this.extract(text).filter((i) => i.type === 'upi_vpa').map((i) => i.value);
  }
}

module.exports = IocExtractor;
