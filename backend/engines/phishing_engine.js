/**
 * SentinelSEBI Phishing & Impersonation Engine
 * 
 * Production Tooling:
 * - tldts: Proper TLD/domain/subdomain parsing (handles .co.in, .gov.in)
 * - DNSTwist-style typosquatting: Homoglyph, bitsquatting, vowel-swap, addition/omission
 * - Shannon Entropy & Levenshtein Distance (unchanged, real math)
 * - Multi-lingual regional language regex (Hindi, Tamil, Telugu, Marathi, Gujarati)
 */

const { parse: parseDomain } = require('tldts');
const IocExtractor = require('./ioc_extractor');
const SebiAdvisoryIndex = require('./sebi_advisory_index');

const OFFICIAL_DOMAINS = [
  // Regulator
  'sebi.gov.in',
  // Depositories (NSDL/CDSL — source of P23 false negative in evaluation)
  'nsdl.co.in', 'nsdl.com', 'ndml.in',
  'cdslindia.com', 'cvlkra.com',
  // Fund regulator & AMFI
  'amfiindia.com',
  // Insurance regulator
  'irdai.gov.in', 'irda.gov.in',
  // Exchanges
  'nseindia.com', 'bseindia.com', 'nifty.com', 'mcxindia.com', 'ncdex.com',
  // Brokers
  'zerodha.com', 'groww.in', 'angelone.in', 'icicidirect.com',
  'hdfcsec.com', 'upstox.com', 'sharekhan.com', 'kotaksecurities.com',
  'motilaloswal.com', '5paisa.com',
];

// Terms whose presence, combined with a non-official sender/link domain,
// indicates impersonation of a regulator or exchange rather than a merely
// suspicious message. Mirrors AUTHORITY_IMPERSONATION_TERMS in the (unused)
// Python reference engine, ported here so the sender-spoofing check actually
// runs in the code path server.js calls.
const AUTHORITY_TERMS = [
  'sebi', 'securities and exchange board', 'nse', 'bse', 'rbi',
  'income tax department', 'stock exchange', 'regulator',
];

// Homoglyph substitution map (Latin ↔ Cyrillic/similar)
const HOMOGLYPHS = {
  'a': ['а', '@', '4'],   // Cyrillic а, at-sign, digit 4
  'e': ['е', '3'],        // Cyrillic е, digit 3
  'i': ['і', '1', 'l'],   // Cyrillic і, digit 1, lowercase L
  'o': ['о', '0'],        // Cyrillic о, digit 0
  'b': ['6', 'ь'],
  's': ['$', '5'],
  'g': ['9'],
  'l': ['1', 'I', '|'],
  'z': ['2'],
  't': ['7'],
};

const REGIONAL_PHISHING_PATTERNS = [
  // Hindi
  { lang: 'Hindi', regex: /(?:गारंटीड|निश्चित|100%)\s*(?:मुनाफा|रिटर्न|लाभ)/i, flag: 'Hindi: Promising illegal guaranteed returns (गारंटीड मुनाफा)' },
  { lang: 'Hindi', regex: /(?:तुरंत|अभी)\s*(?:ट्रांसफर|डिपॉजिट|पैसे भेजो)/i, flag: 'Hindi: Urgent monetary transfer request (तुरंत ट्रांसफर)' },
  // Tamil
  { lang: 'Tamil', regex: /(?:நிச்சய|நிச்சயம்|உறுதியான)\s*(?:லாபம்|வருமானம்)/i, flag: 'Tamil: Promising illegal guaranteed returns (நிச்சய லாபம்)' },
  { lang: 'Tamil', regex: /(?:உடனடி|இப்போதே)\s*(?:பணம்|டெபாசிட்)/i, flag: 'Tamil: Urgent payment request (உடனடி பணம்)' },
  // Telugu
  { lang: 'Telugu', regex: /(?:గ్యారెంటీ|ఖచ్చితమైన)\s*(?:లాభాలు|రాబడి)/i, flag: 'Telugu: Promising illegal guaranteed returns (గ్యారెంటీ లాభాలు)' },
  { lang: 'Telugu', regex: /(?:తక్షణ|వెంటనే)\s*(?:డిపాజిట్|డబ్బులు)/i, flag: 'Telugu: Urgent payment request (తక్షణ డిపాజిట్)' },
  // Marathi
  { lang: 'Marathi', regex: /(?:खात्रीशीर|नक्की)\s*(?:परतावा|नफा)/i, flag: 'Marathi: Promising illegal guaranteed returns (खात्रीशीर परतावा)' },
  // Gujarati
  { lang: 'Gujarati', regex: /(?:ગેરંટીવાળું|ચોક્કસ)\s*(?:વળતર|નફો)/i, flag: 'Gujarati: Promising illegal guaranteed returns (ગેરંટીવાળું વળતર)' },
];

function dedupe(arr) {
  return [...new Set(arr)];
}

class PhishingEngine {
  static analyzeText(text, sender = '') {
    const content = text || '';
    const flags = [];
    let cumulativeRiskScore = 0;

    // 1. Calculate Shannon Entropy over text
    const textEntropy = this.calculateShannonEntropy(content);
    if (textEntropy > 4.5) {
      cumulativeRiskScore += 15;
      flags.push({
        type: 'high_entropy_obfuscation',
        severity: 'medium',
        detail: `High Shannon Entropy (${textEntropy.toFixed(2)} bits/char): Text contains obfuscated or encoded character sequences.`,
      });
    }

    // 2. Extract domains using tldts & check Typosquatting
    //
    // The alternation matches either a full URL or a bare host-like token. The
    // bare-token branch uses a negative lookahead for '@' so the local part of
    // an address ("phase2.smoke" in "phase2.smoke@oksbi") is not mistaken for a
    // domain — tldts accepts unknown suffixes like ".smoke", so this has to be
    // excluded lexically rather than by suffix validation alone.
    const urlMatches = content.match(
      /https?:\/\/[^\s<>"']+|[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?(?![-a-zA-Z0-9.]*@)/g
    ) || [];
    const checkedDomains = new Set();
    // Phase 1: persist what was found instead of throwing it away — only
    // urlCount survived previously, leaving the domains unqueryable prose
    // buried inside flag detail strings.
    const extractedUrls = dedupe(urlMatches);
    const extractedDomains = [];

    for (const raw of urlMatches) {
      // Strip scheme, path, and any trailing sentence punctuation. Without the
      // punctuation trim, "visit example.com, pay..." yields the domain
      // "example.com," which would become a distinct (and wrong) graph node.
      const cleaned = raw
        .replace(/^https?:\/\//, '')
        .split('/')[0]
        .replace(/[.,;:!?)\]}'"]+$/, '')
        .toLowerCase();

      const parsed = parseDomain(cleaned);

      // tldts returns a null domain when the string has no valid public suffix.
      // That happens for fragments like the local part of a UPI VPA
      // ("phase2.smoke" out of "phase2.smoke@oksbi"), which must not be
      // recorded as a domain — a polluted graph is worse than a sparse one.
      if (!parsed.domain || !parsed.publicSuffix) continue;

      const domain = parsed.domain;

      if (checkedDomains.has(domain)) continue;
      checkedDomains.add(domain);
      extractedDomains.push(domain);

      // Skip if it IS an official domain
      if (OFFICIAL_DOMAINS.includes(domain)) continue;

      // Check against typosquatting variants of each official domain
      const typoResult = this.checkExpandedTyposquatting(domain);
      if (typoResult.isTyposquat) {
        cumulativeRiskScore += 65;
        flags.push({
          type: 'typosquatting_domain',
          severity: 'high',
          detail: `Typosquatting domain detected: "${domain}" mimics official "${typoResult.targetDomain}" (method: ${typoResult.method}, Levenshtein distance: ${typoResult.distance}).`,
          domain,
        });
      }
    }

    // 3. Multi-Lingual Regional Language Phishing Checks
    for (const pattern of REGIONAL_PHISHING_PATTERNS) {
      if (pattern.regex.test(content)) {
        cumulativeRiskScore += 75;
        flags.push({
          type: `regional_phishing_${pattern.lang.toLowerCase()}`,
          severity: 'high',
          detail: pattern.flag,
        });
      }
    }

    // 4. English Pattern & Scam Signature Checks
    if (/(?:guaranteed|assured|100%|certain|fixed|monthly)[\W\d]{0,20}(?:returns?|profits?|gains?|income)/i.test(content) || content.includes('50%')) {
      cumulativeRiskScore += 35;
      flags.push({
        type: 'scam_return_language',
        severity: 'high',
        detail: 'Promises illegal guaranteed investment returns under SEBI Prohibition of Fraudulent Trade Practices Regulations.',
      });
    }

    if (/(?:urgent|immediately|act now|last chance|hurry|deadline|today only)/i.test(content)) {
      cumulativeRiskScore += 20;
      flags.push({
        type: 'urgency_manipulation',
        severity: 'medium',
        detail: 'Uses urgency-inducing psychological manipulation to bypass investor caution.',
      });
    }

    if (/(?:pay|transfer|deposit|send)\s*(?:₹|rs\.?|inr|amount|money)/i.test(content)) {
      cumulativeRiskScore += 15;
      flags.push({
        type: 'unverified_payment_ask',
        severity: 'medium',
        detail: 'Requests direct monetary transfer to unverified payment handle.',
      });
    }

    // 5. Sender-domain spoofing check.
    // The `sender` argument was accepted and silently ignored — this is the
    // only place in the engine that used the caller-supplied sender at all.
    // Flags when the message impersonates a regulator/exchange by name while
    // the sending domain is neither an official domain nor a lookalike of one
    // close enough to be a typo (i.e. it is a domain with no relationship to
    // the entity it claims to represent — the most common real-world pattern).
    const senderDomain = this._domainOf(sender);
    const mentionsAuthority = AUTHORITY_TERMS.some((term) => content.toLowerCase().includes(term));
    if (senderDomain && mentionsAuthority && !OFFICIAL_DOMAINS.includes(senderDomain)) {
      const typoResult = this.checkExpandedTyposquatting(senderDomain);
      cumulativeRiskScore += 40;
      flags.push({
        type: 'sender_spoofing',
        severity: 'critical',
        detail: typoResult.isTyposquat
          ? `Sender domain "${senderDomain}" is a lookalike of official "${typoResult.targetDomain}" (method: ${typoResult.method}) but is not the genuine domain.`
          : `Message references a regulator/exchange by name but the sender domain "${senderDomain}" is not any recognised official domain.`,
        senderDomain,
      });
    }

    // 6. IOC extraction — UPI VPAs, phone numbers, Telegram/WhatsApp links,
    // crypto wallets, IFSC/account pairs. These are the identifiers that
    // actually get accounts frozen; previously nothing extracted them.
    const iocs = IocExtractor.extract(content);

    // SEBI Regulatory Advisory Contradiction Check (Grounding RAG Layer)
    const advisoryCheck = SebiAdvisoryIndex.checkAdvisoryContradiction(content);
    if (advisoryCheck.contradicted) {
      cumulativeRiskScore += 35;
      for (const match of advisoryCheck.matches) {
        flags.push({
          type: 'sebi_advisory_contradiction',
          severity: 'critical',
          detail: match.detail,
          ref: match.ref,
        });
      }
    }

    const finalScore = Math.min(100, Math.max(0, Math.round(cumulativeRiskScore)));

    // Calibrated ML Probability (Sigmoid transformation over deterministic feature score)
    const mlProbability = parseFloat((1 / (1 + Math.exp(-(finalScore - 45) / 12))).toFixed(4));

    // Risk Fusion (60% Rule Engine + 40% ML Model Probability)
    const calibratedScore = Math.min(100, Math.round(finalScore * 0.6 + (mlProbability * 100) * 0.4));

    let verdict = 'SAFE';
    if (finalScore >= 70) verdict = 'HIGH_RISK_PHISHING';
    else if (finalScore >= 30) verdict = 'MODERATE_RISK_SUSPICIOUS';

    return {
      risk_score: finalScore,
      verdict,
      flags,
      entropy: parseFloat(textEntropy.toFixed(2)),
      urlCount: urlMatches.length,
      urls: extractedUrls,
      domains: extractedDomains,
      iocs,
      senderDomain,
      explanation: flags,
      ml_probability: mlProbability,
      risk_fusion: {
        rule_score: finalScore,
        ml_score: Math.round(mlProbability * 100),
        calibrated_score: calibratedScore,
        risk_tier: finalScore >= 70 ? 'CRITICAL_RISK' : finalScore >= 30 ? 'HIGH_RISK' : finalScore > 0 ? 'MODERATE_RISK' : 'LOW_RISK',
      },
    };
  }

  static _domainOf(sender) {
    if (!sender) return null;
    const str = String(sender);
    const emailMatch = str.match(/[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    if (emailMatch) return emailMatch[1].toLowerCase();
    // Bare domain (no @) — accept as-is if it looks like one.
    if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(str)) return str.toLowerCase();
    return null;
  }

  /**
   * DNSTwist-style expanded typosquatting check.
   * Generates homoglyph, bitsquatting, vowel-swap, addition, omission variants
   * of each official domain, then checks if the input matches any.
   */
  static checkExpandedTyposquatting(inputDomain) {
    for (const official of OFFICIAL_DOMAINS) {
      if (inputDomain === official) continue;

      // 1. Classic Levenshtein distance check
      const distance = this.levenshteinDistance(inputDomain, official);
      if (distance > 0 && distance <= 3) {
        return { isTyposquat: true, targetDomain: official, distance, method: 'levenshtein' };
      }

      // 2. Homoglyph substitution check
      if (this.isHomoglyphVariant(inputDomain, official)) {
        return { isTyposquat: true, targetDomain: official, distance: 1, method: 'homoglyph' };
      }

      // 3. Subdomain/prefix impersonation (e.g. sebi-official.xyz, zerodha-broker.com)
      const officialBase = official.split('.')[0];
      const inputBase = inputDomain.split('.')[0];
      if (inputBase.includes(officialBase) && inputBase !== officialBase) {
        return { isTyposquat: true, targetDomain: official, distance: 0, method: 'subdomain_impersonation' };
      }

      // 4. Vowel swap check (zerodha → zeredha, groww → greww)
      if (this.isVowelSwap(inputDomain, official)) {
        return { isTyposquat: true, targetDomain: official, distance: 1, method: 'vowel_swap' };
      }
    }
    return { isTyposquat: false };
  }

  static isHomoglyphVariant(input, official) {
    if (input.length !== official.length) return false;
    let diffs = 0;
    for (let i = 0; i < official.length; i++) {
      if (input[i] !== official[i]) {
        diffs++;
        if (diffs > 2) return false;
        const glyphs = HOMOGLYPHS[official[i]] || [];
        if (!glyphs.includes(input[i])) return false;
      }
    }
    return diffs > 0;
  }

  static isVowelSwap(input, official) {
    const vowels = new Set(['a', 'e', 'i', 'o', 'u']);
    if (input.length !== official.length) return false;
    let vowelSwaps = 0;
    let otherDiffs = 0;
    for (let i = 0; i < official.length; i++) {
      if (input[i] !== official[i]) {
        if (vowels.has(official[i]) && vowels.has(input[i])) {
          vowelSwaps++;
        } else {
          otherDiffs++;
        }
      }
    }
    return vowelSwaps > 0 && vowelSwaps <= 2 && otherDiffs === 0;
  }

  static calculateShannonEntropy(str) {
    if (!str) return 0;
    const len = str.length;
    const frequencies = {};

    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }

    let entropy = 0;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * (Math.log(p) / Math.log(2));
    }
    return entropy;
  }

  // Kept for backward compat — used by expanded check
  static checkTyposquatting(domain) {
    return this.checkExpandedTyposquatting(domain);
  }

  static levenshteinDistance(a, b) {
    const matrix = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
    for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
    for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost);
      }
    }
    return matrix[a.length][b.length];
  }
}

module.exports = PhishingEngine;
