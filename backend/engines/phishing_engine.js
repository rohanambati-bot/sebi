/**
 * SentinelSEBI Phishing & Impersonation Engine — Multi-Lingual & 100% Dynamic Execution
 */

const OFFICIAL_DOMAINS = [
  'sebi.gov.in', 'zerodha.com', 'groww.in', 'angelone.in', 'icicidirect.com',
  'hdfcsec.com', 'nifty.com', 'nseindia.com', 'bseindia.com', 'upstox.com',
];

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

    // 2. Extract domains & check Typosquatting (Levenshtein Distance)
    const domainMatches = content.match(/([a-zA-Z0-9-]+\.[a-zA-Z]{2,})/g) || [];
    for (const rawDomain of domainMatches) {
      const cleanDomain = rawDomain.toLowerCase().replace(/^www\./, '');
      const typosquatMatch = this.checkTyposquatting(cleanDomain);
      if (typosquatMatch.isTyposquat) {
        cumulativeRiskScore += 65;
        flags.push({
          type: 'typosquatting_domain',
          severity: 'high',
          detail: `Look-alike domain detected: "${cleanDomain}" mimics official "${typosquatMatch.targetDomain}" (Levenshtein distance: ${typosquatMatch.distance}).`,
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

    // 4. Dynamic English Pattern & LLM Phishing Signature Checks
    if (/(?:guaranteed|assured|100%|certain|fixed|monthly)\s*(?:returns?|profits?|gains?|income)/i.test(content) || content.includes('50%')) {
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

    const finalScore = Math.min(100, Math.max(0, Math.round(cumulativeRiskScore)));

    let verdict = 'SAFE';
    if (finalScore >= 70) verdict = 'HIGH_RISK_PHISHING';
    else if (finalScore >= 30) verdict = 'MODERATE_RISK_SUSPICIOUS';

    return {
      risk_score: finalScore,
      verdict,
      flags,
      entropy: parseFloat(textEntropy.toFixed(2)),
      urlCount: domainMatches.length,
      explanation: flags,
    };
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

  static checkTyposquatting(domain) {
    for (const official of OFFICIAL_DOMAINS) {
      if (domain === official) continue;
      const distance = this.levenshteinDistance(domain, official);
      if (distance > 0 && distance <= 3) {
        return { isTyposquat: true, targetDomain: official, distance };
      }
    }
    return { isTyposquat: false };
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
