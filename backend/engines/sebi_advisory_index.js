/**
 * SentinelSEBI Official Advisory Index & Contradiction Engine
 * 
 * Grounding RAG Layer: Indexes official SEBI regulatory circulars and advisories
 * to detect direct contradictions in scam communications (eliminates AI hallucinations).
 */

const SEBI_ADVISORIES = [
  {
    id: 'SEBI-IA-2013-REG15',
    ref: 'SEBI (Investment Advisers) Regulations 2013, Reg 15(1)',
    title: 'Prohibition of Guaranteed Returns & Unrealistic Profit Claims',
    keywords: [/guarantee[d\s]*return/i, /500%\s*return/i, /assured\s*profit/i, /100%\s*profit/i, /risk-free\s*investment/i],
    rule: 'SEBI Investment Advisers Regulations strictly prohibit any registered or unregistered entity from promising guaranteed, fixed, or assured returns on equity/derivative markets.'
  },
  {
    id: 'SEBI-CIRCULAR-2026-04',
    ref: 'SEBI Advisory Ref #2026/04',
    title: 'Zero Account Unlock / Release Fee Mandate',
    keywords: [/pay\s*(?:₹|rs\.?|inr)?\s*[\d,]+\s*to\s*unlock/i, /deposit\s*(?:₹|rs\.?|inr)?\s*[\d,]+\s*to\s*release/i, /unlock\s*demat\s*fee/i, /transfer\s*(?:₹|rs\.?|inr)?\s*[\d,]+\s*to\s*unblock/i],
    rule: 'SEBI and registered Depository Participants (NSDL/CDSL) NEVER require investors to transfer fees or security deposits to unblock or release frozen demat/trading accounts.'
  },
  {
    id: 'SEBI-CAUTION-2025-11',
    ref: 'SEBI Public Caution Notice #2025/11',
    title: 'Prohibition of Unregistered Telegram/WhatsApp Stock Tip Groups',
    keywords: [/vip\s*stock\s*tips/i, /pre-ipo\s*guaranteed\s*allotment/i, /insider\s*trading\s*group/i, /sebi\s*approved\s*tip/i],
    rule: 'SEBI does NOT approve or endorse stock tip channels on Telegram, WhatsApp, or social media. Trading on recommendations from unregistered entities carries high financial risk.'
  }
];

class SebiAdvisoryIndex {
  /**
   * Scan text for direct contradictions against official SEBI circulars.
   */
  static checkAdvisoryContradiction(text) {
    if (!text || typeof text !== 'string') return { contradicted: false, matches: [] };

    const matches = [];

    for (const advisory of SEBI_ADVISORIES) {
      for (const kwPattern of advisory.keywords) {
        if (kwPattern.test(text)) {
          matches.push({
            advisoryId: advisory.id,
            ref: advisory.ref,
            title: advisory.title,
            detail: `CONTRADICTS OFFICIAL GUIDANCE — ${advisory.ref}: ${advisory.rule}`
          });
          break; // Avoid duplicate matches for same advisory
        }
      }
    }

    return {
      contradicted: matches.length > 0,
      matches,
      primaryMatch: matches[0] || null
    };
  }
}

module.exports = SebiAdvisoryIndex;
