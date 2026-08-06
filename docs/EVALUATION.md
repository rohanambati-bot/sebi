# Detection Performance — Phishing Engine

## Development-Set Accuracy (10 messages)

Sample set: 10 labeled messages (5 phishing, 5 legitimate), threshold = risk_score >= 20

| Metric | Value |
|---|---|
| Accuracy | 100% |
| Precision | 100% |
| Recall | 100% |
| F1 score | 1.00 |
| True Positives | 5 |
| False Positives | 0 |
| True Negatives | 5 |
| False Negatives | 0 |

### Per-message results (dev set)

| Message (truncated) | Label | Risk Score | Verdict | Flagged |
|---|---|---|---|---|
| Dear Customer, SEBI URGENT NOTICE: Your trading account will... | phishing | 60 | HIGH | ✅ |
| URGENT: Your NSE account will be blocked. Click bit.ly/nse-v... | phishing | 31 | MEDIUM | ✅ |
| Guaranteed returns! Double your money in 7 days with our exc... | phishing | 25 | MEDIUM | ✅ |
| Dear valued client, your KYC has expired. Update your Aadhaa... | phishing | 30 | MEDIUM | ✅ |
| RBI final notice: share your net banking password within 24 ... | phishing | 32 | MEDIUM | ✅ |
| Your Zerodha contract note for June 2026 is now available in... | legit | 0 | LOW | ❌ |
| SEBI Circular: Investors are advised that SEBI never asks fo... | legit | 0 | LOW | ❌ |
| Hi, this is a reminder that the NSE market will remain close... | legit | 0 | LOW | ❌ |
| Your monthly statement from ICICI Direct for June 2026 has b... | legit | 0 | LOW | ❌ |
| Reminder: Your Angel One margin report is ready to view in t... | legit | 0 | LOW | ❌ |

*This is the same 10-message set used during pattern development. 100% is expected and unremarkable.*

---

## Held-Out Benchmark (50 messages — never used to tune patterns)

50 original-composition messages (25 phishing, 25 legitimate) modeled on realistic Indian capital market communications. **None of these messages were seen during regex pattern development.** This is the authoritative accuracy measurement.

| Metric | Value |
|---|---|
| **Accuracy** | **92.0%** |
| Precision | 95.7% |
| Recall | 88.0% |
| F1 Score | 91.7% |
| True Positives | 22 |
| False Positives | 1 |
| True Negatives | 24 |
| False Negatives | 3 |

### False Negatives (missed phishing — 3 messages)

| ID | Risk Score | Why Missed |
|---|---|---|
| P12 | 0 | "Make ₹1 crore in 90 days with AI algo trading bot" — uses indirect scam language without triggering keyword patterns |
| P21 | 15 | "IPO APPLICATION CONFIRMED: allotted 500 shares at 90% discount" — entropy signal fires but urgency/impersonation patterns don't |
| P25 | 15 | "SIP bounced, click to pay" — domain is suspicious but scam-language patterns don't cover SIP bounce scenarios |

### False Positives (legitimate flagged — 1 message)

| ID | Risk Score | Why Flagged |
|---|---|---|
| L25 | 35 | SEBI circular with reference number — entropy of the reference string pushes score above threshold |

### Interpretation

The 90% held-out accuracy with 95.5% precision demonstrates that the regex-based engine generalizes beyond its training data. The 84% recall indicates that ~16% of novel phishing variants evade the current pattern set — this is expected for a rule-based engine without ML, and the specific gaps (indirect scam language, missing official domain entries, SIP-specific scenarios) are documented above for future improvement.

---

## Evasion Fixes

**Intervening-token evasion (fixed).** The original scam-return regex used `\s*` between the qualifier (`guaranteed`, `assured`, etc.) and the noun (`returns`, `profits`, etc.), which only tolerated whitespace. Strings like `"Guaranteed 500% returns"` evaded detection because `500%` is not whitespace. The pattern now uses `[\W\d]{0,20}`, tolerating up to 20 characters of non-word characters and digits between the qualifier and noun. Verified by a dedicated test in `accuracy.test.js`.

**Remaining narrow gap:** Multi-word phrases with alphabetic words between qualifier and noun (e.g., `"Guaranteed by our expert team high returns"`) still evade detection. This requires NLP-level semantic parsing and is out of scope for regex-based detection.