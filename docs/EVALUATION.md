# Detection Performance — Phishing Engine

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

## Per-message results

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

*Note: this is a small hand-labeled sample set for MVP demonstration, not a held-out benchmark. For the full submission, this should be replaced with a larger dataset (e.g. IWSPA-AP phishing corpus / PhishTank-derived samples) and the threshold tuned via ROC analysis.*