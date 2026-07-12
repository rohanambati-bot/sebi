"""
Evaluation harness — generates evidence of detection performance for the
phishing engine, as required by the problem statement's "Desired outcome".

Run: python3 evaluate.py
Writes results to ../docs/EVALUATION.md
"""
from engines import phishing_engine

# Labeled sample set: (text, sender, is_phishing)
SAMPLES = [
    ("Dear Customer, SEBI URGENT NOTICE: Your trading account will be suspended within 24 hours. "
     "Verify immediately by clicking http://sebi-goviin.com/verify and enter your OTP and UPI PIN.",
     "alerts@sebi-goviin.com", True),
    ("URGENT: Your NSE account will be blocked. Click bit.ly/nse-verify now and confirm your login credentials.",
     "support@nse-alerts.info", True),
    ("Guaranteed returns! Double your money in 7 days with our exclusive pre-IPO shares. Join our telegram for insider tips now!",
     "tips@quickrich99.com", True),
    ("Dear valued client, your KYC has expired. Update your Aadhaar number and PAN immediately at bse-kyc-update.net or your account will be permanently blocked.",
     "kyc@bse-kyc-update.net", True),
    ("RBI final notice: share your net banking password within 24 hours to avoid account freeze. Click here to verify.",
     "alert@rbi-secure-verify.com", True),
    ("Your Zerodha contract note for June 2026 is now available in the console under Reports.",
     "noreply@zerodha.com", False),
    ("SEBI Circular: Investors are advised that SEBI never asks for OTP, password or UPI PIN over phone or email.",
     "circulars@sebi.gov.in", False),
    ("Hi, this is a reminder that the NSE market will remain closed on account of a public holiday tomorrow.",
     "notifications@nseindia.com", False),
    ("Your monthly statement from ICICI Direct for June 2026 has been generated and is available for download.",
     "statements@icicidirect.com", False),
    ("Reminder: Your Angel One margin report is ready to view in the app under Reports > Margin Statement.",
     "noreply@angelone.in", False),
]

THRESHOLD = 20  # risk_score >= threshold -> flagged as phishing

def main():
    tp = fp = tn = fn = 0
    rows = []
    for text, sender, is_phish in SAMPLES:
        result = phishing_engine.analyze_text(text, sender)
        predicted = result["risk_score"] >= THRESHOLD
        if predicted and is_phish: tp += 1
        elif predicted and not is_phish: fp += 1
        elif not predicted and not is_phish: tn += 1
        else: fn += 1
        rows.append((text[:60] + "...", is_phish, result["risk_score"], result["verdict"], predicted))

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    accuracy = (tp + tn) / len(SAMPLES)

    lines = []
    lines.append("# Detection Performance — Phishing Engine\n")
    lines.append(f"Sample set: {len(SAMPLES)} labeled messages (5 phishing, 5 legitimate), threshold = risk_score >= {THRESHOLD}\n")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Accuracy | {accuracy:.0%} |")
    lines.append(f"| Precision | {precision:.0%} |")
    lines.append(f"| Recall | {recall:.0%} |")
    lines.append(f"| F1 score | {f1:.2f} |")
    lines.append(f"| True Positives | {tp} |")
    lines.append(f"| False Positives | {fp} |")
    lines.append(f"| True Negatives | {tn} |")
    lines.append(f"| False Negatives | {fn} |\n")
    lines.append("## Per-message results\n")
    lines.append("| Message (truncated) | Label | Risk Score | Verdict | Flagged |")
    lines.append("|---|---|---|---|---|")
    for text, is_phish, score, verdict, predicted in rows:
        lines.append(f"| {text} | {'phishing' if is_phish else 'legit'} | {score} | {verdict} | {'✅' if predicted else '❌'} |")

    lines.append("\n*Note: this is a small hand-labeled sample set for MVP demonstration, not a "
                  "held-out benchmark. For the full submission, this should be replaced with a larger "
                  "dataset (e.g. IWSPA-AP phishing corpus / PhishTank-derived samples) and the threshold "
                  "tuned via ROC analysis.*")

    report = "\n".join(lines)
    with open("../docs/EVALUATION.md", "w") as f:
        f.write(report)
    print(report)

if __name__ == "__main__":
    main()
