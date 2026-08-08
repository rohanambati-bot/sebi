# SentinelSEBI Demo Samples & Presentation Workflow

This folder contains pre-packaged sample files to demonstrate the **SentinelSEBI Hybrid Explainable AI & Regulatory Response Pipeline** during hackathon judging and live evaluation.

## Demo Files

1. **`demo_phishing_spoof.eml`**:
   - Contains DKIM spoofing, urgency indicators, typosquatted domains (`broker-zerodha.online`), and UPI payment handle (`invest.now@oksbi`).
   - Drag & drop into the Phishing Scanner tab to trigger Risk Fusion calculation (Risk Score: `93 CRITICAL`).

2. **`demo_investor_advisory_contradiction.json`**:
   - Fraudulent offer text promising guaranteed 400% stock returns.
   - Demonstrates vector RAG lookup flagging an explicit contradiction against official SEBI advisory circulars.

## Live Presentation Recommendation

Before running a live stage demo, enable offline mock mode in your environment to ensure sub-millisecond responses without external rate limits or venue network dependency:

```bash
export SENTINEL_OFFLINE_MOCK=true
npm test
```
