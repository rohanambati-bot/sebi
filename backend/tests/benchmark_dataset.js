/**
 * SentinelSEBI — Held-Out Benchmark Dataset
 *
 * 50 messages (25 phishing, 25 legitimate) that were NEVER used to tune the
 * regex patterns in phishing_engine.js. These simulate realistic Indian
 * capital market communications.
 *
 * Methodology:
 *  - Phishing samples model observed scam patterns: UPI fraud, fake SEBI
 *    circulars, Telegram tip groups, WhatsApp chain letters, fake KYC links,
 *    pump-and-dump, deepfake advisory claims, lottery/prize bait.
 *  - Legitimate samples model real broker confirmations, SEBI press releases,
 *    exchange notices, portfolio alerts, contract notes — written in the same
 *    formal tone that a naive keyword scanner would over-flag.
 *  - All messages are original compositions, not copied from any public corpus.
 */

const BENCHMARK_DATASET = [
  // ───────────── PHISHING (expected: HIGH_RISK or MODERATE_RISK) ─────────────
  {
    text: "URGENT: Your Zerodha account has been flagged for suspicious activity. Verify your identity within 2 hours at http://zerodha-kyc-verify.net/login or your account will be permanently blocked. Do not ignore this message.",
    sender: "security@zerodha-kyc-verify.net",
    expected: "phishing",
    id: "P01",
  },
  {
    text: "Congratulations! You have been selected for SEBI's Investor Protection Reward Scheme 2026. Claim your ₹50,000 reward by sending your Aadhaar and PAN card to sebi-rewards@gmail.com within 48 hours.",
    sender: "rewards@sebi-india.org",
    expected: "phishing",
    id: "P02",
  },
  {
    text: "Join our exclusive WhatsApp group for guaranteed 200% returns on penny stocks. Our SEBI-registered analyst has a 100% track record. Pay ₹5000 membership to UPI ID: stockguru@ybl to join now!",
    sender: "admin@stocktipsguru.in",
    expected: "phishing",
    id: "P03",
  },
  {
    text: "Dear Investor, NSE has detected unauthorized trades in your demat account. To prevent further loss, immediately transfer your holdings to safe custody account via http://nse-secure-holdings.com/transfer",
    sender: "alerts@nse-secure-holdings.com",
    expected: "phishing",
    id: "P04",
  },
  {
    text: "SEBI CIRCULAR: All retail investors must update KYC by July 31 or face account freezing. Update now at http://sebi-gov-kyc.in/update. Reference: SEBI/HO/CFD/DIL2/2026/42",
    sender: "circular@sebi-gov-kyc.in",
    expected: "phishing",
    id: "P05",
  },
  {
    text: "Your SBI mutual fund has matured. Redeem ₹2,50,000 immediately. Click http://sbi-mf-redeem.co.in/claim and enter your bank details. This link expires in 24 hours.",
    sender: "noreply@sbi-mf-redeem.co.in",
    expected: "phishing",
    id: "P06",
  },
  {
    text: "Exclusive pre-IPO allocation for Swiggy shares at ₹50/share (market price ₹850). Limited to first 100 investors. Pay ₹1,00,000 via NEFT to account 9876543210 IFSC: HDFC0001234 to lock your allocation.",
    sender: "ipo@pre-ipo-deals.in",
    expected: "phishing",
    id: "P07",
  },
  {
    text: "BSE NOTICE: Your trading terminal license has expired. Renew immediately at http://bse-terminal-renew.com or lose access to all open positions. Enter your CDSL DP ID and PIN to proceed.",
    sender: "support@bse-terminal-renew.com",
    expected: "phishing",
    id: "P08",
  },
  {
    text: "FREE STOCK TIPS from certified SEBI advisor! Get 3 guaranteed profit calls daily. Just deposit ₹10,000 to wallet@paytm to start receiving calls. Yesterday's tip gave 500% return in one day!",
    sender: "tips@certifiedadvisor.co",
    expected: "phishing",
    id: "P09",
  },
  {
    text: "Your Groww account password will expire in 6 hours. Reset your password now at http://groww-pass-reset.xyz/reset to continue trading. Failure to act will result in permanent account deletion.",
    sender: "security@groww-pass-reset.xyz",
    expected: "phishing",
    id: "P10",
  },
  {
    text: "IMPORTANT: RBI has mandated linking of all demat accounts with UPI by August 15. Complete the process at http://rbi-demat-link.in/register. Non-compliance will result in freezing of all securities.",
    sender: "compliance@rbi-demat-link.in",
    expected: "phishing",
    id: "P11",
  },
  {
    text: "Make ₹1 crore in 90 days with our AI-powered algo trading bot. Zero risk guaranteed. Send your investment amount to UPI: algo.master@oksbi and our bot starts trading within minutes.",
    sender: "invest@algo-profits.in",
    expected: "phishing",
    id: "P12",
  },
  {
    text: "Angel One ALERT: Margin shortfall of ₹85,000 detected. Your positions will be squared off in 30 minutes. Transfer funds immediately to avoid loss: http://angelone-margin.net/pay",
    sender: "margin@angelone-margin.net",
    expected: "phishing",
    id: "P13",
  },
  {
    text: "Telegram channel @NiftyMaster gives 100% accurate options trading signals. Join now and get first week free. Already 50,000+ members making guaranteed monthly income of ₹2 lakh+!",
    sender: "admin@niftymaster.co",
    expected: "phishing",
    id: "P14",
  },
  {
    text: "Your PAN card has been flagged by Income Tax Department for undisclosed capital gains. Pay penalty of ₹25,000 via UPI to itdept@ybl within 24 hours to avoid prosecution under Section 271C.",
    sender: "notice@incometax-india.org",
    expected: "phishing",
    id: "P15",
  },
  {
    text: "CDSL easi facility - your DP account has been compromised. Immediately verify at http://cdsl-easi-secure.in and change your TPIN. Enter current TPIN and new TPIN to secure your holdings.",
    sender: "security@cdsl-easi-secure.in",
    expected: "phishing",
    id: "P16",
  },
  {
    text: "Dear valued customer, ICICI Direct is offering special intraday brokerage of ₹0. Activate your account now at http://icicidirect-offer.com/activate. Enter your login credentials to avail the offer.",
    sender: "offers@icicidirect-offer.com",
    expected: "phishing",
    id: "P17",
  },
  {
    text: "WARNING from SEBI: Your broker has been blacklisted. Transfer all holdings immediately to Government-approved custodian via http://sebi-custodian-transfer.in to protect your investments.",
    sender: "action@sebi-custodian-transfer.in",
    expected: "phishing",
    id: "P18",
  },
  {
    text: "Earn fixed monthly returns of 5% on your corpus. Our scheme is backed by Government of India bonds. Minimum investment ₹50,000. Contact Rajesh at +91-9876543210 or pay to rajesh.invest@paytm",
    sender: "rajesh@fixed-returns.in",
    expected: "phishing",
    id: "P19",
  },
  {
    text: "Your Upstox account login from new device detected in Karachi, Pakistan. If this wasn't you, secure your account immediately at http://upstox-security.co/verify and enter your OTP.",
    sender: "noreply@upstox-security.co",
    expected: "phishing",
    id: "P20",
  },
  {
    text: "IPO APPLICATION CONFIRMED: You have been allotted 500 shares of TCS at ₹100 (90% discount). Pay application money ₹50,000 to account 1234567890 IFSC SBIN0001234 within 2 hours or allotment will be cancelled.",
    sender: "allotment@tcs-ipo-2026.in",
    expected: "phishing",
    id: "P21",
  },
  {
    text: "Get insider tips on Adani Group stocks directly from company insiders. 100% guaranteed profit on every trade. Monthly subscription only ₹15,000. Pay to UPI: insidertips@axl",
    sender: "tips@insider-trading-tips.com",
    expected: "phishing",
    id: "P22",
  },
  {
    text: "NSDL NOTICE: Your demat account KYC is expired since March 2026. Complete re-KYC at http://nsdl-rekyc.org/update within 48 hours. Upload Aadhaar, PAN and bank statement to avoid account suspension.",
    sender: "kyc@nsdl-rekyc.org",
    expected: "phishing",
    id: "P23",
  },
  {
    text: "Forex trading opportunity! Convert ₹10,000 into ₹10,00,000 in just 30 days using our proprietary algorithm. SEBI approved. Start now by depositing to forex.master@ybl. Assured monthly income!",
    sender: "admin@forex-profits.in",
    expected: "phishing",
    id: "P24",
  },
  {
    text: "Dear customer, your SIP of ₹10,000 in Axis Bluechip Fund has bounced. Click http://axis-sip-recovery.com/pay to make immediate payment and avoid SIP cancellation. Enter UPI PIN to confirm.",
    sender: "sip@axis-sip-recovery.com",
    expected: "phishing",
    id: "P25",
  },

  // ───────────── LEGITIMATE (expected: SAFE) ─────────────
  {
    text: "Your Zerodha contract note for trades executed on 05-Aug-2026 is available in the Console under Reports > Contract Notes. No action required from your end.",
    sender: "noreply@zerodha.com",
    expected: "legitimate",
    id: "L01",
  },
  {
    text: "SEBI vide circular SEBI/HO/MRD/MRD-PoD-1/P/CIR/2026/89 dated August 01, 2026 has revised the lot size for derivatives contracts effective from September expiry series. Exchanges are advised to implement the changes.",
    sender: "circulars@sebi.gov.in",
    expected: "legitimate",
    id: "L02",
  },
  {
    text: "NSE Trading Holiday Notice: The equity and derivatives segments will remain closed on August 15, 2026 on account of Independence Day. Normal trading will resume on August 16, 2026.",
    sender: "notices@nseindia.com",
    expected: "legitimate",
    id: "L03",
  },
  {
    text: "Your SIP installment of ₹5,000 in HDFC Mid-Cap Opportunities Fund has been successfully processed. Units allotted: 23.456 at NAV ₹213.12. View statement in your Groww app.",
    sender: "noreply@groww.in",
    expected: "legitimate",
    id: "L04",
  },
  {
    text: "BSE Notice No. 20260801-29: Members are informed that the settlement cycle for trades executed on T+0 optional segment will follow the existing guidelines. No change in margin requirements.",
    sender: "notices@bseindia.com",
    expected: "legitimate",
    id: "L05",
  },
  {
    text: "Annual Maintenance Charges of ₹300 + GST have been debited from your CDSL demat account (DP ID: 12345678) for FY 2026-27. For queries, contact your depository participant.",
    sender: "noreply@cdslindia.com",
    expected: "legitimate",
    id: "L06",
  },
  {
    text: "Dividend of ₹12.50 per share has been credited to your bank account for your holding of 200 shares of Infosys Ltd (ISIN: INE009A01021). Record date: July 28, 2026.",
    sender: "dividends@nsdl.co.in",
    expected: "legitimate",
    id: "L07",
  },
  {
    text: "Your portfolio summary for July 2026: Total value ₹8,45,230. Monthly change: +2.3%. Top performer: HDFC Bank (+5.1%). View detailed analytics in Angel One app.",
    sender: "portfolio@angelone.in",
    expected: "legitimate",
    id: "L08",
  },
  {
    text: "Margin statement for August 05, 2026: Available margin ₹1,25,000. Utilized margin ₹78,000. Margin utilization: 62.4%. No additional margin required for current positions.",
    sender: "margin@icicidirect.com",
    expected: "legitimate",
    id: "L09",
  },
  {
    text: "SEBI has imposed a penalty of ₹15 lakh on XYZ Securities Ltd for non-compliance with client fund segregation norms under SEBI (Stock Brokers) Regulations, 1992. Order available at sebi.gov.in.",
    sender: "enforcement@sebi.gov.in",
    expected: "legitimate",
    id: "L10",
  },
  {
    text: "Your withdrawal request of ₹50,000 from Upstox account has been processed. Amount will be credited to your linked bank account within 24 hours. Transaction ID: UPX20260805001.",
    sender: "withdrawals@upstox.com",
    expected: "legitimate",
    id: "L11",
  },
  {
    text: "Quarterly investor grievance report published. Total complaints received: 4,521. Resolved: 4,389 (97.1%). Average resolution time: 12 working days. Full report at scores.gov.in.",
    sender: "grievance@sebi.gov.in",
    expected: "legitimate",
    id: "L12",
  },
  {
    text: "Your mutual fund folio statement for the period April-June 2026 has been generated. Download from your registered email or visit the AMC website with your folio number.",
    sender: "statements@camsonline.com",
    expected: "legitimate",
    id: "L13",
  },
  {
    text: "NSE Circular: Index reconstitution of Nifty 50 effective September 27, 2026. Adani Energy Solutions Ltd to be included, replacing BPCL. Full details on nseindia.com.",
    sender: "indexservices@nseindia.com",
    expected: "legitimate",
    id: "L14",
  },
  {
    text: "Your order to BUY 50 shares of Reliance Industries at ₹2,850.00 has been executed. Order ID: 260805100234. Average price: ₹2,849.75. Brokerage: ₹20. View in Kite app.",
    sender: "trades@zerodha.com",
    expected: "legitimate",
    id: "L15",
  },
  {
    text: "Corporate action alert: TCS has announced a bonus issue in the ratio of 1:1. Record date: September 15, 2026. Your current holding: 100 shares. Post-bonus holding: 200 shares.",
    sender: "corporateactions@nsdl.co.in",
    expected: "legitimate",
    id: "L16",
  },
  {
    text: "AMFI reminder: Complete your annual risk profiling to ensure your mutual fund investments align with your risk appetite. Login to your AMC website or visit your mutual fund distributor.",
    sender: "noreply@amfiindia.com",
    expected: "legitimate",
    id: "L17",
  },
  {
    text: "Market closing summary for August 05, 2026: Sensex 79,234 (+0.45%), Nifty 50 23,987 (+0.52%). Top gainer: Bajaj Finance (+3.2%). Top loser: Coal India (-1.8%). FII net buy: ₹1,234 crore.",
    sender: "dailyreport@bseindia.com",
    expected: "legitimate",
    id: "L18",
  },
  {
    text: "Your e-CAS (Electronic Consolidated Account Statement) for July 2026 is attached. This statement is generated by CDSL/NSDL and covers all your demat and mutual fund holdings.",
    sender: "ecas@cdslindia.com",
    expected: "legitimate",
    id: "L19",
  },
  {
    text: "SEBI Chairman Madhabi Puri Buch addressed the CII Financial Markets Summit. Key highlights: enhanced surveillance framework, T+0 settlement progress, and investor protection initiatives. Full transcript on sebi.gov.in.",
    sender: "communications@sebi.gov.in",
    expected: "legitimate",
    id: "L20",
  },
  {
    text: "Tax loss harvesting opportunity: Your holding in Vodafone Idea shows unrealized loss of ₹12,450. Consider booking the loss before March 31 to offset against capital gains. Consult your tax advisor.",
    sender: "insights@groww.in",
    expected: "legitimate",
    id: "L21",
  },
  {
    text: "IPO Application Status: Your application for Ola Electric IPO (Category: Retail Individual) for 1 lot at cut-off price has been received. Allotment date: August 10, 2026. Check status on BSE IPO.",
    sender: "ipo@zerodha.com",
    expected: "legitimate",
    id: "L22",
  },
  {
    text: "Your Form 26AS for AY 2026-27 shows total TDS on securities transactions of ₹8,450. Verify this matches your broker statements. View on incometax.gov.in.",
    sender: "noreply@incometaxindiaefiling.gov.in",
    expected: "legitimate",
    id: "L23",
  },
  {
    text: "Scheduled maintenance: Kite trading platform will be unavailable on August 10, 2026 from 00:00 to 06:00 IST for infrastructure upgrades. Post-market and pre-market orders will not be affected.",
    sender: "support@zerodha.com",
    expected: "legitimate",
    id: "L24",
  },
  {
    text: "SEBI has extended the deadline for implementation of the Consolidated Account Statement generation by depositories from August 1 to September 30, 2026. Circular ref: SEBI/HO/OIAE/IGRD/CIR/2026/102.",
    sender: "circulars@sebi.gov.in",
    expected: "legitimate",
    id: "L25",
  },
];

module.exports = { BENCHMARK_DATASET };
