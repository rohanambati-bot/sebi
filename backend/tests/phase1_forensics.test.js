/**
 * Phase 1 — Evidence Capture & Chain of Custody
 *
 * Covers:
 *  1A. Received: chain parsing, originating IP, forensic headers
 *  1B. IOC extraction (UPI, phone, Telegram/WhatsApp, wallets, IFSC)
 *  1C. Sender-domain spoofing, full-text persistence, URL/domain persistence
 *  1D. Evidence retention, hashing, and the custody hash chain
 */

const test = require('node:test');
const assert = require('node:assert');
const EMLParser = require('../engines/eml_parser');
const PhishingEngine = require('../engines/phishing_engine');
const IocExtractor = require('../engines/ioc_extractor');

// ─────────────────────────── 1A: Received chain ───────────────────────────

test('Received chain: extracts originating IP from a realistic multi-hop header set', () => {
  const raw = `Received: from mail.victimbank.example (mail.victimbank.example [203.0.113.9])
	by mx.google.com with ESMTPS id abc123
	for <victim@example.com>; Wed, 22 Jul 2026 10:15:00 +0530
Received: from smtp-relay.sendgrid.net (smtp-relay.sendgrid.net [198.51.100.44])
	by mail.victimbank.example with ESMTP id def456
	for <victim@example.com>; Wed, 22 Jul 2026 10:14:50 +0530
Received: from [10.0.0.5] (unverified [45.33.32.156])
	by smtp-relay.sendgrid.net with SMTP id ghi789
	for <victim@example.com>; Wed, 22 Jul 2026 10:14:40 +0530
From: "SEBI Alerts" <alerts@sebi-govin.com>
Subject: Urgent
Date: Wed, 22 Jul 2026 10:14:00 +0530
Content-Type: text/plain

Your account is suspended.`;

  const parsed = EMLParser.parse(raw);

  assert.strictEqual(parsed.headers.receivedHops, 3, 'should count all three Received headers');
  assert.strictEqual(parsed.headers.originatingIp, '45.33.32.156', 'should walk to the earliest hop and take the bracketed connecting IP');
  assert.strictEqual(parsed.headers.originatingIpIsPrivate, false);
  assert.strictEqual(parsed.headers.originatingHop, 1, 'earliest hop is chronologically hop 1 after reversal');
  assert.ok(Array.isArray(parsed.headers.receivedChain));
  assert.strictEqual(parsed.headers.receivedChain.length, 3);
  assert.strictEqual(parsed.headers.receivedChain[0].hop, 1);
});

test('Received chain: reports the earliest private IP when the whole chain is internal', () => {
  const raw = `Received: from internal-relay.corp (internal-relay.corp [10.0.0.9])
	by mail.corp.example with ESMTP; Wed, 22 Jul 2026 10:15:00 +0530
Received: from workstation.corp (workstation.corp [192.168.1.50])
	by internal-relay.corp with ESMTP; Wed, 22 Jul 2026 10:14:50 +0530
From: internal@corp.example
Subject: Internal memo
Content-Type: text/plain

Test.`;

  const parsed = EMLParser.parse(raw);

  assert.strictEqual(parsed.headers.originatingIp, '192.168.1.50');
  assert.strictEqual(parsed.headers.originatingIpIsPrivate, true, 'should be honestly labelled private, not silently dropped');
});

test('Received chain: absent header yields zero hops and a null originating IP, not a crash', () => {
  const raw = `From: test@example.com\nSubject: no received headers\nContent-Type: text/plain\n\nBody text.`;
  const parsed = EMLParser.parse(raw);

  assert.strictEqual(parsed.headers.receivedHops, 0);
  assert.strictEqual(parsed.headers.originatingIp, null);
});

test('Forensic headers: Authentication-Results SPF/DKIM/DMARC verdicts are parsed', () => {
  const raw = `Received: from mx.example.com (mx.example.com [203.0.113.1]) by mx.google.com; Wed, 22 Jul 2026 10:00:00 +0530
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=scam.example; dkim=none; dmarc=fail
From: fraud@scam.example
Subject: test
Content-Type: text/plain

Body.`;

  const parsed = EMLParser.parse(raw);

  assert.strictEqual(parsed.headers.authResults.spf, 'fail');
  assert.strictEqual(parsed.headers.authResults.dkim, 'none');
  assert.strictEqual(parsed.headers.authResults.dmarc, 'fail');
});

test('Forensic headers: Reply-To domain mismatch is flagged (BEC tell)', () => {
  const raw = `From: "Zerodha Support" <support@zerodha.com>
Reply-To: payouts@zerodha-refunds.xyz
Subject: Refund
Content-Type: text/plain

Please reply to claim your refund.`;

  const parsed = EMLParser.parse(raw);

  assert.strictEqual(parsed.headers.replyTo, 'payouts@zerodha-refunds.xyz');
  assert.strictEqual(parsed.headers.replyToMismatch, true);
});

test('Forensic headers: matching Reply-To domain is not flagged', () => {
  const raw = `From: "Zerodha Support" <support@zerodha.com>
Reply-To: help@zerodha.com
Subject: Contract note
Content-Type: text/plain

See attached.`;

  const parsed = EMLParser.parse(raw);
  assert.strictEqual(parsed.headers.replyToMismatch, false);
});

test('Forensic headers: Message-ID domain is extracted (leaks true sending platform)', () => {
  const raw = `From: "SEBI" <alerts@sebi.gov.in>
Message-ID: <20260722.abc123@sendgrid.net>
Subject: test
Content-Type: text/plain

Body.`;

  const parsed = EMLParser.parse(raw);
  assert.strictEqual(parsed.headers.messageIdDomain, 'sendgrid.net');
});

test('Attachment inventory: async path hashes attachment content', async () => {
  const boundary = 'BOUNDARY123';
  const raw = Buffer.from(
    `From: sender@example.com\r\n` +
    `Subject: Invoice\r\n` +
    `Content-Type: multipart/mixed; boundary="${boundary}"\r\n\r\n` +
    `--${boundary}\r\n` +
    `Content-Type: text/plain\r\n\r\n` +
    `See attached invoice.\r\n` +
    `--${boundary}\r\n` +
    `Content-Type: application/pdf\r\n` +
    `Content-Disposition: attachment; filename="invoice.pdf"\r\n` +
    `Content-Transfer-Encoding: base64\r\n\r\n` +
    Buffer.from('fake pdf bytes').toString('base64') + `\r\n` +
    `--${boundary}--\r\n`
  );

  const parsed = await EMLParser.parseAsync(raw);

  assert.strictEqual(parsed.headers.attachmentCount, 1);
  assert.strictEqual(parsed.attachments.length, 1);
  assert.strictEqual(parsed.attachments[0].filename, 'invoice.pdf');
  assert.match(parsed.attachments[0].sha256, /^[a-f0-9]{64}$/, 'attachment must be hashed, not just counted');
});

// ─────────────────────────── 1B: IOC extraction ───────────────────────────

test('IOC extraction: UPI VPA with a recognised PSP handle', () => {
  const iocs = IocExtractor.extract('Pay now to invest.now@oksbi to claim your bonus.');
  const upi = iocs.filter((i) => i.type === 'upi_vpa');
  assert.strictEqual(upi.length, 1);
  assert.strictEqual(upi[0].value, 'invest.now@oksbi');
});

test('IOC extraction: rejects a plain email as a UPI VPA (no PSP handle)', () => {
  const iocs = IocExtractor.extract('Contact us at support@example.com');
  assert.strictEqual(iocs.filter((i) => i.type === 'upi_vpa').length, 0);
});

test('IOC extraction: Indian mobile number in international format', () => {
  const iocs = IocExtractor.extract('Call us on +91 9876543210 for details.');
  const phones = iocs.filter((i) => i.type === 'phone_in');
  assert.strictEqual(phones.length, 1);
  assert.strictEqual(phones[0].value, '9876543210');
});

test('IOC extraction: Telegram and WhatsApp links', () => {
  const iocs = IocExtractor.extract('Join t.me/sebi_tips_group or message wa.me/919876543210 now.');
  assert.ok(iocs.some((i) => i.type === 'telegram' && i.value === 't.me/sebi_tips_group'));
  assert.ok(iocs.some((i) => i.type === 'whatsapp' && i.value === 'wa.me/919876543210'));
});

test('IOC extraction: ETH wallet address', () => {
  const addr = '0x742d35Cc6634C0532925a3b844Bc454e4438f44e';
  const iocs = IocExtractor.extract(`Send USDT to ${addr}`);
  assert.ok(iocs.some((i) => i.type === 'wallet_eth' && i.value === addr));
});

test('IOC extraction: TRON wallet address', () => {
  const iocs = IocExtractor.extract('TRC20 address: TLPpXqLcauUCUD8jK6oDU7dsKW4cwGGCwv');
  assert.ok(iocs.some((i) => i.type === 'wallet_tron'));
});

test('IOC extraction: IFSC + nearby account number pairs are linked', () => {
  const iocs = IocExtractor.extract('Transfer to account 123456789012 IFSC: HDFC0001234 immediately.');
  assert.ok(iocs.some((i) => i.type === 'ifsc' && i.value === 'HDFC0001234'));
  assert.ok(iocs.some((i) => i.type === 'bank_account' && i.value === '123456789012'));
});

test('IOC extraction: bare digit strings without an IFSC nearby are not reported as accounts', () => {
  const iocs = IocExtractor.extract('Order number 123456789012 has shipped.');
  assert.strictEqual(iocs.filter((i) => i.type === 'bank_account').length, 0);
});

test('IOC extraction: deduplicates repeated indicators', () => {
  const iocs = IocExtractor.extract('Pay to scam@paytm or pay to scam@paytm again.');
  assert.strictEqual(iocs.filter((i) => i.type === 'upi_vpa').length, 1);
});

test('IOC extraction: never throws on adversarial/empty input', () => {
  for (const input of ['', null, undefined, 'a'.repeat(50000), '@@@@@@@@@@@@']) {
    assert.doesNotThrow(() => IocExtractor.extract(input));
  }
});

// ───────────────────── 1C: sender spoofing & persistence ─────────────────────

test('Sender spoofing: flags a non-official domain impersonating a regulator', () => {
  const result = PhishingEngine.analyzeText(
    'SEBI URGENT: your account will be suspended, verify now.',
    'alerts@sebi-govin.com'
  );

  assert.ok(result.flags.some((f) => f.type === 'sender_spoofing'), 'sender argument must actually be used');
  assert.strictEqual(result.senderDomain, 'sebi-govin.com');
});

test('Sender spoofing: does not flag the genuine official domain', () => {
  const result = PhishingEngine.analyzeText('SEBI circular on quarterly settlement.', 'circulars@sebi.gov.in');
  assert.ok(!result.flags.some((f) => f.type === 'sender_spoofing'));
});

test('Sender spoofing: no sender provided does not crash and does not flag', () => {
  const result = PhishingEngine.analyzeText('SEBI notice regarding your account.');
  assert.ok(!result.flags.some((f) => f.type === 'sender_spoofing'));
  assert.strictEqual(result.senderDomain, null);
});

test('Persistence surface: analyzeText returns extracted urls, domains, and iocs', () => {
  const result = PhishingEngine.analyzeText(
    'Visit http://z3rodha.com and pay to scam@oksbi, call +919876543210'
  );

  assert.ok(Array.isArray(result.urls) && result.urls.length > 0, 'urls must be returned, not just counted');
  assert.ok(Array.isArray(result.domains) && result.domains.includes('z3rodha.com'));
  assert.ok(Array.isArray(result.iocs));
  assert.ok(result.iocs.some((i) => i.type === 'upi_vpa'));
  assert.ok(result.iocs.some((i) => i.type === 'phone_in'));
});

// ───────────────────── Regression: existing behaviour intact ─────────────────────

test('Regression: benign message with no sender remains SAFE', () => {
  const result = PhishingEngine.analyzeText('Nifty 50 closed higher today.');
  assert.strictEqual(result.verdict, 'SAFE');
});

test('Regression: typosquat detection still fires without a sender argument', () => {
  const result = PhishingEngine.analyzeText('Check out http://z3rodha.com for guaranteed 50% returns');
  assert.strictEqual(result.verdict, 'HIGH_RISK_PHISHING');
});
