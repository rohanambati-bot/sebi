const test = require('node:test');
const assert = require('node:assert');
const MediaEngine = require('../engines/media_engine');
const CorrelationEngine = require('../engines/correlation_engine');

test('Tier 1 & 2 Platform Features Suite', async (t) => {
  await t.test('1. QR Code / Quishing Payload Detection', () => {
    const mockImageBuffer = Buffer.from(
      'GIF89a... payload https://z3rodha-login.com/verify upi://pay?pa=scammer@oksbi&am=5000'
    );

    const qrResult = MediaEngine.detectQrPayload(mockImageBuffer);
    assert.strictEqual(qrResult.detected, true, 'QR payload detected');
    assert.ok(qrResult.payloads.length >= 2, 'Extracted multiple target URIs');
    assert.ok(qrResult.targetUri.includes('z3rodha-login.com'), 'Extracted lookalike broker target URI');

    const analysis = MediaEngine.analyzeImage(mockImageBuffer);
    assert.strictEqual(analysis.qrDetected, true, 'Image analysis flagged QR code');
    assert.ok(analysis.flags.some(f => f.type === 'quishing_qr_detected'), 'quishing_qr_detected flag added');
    assert.ok(analysis.risk_score >= 85, 'Quishing target elevated image risk score');
  });

  await t.test('2. Campaign Attribution Confidence Score', () => {
    const mockIndicators = [
      { type: 'upi_vpa', value: 'invest.scam@oksbi' },
      { type: 'telegram_link', value: 't.me/sebi_insider_tips' },
      { type: 'domain', value: 'z3rodha-login.com' },
      { type: 'domain', value: 'sebi-govin.com' }
    ];
    const mockScans = [{ id: 1 }, { id: 2 }, { id: 3 }];

    const conf = CorrelationEngine.calculateCampaignConfidence(mockIndicators, mockScans);
    assert.ok(conf.confidenceScore >= 80, 'Multi-factor score assigned correctly');
    assert.strictEqual(conf.confidenceTier, 'VERY_HIGH', 'High confidence tier assigned');
    assert.ok(conf.reasons.length >= 3, 'Multiple evidence reasons documented');
  });
});
