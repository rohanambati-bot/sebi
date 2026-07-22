const test = require('node:test');
const assert = require('node:assert');
const PhishingEngine = require('../engines/phishing_engine');

test('Multi-Lingual Regional Language Phishing Detection Suite', async (t) => {
  await t.test('Hindi Phishing Detection (गारंटीड मुनाफा)', () => {
    const res = PhishingEngine.analyzeText('इस ग्रुप में जुड़ें 100% गारंटीड मुनाफा कमाएं');
    assert.strictEqual(res.verdict, 'HIGH_RISK_PHISHING');
    assert.ok(res.flags.some(f => f.detail.includes('गारंटीड मुनाफा')));
  });

  await t.test('Tamil Phishing Detection (நிச்சய லாபம்)', () => {
    const res = PhishingEngine.analyzeText('இப்போதே டெபாசிட் செய்யுங்கள் நிச்சயம் லாபம்');
    assert.strictEqual(res.verdict, 'HIGH_RISK_PHISHING');
    assert.ok(res.flags.some(f => f.detail.includes('நிச்சய லாபம்')));
  });

  await t.test('Telugu Phishing Detection (గ్యారెంటీ లాభాలు)', () => {
    const res = PhishingEngine.analyzeText('తక్షణ డిపాజిట్ చేయండి గ్యారెంటీ లాభాలు');
    assert.strictEqual(res.verdict, 'HIGH_RISK_PHISHING');
    assert.ok(res.flags.some(f => f.detail.includes('గ్యారెంటీ లాభాలు')));
  });
});
