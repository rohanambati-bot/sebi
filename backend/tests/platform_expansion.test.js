const test = require('node:test');
const assert = require('node:assert');
const SebiAdvisoryIndex = require('../engines/sebi_advisory_index');
const PhishingEngine = require('../engines/phishing_engine');
const { ExportEngine } = require('../engines/export_engine');

test('Platform Expansion Feature Suite', async (t) => {
  await t.test('1. SEBI Advisory Contradiction Engine (Grounding RAG Layer)', () => {
    const scamText = 'URGENT: Pay ₹10,000 to unlock your demat account immediately and get guaranteed 500% returns on pre-IPO shares.';
    
    const check = SebiAdvisoryIndex.checkAdvisoryContradiction(scamText);
    assert.strictEqual(check.contradicted, true, 'Flagged SEBI circular contradiction');
    assert.ok(check.matches.length >= 2, 'Matched multiple SEBI circular violations');
    assert.ok(check.matches.some(m => m.advisoryId === 'SEBI-CIRCULAR-2026-04'), 'Matched SEBI zero unlock fee circular');

    const analysis = PhishingEngine.analyzeText(scamText);
    assert.ok(analysis.flags.some(f => f.type === 'sebi_advisory_contradiction'), 'Added sebi_advisory_contradiction flag');
    assert.ok(analysis.risk_score >= 80, 'Risk score elevated due to regulatory contradiction');
  });

  await t.test('2. NPCI Payment Security VPA Freeze Notice Generator', () => {
    const notice = ExportEngine.generateNpciFreezeNotice({
      noticeId: 'NPCI-TEST-001',
      vpa: 'fraudster@oksbi',
      scanId: 42,
      evidenceHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    });

    assert.ok(notice.includes('NPCI PAYMENT SECURITY DIRECTIVE'), 'Formatted NPCI security header');
    assert.ok(notice.includes('fraudster@oksbi'), 'Target VPA present in notice');
    assert.ok(notice.includes('Section 18'), 'Statutory PSS Act authority cited');
  });
});
