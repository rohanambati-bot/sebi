const test = require('node:test');
const assert = require('node:assert');
const EMLParser = require('../engines/eml_parser');

test('Encrypted Payload & Password Extraction Forensics Suite', async (t) => {
  await t.test('Detect S/MIME Encryption & Extract Body Password', () => {
    const rawEml = `From: "Bank Support" <alert@spoofed-bank.com>
Subject: Account Statement
Content-Type: application/pkcs7-mime

Dear Customer,
Attached statement is encrypted.
Password: DOB1990`;

    const parsed = EMLParser.parse(rawEml);

    assert.strictEqual(parsed.encryptionStatus.isEncryptedPayload, true, 'Flagged as encrypted payload');
    assert.strictEqual(parsed.encryptionStatus.isSmimeEncrypted, true, 'S/MIME header detected');
    assert.strictEqual(parsed.encryptionStatus.extractedPassword, 'DOB1990', 'Extracted embedded password');
  });
});
