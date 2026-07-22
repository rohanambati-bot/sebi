const test = require('node:test');
const assert = require('node:assert');
const EMLParser = require('../engines/eml_parser');

test('EML RFC 822 & RFC 2047 Decoders Suite', async (t) => {
  await t.test('Decode Base64 RFC 2047 Subject Header', () => {
    const rawEml = `From: "Groww Digest" <noreply@digest.groww.in>
Subject: =?UTF-8?B?TWFqb3IgYmFua3MgUTEgcmVzdWx0cyBvdXQsIEwmVCdzIFJzIDEwLDAwMCBjci1ScyAxNSwwMDAgY3IgbWVnYSBvcmRlcnMsICYgbW9yZSAtIEdyb3d3IERpZ2VzdA==?=
Date: Wed, 22 Jul 2026 15:20:00 +0530
Content-Type: text/plain

Major banks Q1 results out today.`;

    const parsed = EMLParser.parse(rawEml);

    assert.strictEqual(parsed.success, true);
    assert.strictEqual(parsed.headers.from, 'noreply@digest.groww.in');
    assert.ok(parsed.headers.subject.includes('Major banks Q1 results out'), `Decoded Subject: ${parsed.headers.subject}`);
  });
});
