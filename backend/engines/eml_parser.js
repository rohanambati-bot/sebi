/**
 * SentinelSEBI EML Engine — Production mailparser + DKIM Verification + Encryption Forensics
 * 
 * Production Tooling:
 * - mailparser (simpleParser): Battle-tested multipart MIME, RFC 2047, nested attachment parsing
 * - DKIM Signature Verification: Parses DKIM-Signature header fields, verifies cryptographic structure
 * - S/MIME & PGP encryption detection with dynamic password extraction heuristics
 */

const { simpleParser } = require('mailparser');

class EMLParser {
  /**
   * Parse EML using mailparser (async) with fallback to manual parsing.
   * Returns a standardized result object.
   */
  static async parseAsync(emlBufferOrString) {
    const rawContent = Buffer.isBuffer(emlBufferOrString)
      ? emlBufferOrString
      : Buffer.from(String(emlBufferOrString || ''), 'utf8');

    try {
      const parsed = await simpleParser(rawContent);
      return this._buildResult(parsed, rawContent.toString('utf8'));
    } catch (err) {
      // Fallback to manual parsing if mailparser fails
      return this.parse(emlBufferOrString);
    }
  }

  /**
   * Build standardized result from mailparser output.
   */
  static _buildResult(parsed, rawStr) {
    const fromAddr = parsed.from ? (parsed.from.value[0]?.address || parsed.from.text || '') : '';
    const subject = parsed.subject || '';
    const bodyText = parsed.text || '';
    const bodyHtml = parsed.html || '';
    const decodedBody = bodyText || bodyHtml.replace(/<[^>]+>/g, ' ');

    // DKIM verification
    const dkimResult = this.verifyDkimStructure(rawStr);

    // Encryption forensics
    const contentType = (parsed.headers?.get('content-type')?.value || '').toLowerCase();
    const isSmimeEncrypted = contentType.includes('pkcs7-mime') || contentType.includes('x-pkcs7');
    const isPgpEncrypted = contentType.includes('pgp-encrypted') || decodedBody.includes('-----BEGIN PGP MESSAGE-----');
    const isEncryptedPayload = isSmimeEncrypted || isPgpEncrypted || /encrypted|password-protected/i.test(decodedBody);
    const extractedPassword = this.extractEmbeddedPassword(decodedBody);

    // Received hops
    const receivedHeaders = parsed.headers?.get('received');
    const receivedHops = Array.isArray(receivedHeaders) ? receivedHeaders.length : (receivedHeaders ? 1 : 0);

    return {
      success: true,
      headers: {
        from: fromAddr,
        subject,
        date: parsed.date ? parsed.date.toISOString() : '',
        dkimSignaturePresent: dkimResult.present,
        dkimVerification: dkimResult.status,
        dkimDetails: dkimResult.details,
        receivedHops,
        encodingDetected: 'mailparser (auto-detected)',
        attachmentCount: parsed.attachments ? parsed.attachments.length : 0,
      },
      encryptionStatus: {
        isEncryptedPayload,
        isSmimeEncrypted,
        isPgpEncrypted,
        extractedPassword,
        securityActionNeeded: isEncryptedPayload ? 'FLAGGED_UNSCANNABLE_ENCRYPTED_PAYLOAD' : 'NONE',
      },
      bodyText: `${subject}\n\n${decodedBody}`,
      rawBody: decodedBody,
    };
  }

  /**
   * Verify DKIM-Signature header structure and cryptographic field presence.
   * Full DNS-based verification would require network access; we verify the
   * structural integrity and field completeness of the signature.
   */
  static verifyDkimStructure(rawEml) {
    const dkimMatch = rawEml.match(/DKIM-Signature:\s*([^\r\n]+(?:\r?\n\s+[^\r\n]+)*)/i);
    if (!dkimMatch) {
      return { present: false, status: 'DKIM_MISSING', details: 'No DKIM-Signature header found.' };
    }

    const dkimHeader = dkimMatch[1].replace(/\r?\n\s+/g, ' ');
    const fields = {};
    for (const part of dkimHeader.split(';')) {
      const kv = part.trim().match(/^([a-z]+)\s*=\s*(.+)/i);
      if (kv) fields[kv[1].toLowerCase()] = kv[2].trim();
    }

    const requiredFields = ['v', 'd', 's', 'b', 'bh', 'h', 'a'];
    const missingFields = requiredFields.filter(f => !fields[f]);

    if (missingFields.length > 0) {
      return {
        present: true,
        status: 'DKIM_MALFORMED',
        details: `DKIM-Signature present but missing required fields: ${missingFields.join(', ')}. Possible spoofed header.`,
        fields
      };
    }

    // Verify algorithm is acceptable
    const algo = fields['a'] || '';
    const validAlgos = ['rsa-sha256', 'rsa-sha1', 'ed25519-sha256'];
    if (!validAlgos.includes(algo.toLowerCase())) {
      return {
        present: true,
        status: 'DKIM_SUSPICIOUS_ALGO',
        details: `DKIM uses non-standard algorithm: ${algo}`,
        fields
      };
    }

    return {
      present: true,
      status: 'DKIM_STRUCTURALLY_VALID',
      details: `DKIM-Signature structurally valid (v=${fields.v}, d=${fields.d}, s=${fields.s}, a=${fields.a}). Full DNS verification requires network access.`,
      signingDomain: fields.d,
      selector: fields.s,
      algorithm: fields.a,
      fields
    };
  }

  /**
   * Synchronous fallback parser (for backward compatibility with existing tests).
   */
  static parse(emlBufferOrString) {
    const rawContent = Buffer.isBuffer(emlBufferOrString)
      ? emlBufferOrString.toString('utf8')
      : String(emlBufferOrString || '');

    const headers = {};
    let body = '';

    const parts = rawContent.split(/\r?\n\r?\n/);
    const headerLines = (parts[0] || '').split(/\r?\n/);

    let currentHeader = '';
    for (const line of headerLines) {
      if (/^\s+/.test(line) && currentHeader) {
        headers[currentHeader] += ' ' + line.trim();
      } else {
        const match = line.match(/^([a-zA-Z0-9-]+):\s*(.*)$/);
        if (match) {
          currentHeader = match[1].toLowerCase();
          headers[currentHeader] = match[2].trim();
        }
      }
    }

    body = parts.slice(1).join('\n\n').trim();

    const rawSubject = headers['subject'] || '';
    const decodedSubject = this.decodeRfc2047(rawSubject);

    const rawFrom = headers['from'] || '';
    const decodedFrom = this.decodeRfc2047(rawFrom);
    const senderEmail = decodedFrom.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/)?.[0] || decodedFrom;

    const transferEncoding = (headers['content-transfer-encoding'] || '').toLowerCase();
    let decodedBody = body;

    if (transferEncoding.includes('base64')) {
      try {
        decodedBody = Buffer.from(body.replace(/\s+/g, ''), 'base64').toString('utf8');
      } catch {}
    } else if (transferEncoding.includes('quoted-printable') || body.includes('=')) {
      decodedBody = this.decodeQuotedPrintable(body);
    }

    decodedBody = decodedBody.replace(/<[^>]+>/g, ' ');

    const contentType = (headers['content-type'] || '').toLowerCase();
    const isSmimeEncrypted = contentType.includes('pkcs7-mime') || contentType.includes('x-pkcs7');
    const isPgpEncrypted = contentType.includes('pgp-encrypted') || decodedBody.includes('-----BEGIN PGP MESSAGE-----');
    const isEncryptedPayload = isSmimeEncrypted || isPgpEncrypted || /encrypted|password-protected/i.test(decodedBody);
    const extractedPassword = this.extractEmbeddedPassword(decodedBody);

    const dkimResult = this.verifyDkimStructure(rawContent);
    const receivedHops = (headers['received'] || '').split(/from /i).length - 1;

    return {
      success: true,
      headers: {
        from: senderEmail,
        subject: decodedSubject,
        date: headers['date'] || '',
        dkimSignaturePresent: dkimResult.present,
        dkimVerification: dkimResult.status,
        dkimDetails: dkimResult.details,
        receivedHops,
        encodingDetected: transferEncoding || 'RFC 2047 / standard',
      },
      encryptionStatus: {
        isEncryptedPayload,
        isSmimeEncrypted,
        isPgpEncrypted,
        extractedPassword,
        securityActionNeeded: isEncryptedPayload ? 'FLAGGED_UNSCANNABLE_ENCRYPTED_PAYLOAD' : 'NONE',
      },
      bodyText: `${decodedSubject}\n\n${decodedBody}`,
      rawBody: decodedBody,
    };
  }

  static decodeRfc2047(str) {
    if (!str || !str.includes('=?')) return str;
    return str.replace(/=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g, (_, charset, encoding, data) => {
      try {
        if (encoding.toUpperCase() === 'B') {
          return Buffer.from(data, 'base64').toString('utf8');
        } else if (encoding.toUpperCase() === 'Q') {
          return this.decodeQuotedPrintable(data.replace(/_/g, ' '));
        }
      } catch {}
      return data;
    });
  }

  static decodeQuotedPrintable(str) {
    if (!str) return '';
    return str
      .replace(/=\r?\n/g, '')
      .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  }

  static extractEmbeddedPassword(text) {
    const match = text.match(/(?:pass(?:word)?|pin|code)\s*[:=]\s*([a-zA-Z0-9@#$!%^&*]{3,20})/i);
    return match ? match[1] : null;
  }
}

module.exports = EMLParser;
