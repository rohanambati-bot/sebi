/**
 * SentinelSEBI EML RFC 822 / 2047 & Encryption Forensics Engine
 * 
 * Features:
 * 1. Decodes RFC 2047 Base64 / Quoted-Printable subjects & bodies.
 * 2. Detects S/MIME, PGP, and password-protected encrypted payloads.
 * 3. Dynamic Password-Extraction Heuristics (extracts embedded passwords from email body).
 */

class EMLParser {
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

    // 1. Decode RFC 2047 Subject and From headers
    const rawSubject = headers['subject'] || '';
    const decodedSubject = this.decodeRfc2047(rawSubject);

    const rawFrom = headers['from'] || '';
    const decodedFrom = this.decodeRfc2047(rawFrom);
    const senderEmail = decodedFrom.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/)?.[0] || decodedFrom;

    // 2. Decode Body (Quoted-Printable or Base64)
    const transferEncoding = (headers['content-transfer-encoding'] || '').toLowerCase();
    let decodedBody = body;

    if (transferEncoding.includes('base64')) {
      try {
        decodedBody = Buffer.from(body.replace(/\s+/g, ''), 'base64').toString('utf8');
      } catch {}
    } else if (transferEncoding.includes('quoted-printable') || body.includes('=')) {
      decodedBody = this.decodeQuotedPrintable(body);
    }

    decodedBody = decodedBody.replace(/<[^>]+>/g, ' '); // Strip HTML tags

    // 3. Encryption & Password-Protected Payload Forensics
    const contentType = (headers['content-type'] || '').toLowerCase();
    const isSmimeEncrypted = contentType.includes('pkcs7-mime') || contentType.includes('x-pkcs7');
    const isPgpEncrypted = contentType.includes('pgp-encrypted') || decodedBody.includes('-----BEGIN PGP MESSAGE-----');
    const isEncryptedPayload = isSmimeEncrypted || isPgpEncrypted || /encrypted|password-protected/i.test(decodedBody);

    // Dynamic Password Extraction Heuristic
    const extractedPassword = this.extractEmbeddedPassword(decodedBody);

    const dkimSignaturePresent = !!headers['dkim-signature'];
    const receivedHops = (headers['received'] || '').split(/from /i).length - 1;

    return {
      success: true,
      headers: {
        from: senderEmail,
        subject: decodedSubject,
        date: headers['date'] || '',
        dkimSignaturePresent,
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

  /**
   * Extract embedded passwords from email body text (e.g. "Password: 1234", "Passcode: XYZ")
   */
  static extractEmbeddedPassword(text) {
    const match = text.match(/(?:pass(?:word)?|pin|code)\s*[:=]\s*([a-zA-Z0-9@#$!%^&*]{3,20})/i);
    return match ? match[1] : null;
  }
}

module.exports = EMLParser;
