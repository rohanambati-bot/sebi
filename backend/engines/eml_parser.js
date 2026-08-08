/**
 * SentinelSEBI EML Engine — Production mailparser + DKIM Verification + Encryption Forensics
 * 
 * Production Tooling:
 * - mailparser (simpleParser): Battle-tested multipart MIME, RFC 2047, nested attachment parsing
 * - DKIM Signature Verification: Parses DKIM-Signature header fields, verifies cryptographic structure
 * - S/MIME & PGP encryption detection with dynamic password extraction heuristics
 * - Phase 1 forensic header extraction: full Received: chain, originating IP,
 *   Return-Path / Reply-To / Message-ID, Authentication-Results (SPF/DKIM/DMARC),
 *   and per-attachment hashing.
 */

const crypto = require('crypto');
const { simpleParser } = require('mailparser');

/** RFC 1918 / loopback / link-local / ULA ranges. Not a real origin. */
function isPrivateIp(ip) {
  if (!ip) return false;

  if (ip.includes('.')) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return false;
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 0) return true;
    return false;
  }

  const lower = ip.toLowerCase();
  if (lower === '::1') return true;
  if (lower.startsWith('fe80:')) return true; // link-local
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true; // fc00::/7 ULA
  return false;
}

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
// Deliberately conservative: full IPv6 has many valid textual forms. This
// catches the common colon-hex forms seen in Received headers, which is
// sufficient for provenance purposes; it is not a complete IPv6 validator.
const IPV6_RE = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b/g;

function extractIps(text) {
  const found = [];
  for (const m of text.match(IPV4_RE) || []) found.push(m);
  for (const m of text.match(IPV6_RE) || []) found.push(m);
  return [...new Set(found)];
}

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

    // Full forensic header extraction (Phase 1): Received chain, originating
    // IP, Return-Path/Reply-To/Message-ID, Authentication-Results.
    const forensics = this.buildForensicHeaders(rawStr, fromAddr);

    // Attachment inventory with hashes — filenames/MIME types/hashes are kept
    // even though the file content itself is not retained by this parser.
    const attachments = (parsed.attachments || []).map((att) => ({
      filename: att.filename || null,
      contentType: att.contentType || null,
      sizeBytes: att.size ?? (att.content ? att.content.length : null),
      sha256: att.content ? crypto.createHash('sha256').update(att.content).digest('hex') : null,
    }));

    return {
      success: true,
      headers: {
        from: fromAddr,
        subject,
        date: parsed.date ? parsed.date.toISOString() : '',
        dkimSignaturePresent: dkimResult.present,
        dkimVerification: dkimResult.status,
        dkimDetails: dkimResult.details,
        receivedHops: forensics.receivedHops,
        encodingDetected: 'mailparser (auto-detected)',
        attachmentCount: attachments.length,
        // Forensic fields — see buildForensicHeaders for scope/limitations.
        receivedChain: forensics.receivedChain,
        originatingIp: forensics.originatingIp,
        originatingIpIsPrivate: forensics.originatingIpIsPrivate,
        originatingIpVerified: forensics.originatingIpVerified,
        originatingHop: forensics.originatingHop,
        returnPath: forensics.returnPath,
        replyTo: forensics.replyTo,
        replyToMismatch: forensics.replyToMismatch,
        messageId: forensics.messageId,
        messageIdDomain: forensics.messageIdDomain,
        xMailer: forensics.xMailer,
        xOriginatingIp: forensics.xOriginatingIp,
        authResults: forensics.authResults,
        toRecipients: forensics.toRecipients,
        ccRecipients: forensics.ccRecipients,
      },
      attachments,
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
    const forensics = this.buildForensicHeaders(rawContent, senderEmail);

    return {
      success: true,
      headers: {
        from: senderEmail,
        subject: decodedSubject,
        date: headers['date'] || '',
        dkimSignaturePresent: dkimResult.present,
        dkimVerification: dkimResult.status,
        dkimDetails: dkimResult.details,
        receivedHops: forensics.receivedHops,
        encodingDetected: transferEncoding || 'RFC 2047 / standard',
        attachmentCount: 0, // the sync fallback does not parse MIME parts
        receivedChain: forensics.receivedChain,
        originatingIp: forensics.originatingIp,
        originatingIpIsPrivate: forensics.originatingIpIsPrivate,
        originatingIpVerified: forensics.originatingIpVerified,
        originatingHop: forensics.originatingHop,
        returnPath: forensics.returnPath,
        replyTo: forensics.replyTo,
        replyToMismatch: forensics.replyToMismatch,
        messageId: forensics.messageId,
        messageIdDomain: forensics.messageIdDomain,
        xMailer: forensics.xMailer,
        xOriginatingIp: forensics.xOriginatingIp,
        authResults: forensics.authResults,
        toRecipients: forensics.toRecipients,
        ccRecipients: forensics.ccRecipients,
      },
      attachments: [],
      encryptionStatus: {
        isEncryptedPayload,
        isSmimeEncrypted,
        isPgpEncrypted,
        extractedPassword,
        credentialArtifactDetected: Boolean(extractedPassword),
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

  // ─────────────────────── Phase 1: Forensic Headers ───────────────────────

  /**
   * Extract every occurrence of a header, unfolding continuation lines.
   * Used for headers that can legitimately repeat (Received, Authentication-Results).
   */
  static extractHeaderValues(rawEml, name) {
    const re = new RegExp(`^${name}:\\s*([^\\r\\n]+(?:\\r?\\n[ \\t]+[^\\r\\n]+)*)`, 'gim');
    const out = [];
    let m;
    while ((m = re.exec(rawEml)) !== null) {
      out.push(m[1].replace(/\r?\n[ \t]+/g, ' ').trim());
    }
    return out;
  }

  static extractHeaderValue(rawEml, name) {
    const values = this.extractHeaderValues(rawEml, name);
    return values.length ? values[0] : null;
  }

  static _extractEmailAddress(str) {
    if (!str) return null;
    const match = str.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
    return match ? match[0].toLowerCase() : null;
  }

  static _extractAllEmailAddresses(str) {
    if (!str) return [];
    const matches = str.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
    return [...new Set(matches.map((m) => m.toLowerCase()))];
  }

  static _domainOf(addr) {
    if (!addr || !addr.includes('@')) return null;
    return addr.split('@').pop().toLowerCase();
  }

  /**
   * Parse one Received: header into its structural parts.
   *
   * Received headers are free-text and MTA-specific; this extracts what is
   * consistently present across common MTAs (Postfix, Exim, Sendmail, Gmail,
   * Outlook/Exchange) rather than attempting a full grammar per RFC 5321 §4.4.
   */
  static _parseReceivedHop(raw, hopNumber) {
    const fromMatch = raw.match(/\bfrom\s+([^\s;]+)/i);
    const byMatch = raw.match(/\bby\s+([^\s;]+)/i);
    const withMatch = raw.match(/\bwith\s+([^\s;]+)/i);
    const dateMatch = raw.match(/;\s*([^;]+)$/);

    // The trustworthy IP is the one inside the parenthetical that follows
    // "from <claimed-name>": "from <claimed> (<verified-name> [<verified-ip>])".
    // That bracket is what the receiving MTA observed on the actual TCP
    // connection. A bracket appearing directly after "from" with no
    // parenthetical (e.g. "from [10.0.0.5]") is the client's self-declared
    // HELO/EHLO address, which is attacker-controlled text and must not be
    // preferred over the verified one — this is the exact distinction that
    // makes Received-header IP extraction meaningful rather than spoofable.
    const parenMatch = raw.match(/\bfrom\s+\S+\s*\(([^)]*)\)/i);
    const bracketInParen = parenMatch
      ? parenMatch[1].match(/\[((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,})\]/)
      : null;
    const anyBracket = raw.match(/\[((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,})\]/);
    const anyIps = extractIps(raw);

    const ip = bracketInParen ? bracketInParen[1] : (anyBracket ? anyBracket[1] : (anyIps[0] || null));
    const ipIsVerified = Boolean(bracketInParen);

    return {
      hop: hopNumber,
      from_host: fromMatch ? fromMatch[1].replace(/[,;]$/, '') : null,
      by_host: byMatch ? byMatch[1].replace(/[,;]$/, '') : null,
      protocol: withMatch ? withMatch[1].replace(/[,;]$/, '') : null,
      ip,
      // True only when the IP came from the parenthetical the receiving MTA
      // itself recorded, not from a client-supplied HELO string.
      ip_is_trusted_source: ipIsVerified,
      ip_is_private: ip ? isPrivateIp(ip) : null,
      timestamp: dateMatch ? dateMatch[1].trim() : null,
      raw,
    };
  }

  /**
   * Extract forensic headers relevant to attribution: the full Received chain,
   * the best-effort originating IP, Return-Path/Reply-To/Message-ID, X-Mailer,
   * X-Originating-IP, and SPF/DKIM/DMARC verdicts from Authentication-Results.
   *
   * Scope: this reads what the receiving mail infrastructure already recorded.
   * It does not perform live DNS/SPF/DKIM verification — see verifyDkimStructure
   * for why that is deliberately out of scope here.
   */
  static buildForensicHeaders(rawEml, fromAddr) {
    // Received headers are prepended by each hop, so the header nearest the top
    // of the file is the most recent (closest to the recipient) and the one
    // nearest the bottom is the oldest (closest to the sender). Reversing gives
    // chronological order so hop 1 is the earliest hop in the chain.
    const receivedTopToBottom = this.extractHeaderValues(rawEml, 'Received');
    const receivedChain = [...receivedTopToBottom]
      .reverse()
      .map((raw, idx) => this._parseReceivedHop(raw, idx + 1));

    // Walk from the earliest hop forward — the hop closest to the true sender —
    // and take the first public IP. If the entire chain is private (internal
    // relay, VPN, misconfigured MTA), report the earliest private IP instead
    // so an investigator sees that the chain never left a private network
    // rather than seeing nothing. Each hop's `ip` field already prefers the
    // MTA-verified parenthetical address over an unverified HELO string (see
    // _parseReceivedHop), so no further trust ranking is needed here.
    let originatingIp = null;
    let originatingIpIsPrivate = null;
    let originatingIpVerified = null;
    let originatingHop = null;
    for (const hop of receivedChain) {
      if (!hop.ip) continue;
      if (!hop.ip_is_private) {
        originatingIp = hop.ip;
        originatingIpIsPrivate = false;
        originatingIpVerified = hop.ip_is_trusted_source;
        originatingHop = hop.hop;
        break;
      }
      if (originatingIp === null) {
        originatingIp = hop.ip;
        originatingIpIsPrivate = true;
        originatingIpVerified = hop.ip_is_trusted_source;
        originatingHop = hop.hop;
      }
    }

    const authValues = this.extractHeaderValues(rawEml, 'Authentication-Results');
    const authBlob = authValues.join(' ');
    const spfMatch = authBlob.match(/\bspf=(\w+)/i);
    const dkimMatch = authBlob.match(/\bdkim=(\w+)/i);
    const dmarcMatch = authBlob.match(/\bdmarc=(\w+)/i);

    const returnPathRaw = this.extractHeaderValue(rawEml, 'Return-Path');
    const replyToRaw = this.extractHeaderValue(rawEml, 'Reply-To');
    const messageIdRaw = this.extractHeaderValue(rawEml, 'Message-ID');
    const xMailer = this.extractHeaderValue(rawEml, 'X-Mailer');
    const xOriginatingIp = this.extractHeaderValue(rawEml, 'X-Originating-IP');
    const toRaw = this.extractHeaderValue(rawEml, 'To');
    const ccRaw = this.extractHeaderValue(rawEml, 'Cc');

    const replyToAddr = this._extractEmailAddress(replyToRaw);
    const fromDomain = this._domainOf(fromAddr);
    const replyToDomain = this._domainOf(replyToAddr);
    // Classic BEC tell: reply traffic is redirected to a different domain than
    // the one the message claims to be from.
    const replyToMismatch = Boolean(replyToAddr && fromDomain && replyToDomain && replyToDomain !== fromDomain);

    const messageId = messageIdRaw ? messageIdRaw.replace(/^<|>$/g, '') : null;

    return {
      receivedChain,
      receivedHops: receivedChain.length,
      originatingIp,
      originatingIpIsPrivate,
      originatingIpVerified,
      originatingHop,
      returnPath: this._extractEmailAddress(returnPathRaw) || returnPathRaw,
      replyTo: replyToAddr || replyToRaw,
      replyToMismatch,
      messageId,
      // The domain in a Message-ID frequently identifies the true sending
      // platform (e.g. sendgrid.net, mailgun.org) even when From: is spoofed.
      messageIdDomain: messageId ? (messageId.match(/@([^>]+)$/)?.[1] || null) : null,
      xMailer,
      xOriginatingIp,
      authResults: {
        raw: authValues.length ? authBlob : null,
        spf: spfMatch ? spfMatch[1].toLowerCase() : null,
        dkim: dkimMatch ? dkimMatch[1].toLowerCase() : null,
        dmarc: dmarcMatch ? dmarcMatch[1].toLowerCase() : null,
      },
      toRecipients: this._extractAllEmailAddresses(toRaw),
      ccRecipients: this._extractAllEmailAddresses(ccRaw),
    };
  }
}

module.exports = EMLParser;
