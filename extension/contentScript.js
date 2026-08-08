/**
 * SentinelSEBI Browser Extension Content Script
 *
 * 1. Hyperlink Audit: Scans page hyperlinks for typosquat/homoglyph impersonation of official SEBI & broker domains.
 * 2. VPA / Payment Handle Highlight: Detects and badges UPI VPA handles in page text for real-time investor safety.
 * 3. Dynamic MutationObserver: Re-scans newly inserted DOM nodes on single-page applications.
 */
(function () {
  console.log('🛡️ SentinelSEBI Extension Active');

  let API_BASE = 'http://127.0.0.1:8000';
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['sentinelApiBase'], (data) => {
      if (data && data.sentinelApiBase) API_BASE = data.sentinelApiBase.replace(/\/$/, '');
    });
  }

  const OFFICIAL_DOMAINS = [
    'sebi.gov.in', 'nseindia.com', 'bseindia.com', 'cdslindia.com',
    'nsdl.co.in', 'zerodha.com', 'upstox.com', 'groww.in',
    'icicidirect.com', 'angelone.in', 'hdfcsec.com'
  ];

  const vpaRegex = /[a-zA-Z0-9._-]+@(oksbi|okaxis|okicici|okhdfcbank|paytm|ybl|apl|postbank|ibl|sbi|icici|hdfc)/gi;

  function editDistance(s1, s2) {
    const costs = [];
    for (let i = 0; i <= s1.length; i++) {
      let lastValue = i;
      for (let j = 0; j <= s2.length; j++) {
        if (i === 0) costs[j] = j;
        else if (j > 0) {
          let newValue = costs[j - 1];
          if (s1.charAt(i - 1) !== s2.charAt(j - 1)) {
            newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
          }
          costs[j - 1] = lastValue;
          lastValue = newValue;
        }
      }
      if (i > 0) costs[s2.length] = lastValue;
    }
    return costs[s2.length];
  }

  function typosquatSimilarity(s1, s2) {
    const longer = s1.length > s2.length ? s1 : s2;
    const shorter = s1.length > s2.length ? s2 : s1;
    if (longer.length === 0) return 1.0;
    return (longer.length - editDistance(longer, shorter)) / parseFloat(longer.length);
  }

  function auditLinks(root = document) {
    const links = root.querySelectorAll ? root.querySelectorAll('a') : [];
    links.forEach((link) => {
      if (link.dataset.sentinelAudited) return;
      link.dataset.sentinelAudited = 'true';

      try {
        const url = new URL(link.href);
        const domain = url.hostname.replace(/^www\./, '').toLowerCase();
        if (!domain || OFFICIAL_DOMAINS.includes(domain)) return;

        for (const official of OFFICIAL_DOMAINS) {
          const sim = typosquatSimilarity(domain, official);
          if (sim >= 0.72 && sim < 1.0) {
            link.style.outline = '2px solid #ef4444';
            link.style.backgroundColor = 'rgba(239, 68, 68, 0.18)';
            link.style.padding = '2px 4px';
            link.style.borderRadius = '3px';
            link.title = `⚠️ SENTINEL WARNING: Lookalike domain '${domain}' mimicking official SEBI registered domain '${official}'!`;
            console.warn(`[Sentinel] Flagged lookalike domain link: ${domain} mimicking ${official}`);

            const badge = document.createElement('span');
            badge.style.cssText = 'background:#ef4444; color:#ffffff; font-size:10px; font-weight:bold; padding:1px 5px; border-radius:3px; margin-left:4px; font-family:sans-serif; vertical-align:middle;';
            badge.innerText = `⚠️ Lookalike: ${official}`;
            link.appendChild(badge);
            break;
          }
        }
      } catch {}
    });
  }

  function scanDOMForVPA(root = document.body) {
    if (!root) return;
    const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null, false);
    let node;
    while ((node = walk.nextNode())) {
      const parent = node.parentElement;
      if (parent && !['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT', 'NOSCRIPT'].includes(parent.tagName)) {
        vpaRegex.lastIndex = 0;
        if (vpaRegex.test(node.nodeValue)) {
          highlightVPA(parent, node.nodeValue);
        }
      }
    }
  }

  function highlightVPA(parent, text) {
    if (parent.dataset.sentinelScanned) return;
    parent.dataset.sentinelScanned = 'true';

    vpaRegex.lastIndex = 0;
    const matches = text.match(vpaRegex) || [];
    const uniqueVPAs = [...new Set(matches)];

    uniqueVPAs.forEach((vpa) => {
      const span = document.createElement('span');
      span.style.cssText = 'background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid #d97706; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-left: 4px; display: inline-block; font-family: monospace;';
      span.innerText = `🛡️ Sentinel VPA: ${vpa}`;
      parent.appendChild(span);
    });
  }

  // Webmail (Gmail / Outlook) Automatic Email Body Scanner
  async function scanWebmailEmails() {
    const emailBodies = document.querySelectorAll('.a3s.aiL, [data-message-id], .ItemBody, .message-in, .message-out');
    emailBodies.forEach(async (bodyEl) => {
      if (bodyEl.dataset.sentinelEmailScanned) return;
      bodyEl.dataset.sentinelEmailScanned = 'true';

      const emailText = bodyEl.innerText;
      if (!emailText || emailText.length < 15) return;

      try {
        const res = await fetch(`${API_BASE}/phishing/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: emailText, channel: location.host.includes('google') ? 'email' : 'chat' })
        });
        const data = await res.json();
        
        // Notify Background Service Worker to update Chrome Extension Badge (Green, Yellow, Red)
        try {
          chrome.runtime.sendMessage({
            type: 'ANALYSIS_RESULT',
            analysis: data,
            url: window.location.href,
            title: document.title,
            channel: location.host.includes('google') ? 'email' : 'chat'
          });
        } catch (e) {}

        // Inject Sentinel Security Banner on top of the email/chat
        const banner = document.createElement('div');
        const isHigh = data.risk_score >= 70;
        const isMed = data.risk_score >= 30;
        const color = isHigh ? '#ef4444' : isMed ? '#f59e0b' : '#10b981';
        const bg = isHigh ? 'rgba(239, 68, 68, 0.12)' : isMed ? 'rgba(245, 158, 11, 0.12)' : 'rgba(16, 185, 129, 0.12)';
        
        banner.style.cssText = `background: ${bg}; border: 1.5px solid ${color}; color: #ffffff; padding: 10px 14px; border-radius: 6px; margin-bottom: 14px; font-family: system-ui, sans-serif; font-size: 13px; font-weight: 500; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 12px rgba(0,0,0,0.15);`;
        banner.innerHTML = `
          <div>
            <span style="font-weight: 800; color: ${color}; font-family: monospace;">🛡️ SENTINEL SEBI SHIELD</span> &nbsp;|&nbsp; 
            Verdict: <b style="color:${color}">${data.verdict || 'SAFE'} RISK</b> (Score: ${data.risk_score}/100)
            <div style="font-size: 11.5px; opacity: 0.85; margin-top: 3px;">
              ${data.flags && data.flags.length ? data.flags.map(f => f.type.replace(/_/g,' ')).join(', ') : 'No malicious flags detected.'}
              ${isHigh ? '<b style="color:#ef4444;"> • Automatically Reported to SEBI Ledger DB</b>' : ''}
            </div>
          </div>
          <span style="background:${color}; color:#000; font-size:10px; font-weight:bold; padding:3px 8px; border-radius:4px; font-family:monospace;">${data.risk_score}% RISK</span>
        `;
        bodyEl.insertBefore(banner, bodyEl.firstChild);
      } catch (e) {
        console.warn('[Sentinel] Webmail scan backend query failed:', e);
      }
    });
  }

  // Scan overall active page text for tab badge state
  async function scanActivePage() {
    const pageText = document.body ? document.body.innerText.slice(0, 3000) : '';
    if (!pageText || pageText.length < 30) return;

    try {
      const res = await fetch(`${API_BASE}/phishing/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: pageText, channel: 'web' })
      });
      const data = await res.json();
      
      try {
        chrome.runtime.sendMessage({
          type: 'ANALYSIS_RESULT',
          analysis: data,
          url: window.location.href,
          title: document.title,
          channel: 'web'
        });
      } catch (e) {}
    } catch (e) {}
  }

  // Initial Scan
  setTimeout(() => {
    auditLinks();
    scanDOMForVPA();
    scanWebmailEmails();
    scanActivePage();
  }, 500);

  // Dynamic DOM Mutation Observer
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          auditLinks(node);
          scanDOMForVPA(node);
          scanWebmailEmails();
        }
      }
    }
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }
})();
