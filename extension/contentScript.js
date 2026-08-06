/**
 * SentinelSEBI Browser Extension Content Script
 *
 * 1. Hyperlink Audit: Scans page hyperlinks for typosquat/homoglyph impersonation of official SEBI & broker domains.
 * 2. VPA / Payment Handle Highlight: Detects and badges UPI VPA handles in page text for real-time investor safety.
 * 3. Dynamic MutationObserver: Re-scans newly inserted DOM nodes on single-page applications.
 */
(function () {
  console.log('🛡️ SentinelSEBI Extension Active');

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

  // Initial Scan
  setTimeout(() => {
    auditLinks();
    scanDOMForVPA();
  }, 500);

  // Dynamic DOM Mutation Observer
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          auditLinks(node);
          scanDOMForVPA(node);
        }
      }
    }
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }
})();
