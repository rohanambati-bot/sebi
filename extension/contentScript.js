/**
 * SentinelSEBI Browser Extension Content Script
 */
(function() {
  console.log('🛡️ SentinelSEBI Extension Overlay Active');

  const vpaRegex = /[a-zA-Z0-9._-]+@[a-zA-Z0-9]+/g;

  function scanDOM() {
    const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
    let node;
    while ((node = walk.nextNode())) {
      if (node.parentElement && !['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT'].includes(node.parentElement.tagName)) {
        if (vpaRegex.test(node.nodeValue)) {
          highlightVPA(node.parentElement, node.nodeValue);
        }
      }
    }
  }

  function highlightVPA(parent, text) {
    if (parent.dataset.sentinelScanned) return;
    parent.dataset.sentinelScanned = 'true';

    const matches = text.match(vpaRegex) || [];
    matches.forEach(vpa => {
      const span = document.createElement('span');
      span.style.cssText = 'background: rgba(217, 119, 6, 0.2); color: #f59e0b; border: 1px solid #d97706; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-left: 4px;';
      span.innerText = ` [🛡️ Sentinel: ${vpa}]`;
      parent.appendChild(span);
    });
  }

  setTimeout(scanDOM, 1000);
})();
