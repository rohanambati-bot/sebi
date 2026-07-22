console.log("Sentinel extension active. Auditing page integrity...");

const OFFICIAL_DOMAINS = [
  "sebi.gov.in", "nseindia.com", "bseindia.com", "cdslindia.com",
  "nsdl.co.in", "zerodha.com", "upstox.com", "groww.in",
  "icicidirect.com", "angelone.in", "hdfcsec.com"
];

function typosquatDistance(s1, s2) {
  let longer = s1.length > s2.length ? s1 : s2;
  let shorter = s1.length > s2.length ? s2 : s1;
  if (longer.length === 0) return 1.0;
  return (longer.length - editDistance(longer, shorter)) / parseFloat(longer.length);
}

function editDistance(s1, s2) {
  let costs = [];
  for (let i = 0; i <= s1.length; i++) {
    let lastValue = i;
    for (let j = 0; j <= s2.length; j++) {
      if (i === 0) costs[j] = j;
      else {
        if (j > 0) {
          let newValue = costs[j - 1];
          if (s1.charAt(i - 1) !== s2.charAt(j - 1))
            newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
          costs[j - 1] = lastValue;
          lastValue = newValue;
        }
      }
    }
    if (i > 0) costs[s2.length] = lastValue;
  }
  return costs[s2.length];
}

// Audit hyperlinks inline
document.querySelectorAll("a").forEach(link => {
  try {
    const url = new URL(link.href);
    const domain = url.hostname.replace("www.", "").toLowerCase();
    if (!domain || OFFICIAL_DOMAINS.includes(domain)) return;
    
    for (let official of OFFICIAL_DOMAINS) {
      let sim = typosquatDistance(domain, official);
      if (sim >= 0.75 && sim < 1.0) {
        link.style.border = "2px solid #ef4444";
        link.style.backgroundColor = "rgba(239, 68, 68, 0.15)";
        link.style.padding = "2px 4px";
        link.style.borderRadius = "3px";
        link.title = `⚠️ SENTINEL WARNING: This link looks like lookalike of official domain '${official}'!`;
        console.warn(`[Sentinel] Flagged lookalike domain link: ${domain} mimicking ${official}`);
      }
    }
  } catch(e) {}
});
