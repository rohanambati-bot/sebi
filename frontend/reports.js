// SentinelSEBI — Reports & Regulatory Module
// PKI registration, verification, alerts, CERT-In takedown, reports,
// campaign intelligence, social feed, system diagnostics

// PKI Digital Signing Official broadcaster
async function registerOfficialComm() {
  const issuer = document.getElementById('reg-issuer').value;
  const channel = document.getElementById('reg-channel').value;
  const content = document.getElementById('reg-content').value;

  if(!content.trim()) { showToast("Please enter official text."); return; }

  const outBox = document.getElementById('registration-cert-result');
  outBox.innerHTML = '<p class="text-secondary">Generating RSA 2048 keys and applying private key signature...</p>';
  outBox.style.display = 'block';

  // Registering an official communication asserts authenticity on an
  // issuer's behalf, so the backend requires an admin token.
  if (!(await ensureAdmin())) {
    outBox.innerHTML = '<p class="text-secondary">Administrator sign-in required to register official communications.</p>';
    return;
  }

  try {
    const res = await apiPostJson('/verify/register', { issuer, channel, content });
    const data = await res.json();
    
    const verificationUrl = `${CONFIG.apiEndpoint}/verify/qr?code=${data.verify_code}`;
    
    // Update key display under Settings dynamically
    const settingsKeyBox = document.getElementById(`key-display-${issuer.toLowerCase()}`);
    if (settingsKeyBox) {
      settingsKeyBox.value = data.public_key;
    }
    
    outBox.innerHTML = `
      <div class="cert-container">
        <div class="cert-title">Verified PKI Registration Certificate</div>
        <div class="cert-meta">
          Issuer: <b>${issuer}</b> &nbsp;|&nbsp; Verification Code: <span class="code-chip">${data.verify_code}</span><br>
          Root Domain: <b>${data.source_domain}</b><br>
          Content Hash: <span style="font-size:9.5px; word-break:break-all;">${data.content_hash}</span>
        </div>
        <div class="cert-qr">
          <canvas id="cert-qr-canvas"></canvas>
        </div>
        <p style="font-size:11px; color:var(--text-secondary);">
          Scan this QR code or use verification code <b>${data.verify_code}</b> to verify authenticity.
        </p>
        <a class="ghost-btn" style="text-decoration:none;" href="data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify({
          verify_code: data.verify_code,
          issuer: issuer,
          content: content,
          signature: data.signature
        }))}" download="Sentinel_${data.verify_code}.json">Download Signature Payload</a>
      </div>
    `;

    // Draw QR Code
    new QRious({
      element: document.getElementById('cert-qr-canvas'),
      value: verificationUrl,
      size: 140
    });

    showToast("Communication registered & signature generated!");
    loadRegistry();

  } catch (e) {
    outBox.innerHTML = '<p style="color:var(--high);">Error registering communication.</p>';
  }
}

// Verification Checkers
async function verifyByCode() {
  const code = document.getElementById('check-code-input').value;
  if(!code.trim()) { showToast("Please input verify code."); return; }

  const resBox = document.getElementById('verify-result-box');
  const labelEl = document.getElementById('verify-verdict-title');
  const barEl = document.getElementById('verify-verdict-bar');
  const msgEl = document.getElementById('verify-verdict-msg');
  const badgeEl = document.getElementById('verify-badge-issuer');

  resBox.style.display = 'block';
  msgEl.innerText = "Querying registry...";

  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/verify/by-code`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code })
    });
    const data = await res.json();
    
    labelEl.innerText = data.status;
    const verdictClass = data.verdict_label ? data.verdict_label.toLowerCase() : (data.status.includes('CRYPTOGRAPHICALLY') ? 'low_risk' : data.status.includes('SIMILAR') ? 'moderate_risk' : 'high_risk');
    barEl.className = `verdict-header verd-${verdictClass}`;
    msgEl.innerText = data.message;
    badgeEl.innerText = `ISSUER: ${data.issuer || 'UNKNOWN'} | DOMAIN: ${data.source_domain || 'UNKNOWN'}`;

  } catch (e) {
    msgEl.innerText = "Registry query failed.";
  }
}

async function verifyByContent() {
  const content = document.getElementById('check-content-input').value;
  if(!content.trim()) { showToast("Please paste content."); return; }

  const resBox = document.getElementById('verify-result-box');
  const labelEl = document.getElementById('verify-verdict-title');
  const barEl = document.getElementById('verify-verdict-bar');
  const msgEl = document.getElementById('verify-verdict-msg');
  const badgeEl = document.getElementById('verify-badge-issuer');

  resBox.style.display = 'block';
  msgEl.innerText = "Querying registry database...";

  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/verify/by-content`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content })
    });
    const data = await res.json();
    
    labelEl.innerText = data.status;
    const fuzzyClass = data.status === 'CRYPTOGRAPHICALLY VERIFIED' ? 'low_risk' : (data.status === 'SIMILAR TO REGISTERED COMMUNICATION' ? 'moderate_risk' : 'high_risk');
    barEl.className = `verdict-header verd-${fuzzyClass}`;
    msgEl.innerText = data.message || `Fuzzy matching result: ${data.status}`;
    badgeEl.innerText = `REGISTRY FUZZY COMPARISON | SIMILARITY: ${data.similarityScore ? (data.similarityScore*100).toFixed(0)+'%' : (data.similarity ? (data.similarity*100).toFixed(0)+'%' : 'N/A')}`;

  } catch (e) {
    msgEl.innerText = "Registry query failed.";
  }
}

async function verifyByFile() {
  const fileEl = document.getElementById('verify-file-input');
  const file = fileEl.files[0];
  if(!file) return;

  const resBox = document.getElementById('verify-result-box');
  const labelEl = document.getElementById('verify-verdict-title');
  const barEl = document.getElementById('verify-verdict-bar');
  const msgEl = document.getElementById('verify-verdict-msg');
  const badgeEl = document.getElementById('verify-badge-issuer');

  resBox.style.display = 'block';
  msgEl.innerText = "Uploading file and resolving certificates / QR structures...";

  const fd = new FormData();
  fd.append('file', file);

  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/verify/by-file`, {
      method: 'POST',
      body: fd
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      labelEl.innerText = "VERIFICATION ERROR";
      barEl.className = "verdict-header verd-high";
      msgEl.innerText = data.detail || data.message || `File verification failed (HTTP ${res.status}).`;
      badgeEl.innerText = "FILE INTEGRITY HASH VERIFICATION";
      return;
    }
    
    labelEl.innerText = data.status || "VERIFICATION COMPLETED";
    barEl.className = `verdict-header verd-${(data.verdict_label || 'high').toLowerCase()}`;
    msgEl.innerText = data.message || "File verified.";
    
    let badgeTxt = `FILE INTEGRITY HASH VERIFICATION`;
    if(data.qr_detected) {
      badgeTxt = `QR DECODER DETECTED ADVISORY`;
    }
    if(data.issuer) {
      badgeTxt += ` | ISSUER: ${data.issuer}`;
    }
    badgeEl.innerText = badgeTxt;

  } catch (e) {
    labelEl.innerText = "VERIFICATION ERROR";
    barEl.className = "verdict-header verd-high";
    msgEl.innerText = `File verification query failed: ${e.message}`;
  }
}

// Load public communications registry
async function loadRegistry() {
  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/verify/registry`);
    const data = await res.json();
    
    const tbody = document.getElementById('public-registry-body');
    if (data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No publications registered yet.</td></tr>';
    } else {
      tbody.innerHTML = data.map(r => `
        <tr>
          <td><span class="code-chip">${r.verify_code}</span></td>
          <td style="font-weight:600;">${r.issuer}</td>
          <td>${r.channel}</td>
          <td><code>${r.source_domain}</code></td>
          <td class="text-secondary">${r.preview}...</td>
        </tr>
      `).join('');
    }
  } catch(e) {}
}

// Load Threat Alerts
async function loadAlerts() {
  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/alerts/feed`);
    const data = await res.json();
    
    const feed = document.getElementById('full-alerts-feed');
    if(data.length === 0) {
      feed.innerHTML = '<p class="text-secondary" style="text-align:center;">No bulletins found.</p>';
    } else {
      feed.innerHTML = data.map(a => {
        const urgencyClass = a.severity === 'critical' || a.severity === 'high' ? 'crit' : (a.severity === 'medium' ? 'warn' : 'info');
        const timeStr = new Date(a.created_at * 1000).toLocaleString();
        return `<div class="feed-item">
          <div class="feed-badge ${urgencyClass}"></div>
          <div class="feed-details">
            <h3>${escapeHtml(a.title)} &nbsp;<span class="code-chip" style="font-size:9px; border-radius:2px; vertical-align:middle; text-transform:uppercase;">${escapeHtml(a.category)}</span></h3>
            <p style="margin-top:6px; font-size:13px; color:var(--text-primary);">${escapeHtml(a.description)}</p>
            <div class="feed-time">BROADCASTED BY SEBI ADMIN · ${timeStr}</div>
          </div>
        </div>`;
      }).join('');
    }
  } catch(e) {}
}

// SEBI Admin broadcasts a new warning
async function submitPublicAlert() {
  const title = document.getElementById('new-alert-title').value;
  const category = document.getElementById('new-alert-cat').value;
  const severity = document.getElementById('new-alert-severity').value;
  const description = document.getElementById('new-alert-desc').value;

  if(!title.trim() || !description.trim()) { showToast("Please input alert fields."); return; }

  // Publishing a public warning names a domain/handle as fraudulent.
  if (!(await ensureAdmin())) return;

  try {
    const res = await apiPostJson('/alerts/create', { title, category, description, severity });
    const data = await res.json();
    if (data.success || data.status === 'success') {
      showToast("Public Warning Broadcasted successfully!");
      document.getElementById('new-alert-title').value = '';
      document.getElementById('new-alert-desc').value = '';
      loadAlerts();
    }
  } catch(e) {}
}

// 1-Click CERT-In, DoT & NPCI Legal Takedown Generator
async function generateCertInTakedown() {
  const targetDomain = document.getElementById('takedown-domain-input').value;
  const scamVpa = document.getElementById('takedown-vpa-input').value;
  const targetPhone = document.getElementById('takedown-phone-input').value;
  const threatCategory = document.getElementById('takedown-category-select').value;

  // A selected campaign supplies the full indicator set, so manual fields
  // are only required when no campaign is chosen.
  if (!selectedCampaignId && !targetDomain && !scamVpa && !targetPhone) {
    showToast("Enter a Domain, UPI VPA, or Phone/Telegram channel — or select a correlated campaign above.");
    return;
  }

  // Generates a legal notice citing IT Act s.70B — must be attributable.
  if (!(await ensureAdmin())) return;

  try {
    const res = await apiPostJson('/reports/cert-in-takedown', {
      targetDomain, scamVpa, targetPhone, threatCategory,
      campaignId: selectedCampaignId || undefined
    });
    const data = await res.json();

    if (data.success) {
      const correlated = data.correlatedIndicators;
      showToast(correlated
        ? `Notice dispatched naming ${correlated.total} correlated indicators from campaign #${correlated.campaignId}.`
        : "CERT-In, DoT & NPCI Takedown Directives Dispatched!");
      document.getElementById('takedown-notice-container').style.display = 'block';
      document.getElementById('takedown-notice-text').innerText = data.legalNoticeText;
      loadReports();
    }
  } catch(e) {
    showToast("Failed to dispatch legal takedown notice.");
  }
}

// 1-Click SEBI SCORES Regulatory Formal Complaint Generator
async function generateSebiScoresComplaint() {
  const targetDomain = document.getElementById('takedown-domain-input').value;
  const scamVpa = document.getElementById('takedown-vpa-input').value;
  const targetPhone = document.getElementById('takedown-phone-input').value;
  const threatCategory = document.getElementById('takedown-category-select').value;

  if (!selectedCampaignId && !targetDomain && !scamVpa && !targetPhone) {
    showToast("Enter a Domain, UPI VPA, or Phone/Telegram channel to generate SEBI SCORES Complaint.");
    return;
  }

  if (!(await ensureAdmin())) return;

  try {
    const timestamp = new Date().toISOString();
    const ref = `SEBI-SCORES-${Date.now().toString(36).toUpperCase()}`;
    const legalNoticeText = [
      '================================================================================',
      '               SEBI SCORES FORMAL COMPLAINT & REGULATORY NOTICE                ',
      `Ref No: ${ref}`,
      `Date: ${timestamp}`,
      'Regulation: SEBI (PFUTP) Regulations 2003 & Circular SEBI/HO/MIRSD/DOS3/CIR/P/2019/30',
      '================================================================================',
      '',
      '1. ENTITY & VIOLATION DETAILS',
      `   Alleged Impersonated Intermediary: Securities Market Intermediary / SEBI Official`,
      `   Fraudulent Web Domain: ${targetDomain || 'N/A'}`,
      `   Illegal Payment Rail / UPI VPA: ${scamVpa || 'N/A'}`,
      `   Scam Contact / Channel: ${targetPhone || 'N/A'}`,
      `   Violation Category: ${threatCategory || 'Unregistered Stock Advice & Impersonation Fraud'}`,
      '',
      '2. APPLICABLE STATUTORY CLAUSES',
      '   - SEBI (PFUTP) Regulation 3: Prohibition of Buying, Selling or Dealing in Securities in Fraudulent Manner',
      '   - SEBI (PFUTP) Regulation 4: Prohibition of Manipulative, Fraudulent and Deceptive Devices',
      '',
      '3. ENFORCEMENT DIRECTIVES REQUESTED',
      '   - Request NIXI / .IN Registry to revoke infringing domain name',
      '   - Request Financial Intelligence Unit (FIU-IND) for immediate bank account freeze',
      '   - Dispath formal warning to public on SEBI SCORES portal',
      '================================================================================',
    ].join('\n');

    document.getElementById('takedown-notice-container').style.display = 'block';
    document.getElementById('takedown-notice-text').innerText = legalNoticeText;
    showToast("SEBI SCORES Formal Legal Complaint Notice generated successfully!");
  } catch(e) {
    showToast("Failed to generate SEBI SCORES complaint.");
  }
}

// SEBI admin reads Incident & Takedown logs
async function loadReports() {
  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/reports/list`);
    const data = await res.json();
    const list = data.reports || data.takedowns || (Array.isArray(data) ? data : []);
    
    const tbody = document.getElementById('sebi-reports-body');
    if (!list || list.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">No high-risk takedown notices reported.</td></tr>';
    } else {
      tbody.innerHTML = list.map(r => {
        const id = r.id || 'N/A';
        const domain = escapeHtml(r.targetDomain || 'N/A');
        const vpa = escapeHtml(r.scamVpa || 'N/A');
        const category = escapeHtml(r.threatCategory || 'Impersonation Fraud');
        const dateStr = r.date || new Date().toISOString().split('T')[0];
        const statusStr = r.status || 'DISPATCHED_TO_DOT_NPCI';
        
        let actionBtns = `
          <select style="margin-bottom:0; font-size:10px; width:auto; padding:4px;" onchange="changeReportStatus('${id}', this.value)">
            <option value="DISPATCHED_TO_DOT_NPCI" ${statusStr==='DISPATCHED_TO_DOT_NPCI'?'selected':''}>Dispatched</option>
            <option value="BLOCKED_BY_DOT" ${statusStr==='BLOCKED_BY_DOT'?'selected':''}>DoT Blocked</option>
            <option value="FROZEN_BY_NPCI" ${statusStr==='FROZEN_BY_NPCI'?'selected':''}>NPCI Frozen</option>
            <option value="COMPLETED" ${statusStr==='COMPLETED'?'selected':''}>Resolved</option>
          </select>
        `;
        
        return `<tr>
          <td><b>#${id.slice(0, 14)}</b></td>
          <td><code>${domain}</code></td>
          <td><code>${vpa}</code></td>
          <td><span class="code-chip" style="font-size:10px; color:var(--text-primary);">${category}</span></td>
          <td>${dateStr}</td>
          <td><span class="code-chip" style="color:var(--gold-light); font-size:9.5px;">${statusStr}</span></td>
          <td>${actionBtns}</td>
        </tr>`;
      }).join('');
    }
  } catch(e) {}
}

// ─────────────── Phase 2: Correlated Campaign Intelligence ───────────────

let selectedCampaignId = null;

async function loadDashboard() {
  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/dashboard/stats`);
    const stats = await res.json();
    
    const scansEl = document.getElementById('stat-scans');
    const phishingEl = document.getElementById('stat-phishing');
    const pkiEl = document.getElementById('stat-pki');
    const alertsEl = document.getElementById('stat-alerts');

    if (scansEl) scansEl.innerText = stats.totalScans || 65;
    if (phishingEl) phishingEl.innerText = stats.phishingBlocked || 6;
    if (pkiEl) pkiEl.innerText = stats.verifiedCommunications || 2;
    if (alertsEl) alertsEl.innerText = stats.activeAlerts || 2;
  } catch (e) {
    console.warn('[dashboard] Failed to fetch stats, using default values', e);
  }

  loadCampaigns();
}

async function loadCampaigns() {
  const container = document.getElementById('campaign-list-container') || document.getElementById('campaign-list');
  if (!container) return;

  try {
    const [campRes, statsRes] = await Promise.all([
      fetch(`${CONFIG.apiEndpoint}/graph/campaigns`),
      fetch(`${CONFIG.apiEndpoint}/graph/stats`)
    ]);
    const campaigns = (await campRes.json()).campaigns || [];
    const stats = await statsRes.json();

    const statLine = `<div style="font-size:12px; color:var(--text-muted); font-family:var(--font-mono); margin-bottom:14px; display:flex; gap:16px;">
      <span>📌 <b>${stats.iocCount || 7}</b> Indicators</span>
      <span>🔗 <b>${stats.linkCount || 6}</b> Correlation Edges</span>
      <span>🕸️ <b>${stats.campaignCount || campaigns.length}</b> Correlated Campaigns</span>
    </div>`;

    if (campaigns.length === 0) {
      container.innerHTML = statLine + `<p style="color:var(--text-muted); font-size:12.5px;">
        No correlated campaigns yet. Scan two or more artifacts that share a domain, UPI handle, or phone number to build correlations.
      </p>`;
      return;
    }

    container.innerHTML = statLine + campaigns.map(c => {
      const riskClass = c.max_risk_score >= 70 ? 'badge-danger' : (c.max_risk_score >= 30 ? 'badge-suspicious' : 'badge-safe');
      const isSelected = String(selectedCampaignId) === String(c.id);
      return `
        <div class="glass-panel" style="padding:16px; border-color:${isSelected ? 'var(--neon-amber)' : 'var(--border-glass)'};">
          <div style="display:flex; justify-content:space-between; align-items:center; gap:12px;">
            <div style="min-width:0;">
              <div style="display:flex; align-items:center; gap:10px; margin-bottom:4px;">
                <b style="font-size:14px; color:#fff; word-break:break-all;">${escapeHtml(c.label)}</b>
                <span class="badge-tag ${riskClass}">${c.max_risk_score}% RISK</span>
              </div>
              <div style="font-size:11.5px; color:var(--text-muted); font-family:var(--font-mono);">
                ID: #${c.id} · ${c.member_count} Indicators · Cluster: <span style="color:var(--neon-cyan);">${escapeHtml(c.cluster_method)}</span>
              </div>
            </div>
            <div style="display:flex; gap:8px; flex-shrink:0;">
              <button class="btn-secondary" style="padding:6px 12px; font-size:11.5px;" onclick="viewCampaign(${c.id})">Inspect</button>
              <button class="btn-secondary" style="padding:6px 12px; font-size:11.5px;" onclick="selectCampaignForTakedown(${c.id}, '${escapeHtml(c.label).replace(/'/g, "\\'")}')">Use for Notice</button>
            </div>
          </div>
          <div id="campaign-detail-${c.id}" style="display:none; margin-top:12px; border-top:1px solid var(--border-glass); padding-top:12px;"></div>
        </div>
      `;
    }).join('');
  } catch (e) {
    container.innerHTML = '<p style="color:var(--text-muted); font-size:12px;">Could not load campaign correlations.</p>';
  }
}

async function viewCampaign(id) {
  const box = document.getElementById(`campaign-detail-${id}`);
  if (!box) return;

  if (box.style.display === 'block') { box.style.display = 'none'; return; }

  box.style.display = 'block';
  box.innerHTML = '<p class="text-secondary" style="font-size:11px;">Loading indicators...</p>';

  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/graph/campaigns/${id}`);
    const data = await res.json();

    // Group indicators by type so the operator sees payment rails separately
    // from infrastructure — they go to different agencies.
    const grouped = {};
    (data.members || []).forEach(m => {
      (grouped[m.type] = grouped[m.type] || []).push(m);
    });

    const memberHtml = Object.entries(grouped).map(([type, items]) => `
      <div style="margin-bottom:8px;">
        <span style="font-size:10px; color:var(--text-secondary); text-transform:uppercase; letter-spacing:0.5px;">${escapeHtml(type)}</span>
        <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;">
          ${items.map(m => `<span class="code-chip" style="font-size:10px;">${escapeHtml(m.value)} <span style="color:var(--text-secondary);">×${m.sighting_count}</span></span>`).join('')}
        </div>
      </div>
    `).join('');

    const scanHtml = (data.scans || []).length
      ? `<div style="margin-top:8px; font-size:11px; color:var(--text-secondary); font-family:var(--font-mono);">
           Evidenced by ${data.scans.length} scan(s): ${data.scans.slice(0, 8).map(s => `#${s.id}`).join(', ')}${data.scans.length > 8 ? '…' : ''}
         </div>`
      : '';

    box.innerHTML = memberHtml + scanHtml;
  } catch (e) {
    box.innerHTML = '<p class="text-secondary" style="font-size:11px;">Failed to load campaign detail.</p>';
  }
}

function selectCampaignForTakedown(id, label) {
  selectedCampaignId = id;
  const banner = document.getElementById('selected-campaign-banner');
  const text = document.getElementById('selected-campaign-text');
  if (banner && text) {
    text.innerHTML = `Notice will name <b>all indicators</b> in campaign #${id}: ${escapeHtml(label)}`;
    banner.style.display = 'block';
  }
  showToast(`Campaign #${id} selected. The notice will enumerate every correlated indicator.`);
  loadCampaigns();
}

function clearSelectedCampaign() {
  selectedCampaignId = null;
  const banner = document.getElementById('selected-campaign-banner');
  if (banner) banner.style.display = 'none';
  loadCampaigns();
}

async function changeReportStatus(reportId, newStatus) {
  if (!(await ensureAdmin())) return;

  try {
    await apiPostJson('/reports/status', { id: reportId, status: newStatus });
    showToast("Incident status updated.");
    loadReports();
  } catch(e) {}
}

// Load Ingested Social Feed
async function loadSocialFeed() {
  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/social/feed`);
    const data = await res.json();
    const posts = data.posts || (Array.isArray(data) ? data : []);
    renderSocialFeed(posts);
  } catch(e) {}
}

function renderSocialFeed(posts) {
  const container = document.getElementById('social-feed-container');
  if (!posts || posts.length === 0) {
    container.innerHTML = '<p class="text-secondary" style="text-align:center; font-size:12px;">No social monitoring logs recorded.</p>';
    return;
  }

  container.innerHTML = posts.map(p => {
    const ts = p.flagged_at || p.created_at || '';
    const timeStr = ts ? new Date(ts).toLocaleString([], {month: 'short', day: 'numeric', hour: '2-digit', minute:'2-digit'}) : '';
    const riskClass = p.risk_score >= 70 ? 'crit' : (p.risk_score >= 30 ? 'warn' : 'info');
    const scoreColor = p.risk_score >= 70 ? 'var(--high)' : (p.risk_score >= 30 ? 'var(--medium)' : 'var(--low)');
    const platform = p.platform || 'Unknown';
    const author = p.author || p.sender || 'Unknown';
    const content = p.content || p.text_or_filename || '';

    return `
      <div style="background:rgba(30,41,59,0.3); border:1px solid var(--border-color); border-radius:8px; padding:16px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
          <div style="display:flex; align-items:center; gap:8px;">
            <div class="avatar" style="width:24px; height:24px; font-size:10px; background:var(--border-color); color:var(--text-primary);">${platform.charAt(0).toUpperCase()}</div>
            <div>
              <b style="font-size:13px;">${escapeHtml(author)}</b>
              <span style="font-size:10px; color:var(--text-secondary); margin-left:6px;">${escapeHtml(platform)} · ${timeStr}</span>
            </div>
          </div>
          <div style="text-align:right;">
            <span class="code-chip" style="color:${scoreColor}; border-color:${scoreColor}; font-size:10px;">Risk: ${p.risk_score}</span>
          </div>
        </div>
        <p style="font-size:13px; line-height:1.5; color:var(--text-primary); font-family:var(--font-mono);">${escapeHtml(content)}</p>
      </div>
    `;
  }).join('');
}

// Ingest new social media posts
async function simulateSocialIngest() {
  if (!(await ensureAdmin())) return;

  showToast("Scraping channels & evaluating post payloads...");
  try {
    const res = await apiFetch('/social/ingest', { method: 'POST' });
    const data = await res.json();
    const post = data.post || {};
    showToast(`Ingested post from ${post.author || 'unknown channel'} on ${post.platform || 'platform'}.`);
    loadSocialFeed();
  } catch(e) {
    if (e.message !== 'UNAUTHENTICATED' && e.message !== 'FORBIDDEN') showToast("Ingestion failed.");
  }
}

// Diagnostics database wipe
async function triggerDatabaseReset() {
  if(!confirm("Wipe SQLite database and seed default communications and alerts?")) return;
  if (!(await ensureAdmin())) return;

  try {
    await apiFetch('/system/reset', { method: 'POST' });
    showToast("SQLite database reset complete!");
    loadRegistry();
    loadDashboard();
    if(CONFIG.currentTab === 'social') loadSocialFeed();
  } catch(e) {}
}
