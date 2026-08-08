// SentinelSEBI — Phishing & Media Scan Module
// Text scan, EML upload, image/audio/video forensics, result rendering

// Text Phishing Scan
async function runTextScan() {
  const text = document.getElementById('scan-text-input').value;
  const sender = document.getElementById('scan-text-sender').value;
  const channel = document.getElementById('scan-text-channel').value;
  
  if(!text.trim()) { showToast("Please input text to scan."); return; }

  const resBox = document.getElementById('scan-result-box');
  const scoreVal = document.getElementById('result-score');
  const labelEl = document.getElementById('result-label-desc');
  const verdEl = document.getElementById('result-verdict');
  const headerBar = document.getElementById('verdict-header-bar');
  const logBox = document.getElementById('evidence-log-container');
  const previewBox = document.getElementById('media-forensics-views');
  
  logBox.innerHTML = '<p class="text-secondary" style="font-size:12px;">Running heuristics scan...</p>';
  previewBox.innerHTML = '';
  resBox.style.display = 'block';

  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/phishing/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, sender, channel })
    });
    const data = await res.json();
    
    scoreVal.innerText = data.risk_score;
    labelEl.innerText = "Phishing Risk / 100";
    verdEl.innerText = `${data.verdict} RISK`;
    
    headerBar.className = `verdict-header verd-${data.verdict.toLowerCase()}`;
    resBox.className = `result-box ${data.risk_score >= 70 ? 'glow-high' : data.risk_score >= 30 ? 'glow-medium' : ''}`;

    // Render Risk Fusion & ML Model Breakdown if available
    const fusionWidget = document.getElementById('risk-fusion-widget');
    if (data.risk_fusion && fusionWidget) {
      fusionWidget.style.display = 'block';
      document.getElementById('fusion-rule-score').innerText = `${data.risk_fusion.rule_score}/100`;
      document.getElementById('fusion-ml-score').innerText = `${data.risk_fusion.ml_score}%`;
      document.getElementById('fusion-calibrated-score').innerText = `${data.risk_fusion.calibrated_score}/100`;
      const tierEl = document.getElementById('fusion-risk-tier');
      tierEl.innerText = data.risk_fusion.risk_tier || data.verdict;
    }
    
    if(data.flags.length === 0) {
      logBox.innerHTML = '<div class="flag-item">No malicious signatures detected in this text.</div>';
    } else {
      logBox.innerHTML = data.flags.map(f => {
        let detailStr = '';
        if (Array.isArray(f.detail)) {
          detailStr = '<ul>' + f.detail.map(d => `<li>• ${escapeHtml(d.reason)} (URL: <code>${escapeHtml(d.url)}</code>)</li>`).join('') + '</ul>';
        } else {
          detailStr = escapeHtml(f.detail);
        }
        const tagClass = getIocTagClass(f.type);
        return `<div class="flag-item">
          <span class="${tagClass}">${escapeHtml(f.type.replace(/_/g, ' '))} · ${escapeHtml(f.severity)}</span>
          <p>${detailStr}</p>
        </div>`;
      }).join('');
    }

  } catch (e) {
    logBox.innerHTML = `<p style="color:var(--high);">Error connecting to scanner API.</p>`;
  }
}

function getIocTagClass(type) {
  if (!type) return 'flag-tag';
  const t = type.toLowerCase();
  if (t.includes('pan')) return 'flag-tag tag-pan';
  if (t.includes('demat')) return 'flag-tag tag-demat';
  if (t.includes('upi') || t.includes('qr')) return 'flag-tag tag-upi';
  if (t.includes('broker')) return 'flag-tag tag-broker';
  if (t.includes('social') || t.includes('telegram') || t.includes('whatsapp')) return 'flag-tag tag-social';
  return 'flag-tag';
}

// EML Scan
async function runEmlScan() {
  const fileEl = document.getElementById('eml-file-input');
  const file = fileEl.files[0];
  if(!file) return;

  setupForensicsLoading();

  const fd = new FormData();
  fd.append('file', file);

  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/phishing/upload-eml`, {
      method: 'POST',
      body: fd
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showMediaError(data.detail || data.message || data.error || `Server returned error status ${res.status}`);
      return;
    }
    
    const scoreVal = document.getElementById('result-score');
    const labelEl = document.getElementById('result-label-desc');
    const verdEl = document.getElementById('result-verdict');
    const headerBar = document.getElementById('verdict-header-bar');
    const logBox = document.getElementById('evidence-log-container');
    const previewBox = document.getElementById('media-forensics-views');
    
    const analysis = data.analysis || {};
    scoreVal.innerText = typeof analysis.risk_score !== 'undefined' ? analysis.risk_score : 0;
    labelEl.innerText = "EML Email Phishing Risk / 100";
    verdEl.innerText = `${analysis.verdict ? analysis.verdict.replace(/_/g, ' ') : 'SAFE'} RISK`;
    headerBar.className = `verdict-header verd-${(analysis.verdict || 'safe').toLowerCase()}`;

    logBox.innerHTML = `
      <div class="flag-item" style="border-left: 3px solid var(--gold-light);">
        <span class="flag-tag">EML MIME HEADERS</span>
        <p>From: <b>${escapeHtml(data.parsedHeaders?.from || 'Unknown')}</b> | Subject: <b>${escapeHtml(data.parsedHeaders?.subject || 'None')}</b><br>
        DKIM Signature: <b>${data.parsedHeaders?.dkimSignaturePresent ? '✅ Present' : '❌ Missing'}</b></p>
      </div>
    ` + (analysis.flags || []).map(f => `
      <div class="flag-item">
        <span class="flag-tag">${escapeHtml(f.type.replace(/_/g, ' '))} · ${escapeHtml(f.severity)}</span>
        <p>${escapeHtml(f.detail)}</p>
      </div>
    `).join('');

    previewBox.innerHTML = '';
    document.getElementById('scan-result-box').style.display = 'block';
  } catch (e) {
    showMediaError(e.message);
  }
}

// Image Scan
async function runImageScan() {
  const fileEl = document.getElementById('image-file-input');
  const file = fileEl.files[0];
  if(!file) return;

  setupForensicsLoading();
  
  const fd = new FormData();
  fd.append('file', file);

  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/media/analyze-image`, {
      method: 'POST',
      body: fd
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showMediaError(data.detail || data.message || data.error || `Server returned error status ${res.status}`);
      return;
    }
    renderMediaResults(data, 'image', file);
  } catch (e) {
    showMediaError(e.message);
  }
}

// Audio Scan
async function runAudioScan() {
  const fileEl = document.getElementById('audio-file-input');
  const file = fileEl.files[0];
  if(!file) return;

  setupForensicsLoading();
  
  const fd = new FormData();
  fd.append('file', file);

  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/media/analyze-audio`, {
      method: 'POST',
      body: fd
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showMediaError(data.detail || data.message || data.error || `Server returned error status ${res.status}`);
      return;
    }
    renderMediaResults(data, 'audio', file);
  } catch (e) {
    showMediaError(e.message);
  }
}

// Video Scan
async function runVideoScan() {
  const fileEl = document.getElementById('video-file-input');
  const file = fileEl.files[0];
  if(!file) return;

  setupForensicsLoading();
  
  const fd = new FormData();
  fd.append('file', file);

  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/media/analyze-video`, {
      method: 'POST',
      body: fd
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showMediaError(data.detail || data.message || data.error || `Server returned error status ${res.status}`);
      return;
    }
    renderMediaResults(data, 'video', file);
  } catch (e) {
    showMediaError(e.message);
  }
}

// Forensic loading setup
function setupForensicsLoading() {
  const resBox = document.getElementById('scan-result-box');
  const logBox = document.getElementById('evidence-log-container');
  const previewBox = document.getElementById('media-forensics-views');
  logBox.innerHTML = '<p class="text-secondary" style="font-size:12px;">Running deep neural / metadata forensic checks...</p>';
  previewBox.innerHTML = '';
  resBox.style.display = 'block';
}

function showMediaError(msg) {
  const scoreVal = document.getElementById('result-score');
  const verdEl = document.getElementById('result-verdict');
  const headerBar = document.getElementById('verdict-header-bar');
  const logBox = document.getElementById('evidence-log-container');

  if (scoreVal) scoreVal.innerText = '—';
  if (verdEl) verdEl.innerText = 'ANALYSIS ERROR';
  if (headerBar) headerBar.className = 'verdict-header verd-high';

  const detailText = msg ? `: ${escapeHtml(msg)}` : '';
  if (logBox) {
    logBox.innerHTML = `
      <div class="flag-item" style="border-left: 3px solid var(--high);">
        <span class="flag-tag">FORENSICS ANALYSIS ERROR</span>
        <p>Error uploading or analyzing file${detailText}</p>
      </div>
    `;
  }
}

// Render forensic outcomes
function renderMediaResults(data, type, file) {
  if (!data || typeof data.risk_score === 'undefined' || !data.verdict) {
    showMediaError(data?.detail || data?.error || 'Invalid or empty analysis outcome from server.');
    return;
  }
  const scoreVal = document.getElementById('result-score');
  const labelEl = document.getElementById('result-label-desc');
  const verdEl = document.getElementById('result-verdict');
  const headerBar = document.getElementById('verdict-header-bar');
  const logBox = document.getElementById('evidence-log-container');
  const previewBox = document.getElementById('media-forensics-views');

  scoreVal.innerText = data.risk_score;
  labelEl.innerText = `${type.toUpperCase()} Manipulation Risk`;
  verdEl.innerText = `${data.verdict.replace(/_/g,' ')} RISK`;
  
  headerBar.className = `verdict-header verd-${data.verdict.toLowerCase()}`;

  if(!data.evidence || data.evidence.length === 0) {
    logBox.innerHTML = '<div class="flag-item">Metadata checks indicate correct camera structures. No edits flagged.</div>';
  } else {
    logBox.innerHTML = data.evidence.map(e => `
      <div class="flag-item">
        <span class="flag-tag">${type.toUpperCase()} FORENSICS SIGNAL</span>
        <p>${escapeHtml(e)}</p>
      </div>
    `).join('');
  }

  // Media views
  if (type === 'image') {
    previewBox.innerHTML = `
      <div class="preview-grid">
        <figure>
          <img src="${URL.createObjectURL(file)}">
          <figcaption>Original circular upload</figcaption>
        </figure>
        <figure>
          <img src="${CONFIG.apiEndpoint}${data.preview_url}?t=${Date.now()}">
          <figcaption>Error Level Analysis (ELA) map (neural edits highlight bright)</figcaption>
        </figure>
      </div>
    `;
  } else if (type === 'audio') {
    const rolloff = Number(data.metrics?.spectral_rolloff_hz ?? 0);
    const flatness = Number(data.metrics?.spectral_flatness ?? 0);
    const silence = Number(data.metrics?.silence_ratio ?? 0);
    const voiceprintBadge = data.voiceprintStored
      ? '<span style="color:var(--low); font-size:11px; font-weight:600;">✅ Voiceprint Biometric Vector Stored</span>'
      : '<span style="color:var(--text-muted); font-size:11px;">Acoustic Signal Extracted</span>';

    previewBox.innerHTML = `
      <div style="background: rgba(30, 41, 59, 0.3); border: 1px solid var(--border-color); padding: 16px; border-radius: 8px; margin-top: 16px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
          <h4 style="font-size:13px; font-family:var(--font-mono); color:var(--gold-light); margin:0;">Acoustic FFT DSP & Voiceprint Parameters</h4>
          ${voiceprintBadge}
        </div>
        <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap: 12px; font-family:var(--font-mono); text-align:center;">
          <div style="background:rgba(15,23,42,0.6); padding:10px; border-radius:6px; border:1px solid var(--border-color);">
            <span style="font-size:10px; color:var(--text-secondary); display:block; margin-bottom:4px;">Sample Bandwidth</span>
            <b style="font-size:15px; color:var(--text-primary);">${rolloff.toFixed(0)} Hz</b>
          </div>
          <div style="background:rgba(15,23,42,0.6); padding:10px; border-radius:6px; border:1px solid var(--border-color);">
            <span style="font-size:10px; color:var(--text-secondary); display:block; margin-bottom:4px;">Spectral Flatness (Wiener)</span>
            <b style="font-size:15px; color:var(--text-primary);">${flatness.toFixed(3)}</b>
          </div>
          <div style="background:rgba(15,23,42,0.6); padding:10px; border-radius:6px; border:1px solid var(--border-color);">
            <span style="font-size:10px; color:var(--text-secondary); display:block; margin-bottom:4px;">Gate Silence Ratio</span>
            <b style="font-size:15px; color:var(--text-primary);">${(silence * 100).toFixed(1)}%</b>
          </div>
        </div>
        <div style="margin-top:12px; font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">
          <b>Model Engine:</b> ${escapeHtml(data.model || 'Hybrid Audio Forensics Engine')}
        </div>
      </div>
    `;
  } else if (type === 'video') {
    const frames = data.metrics?.frames_analyzed ?? 0;
    const sharpness = Number(data.metrics?.sharpness_ratio ?? 1.0);
    const correlation = Number(data.metrics?.avg_temporal_correlation ?? 1.0);
    previewBox.innerHTML = `
      <div style="background: rgba(30, 41, 59, 0.2); border: 1px solid var(--border-color); padding: 16px; border-radius: 6px; margin-top: 16px;">
        <h4 style="font-size:12px; margin-bottom:10px; font-family:var(--font-mono); color:var(--gold-light);">Visual Temporal Consistency</h4>
        <div style="display:grid; grid-template-columns: repeat(3, 1fr); gap: 12px; font-family:var(--font-mono); text-align:center;">
          <div><span style="font-size:10px; color:var(--text-secondary); display:block;">Frames Inspected</span><b style="font-size:14px;">${frames}</b></div>
          <div><span style="font-size:10px; color:var(--text-secondary); display:block;">Blur Contrast Ratio</span><b style="font-size:14px;">${sharpness.toFixed(2)}</b></div>
          <div><span style="font-size:10px; color:var(--text-secondary); display:block;">Temporal Sync Coefficient</span><b style="font-size:14px;">${correlation.toFixed(2)}</b></div>
        </div>
      </div>
    `;
  }
}
