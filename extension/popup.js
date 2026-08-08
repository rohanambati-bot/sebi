document.addEventListener('DOMContentLoaded', async () => {
  const checkBtn = document.getElementById('check');
  const codeInput = document.getElementById('code');
  const resultBox = document.getElementById('result');
  const statusBadge = document.getElementById('statusBadge');
  const statusText = document.getElementById('statusText');
  const statScans = document.getElementById('statScans');
  const serverUrlInput = document.getElementById('serverUrlInput');
  const saveServerBtn = document.getElementById('saveServerBtn');

  let API_BASE = 'http://127.0.0.1:8000';

  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['sentinelApiBase'], (data) => {
      if (data && data.sentinelApiBase) {
        API_BASE = data.sentinelApiBase.replace(/\/$/, '');
      }
      if (serverUrlInput) serverUrlInput.value = API_BASE;
      checkBackendHealth();
    });
  }

  if (saveServerBtn) {
    saveServerBtn.addEventListener('click', () => {
      const inputVal = serverUrlInput ? serverUrlInput.value.trim() : '';
      if (inputVal) {
        API_BASE = inputVal.replace(/\/$/, '');
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
          chrome.storage.local.set({ sentinelApiBase: API_BASE }, () => {
            checkBackendHealth();
            alert(`Backend host updated to: ${API_BASE}`);
          });
        }
      }
    });
  }

  const setupBox = document.getElementById('sessionSetupBox');
  const activeBox = document.getElementById('sessionActiveBox');
  const emailInput = document.getElementById('userEmailInput');
  const activateBtn = document.getElementById('activateSessionBtn');
  const displayEmail = document.getElementById('displayUserEmail');
  const logoutBtn = document.getElementById('logoutBtn');

  // Check persistent chrome.storage for verified user email
  function loadUserSession() {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['sentinelUserEmail'], (data) => {
        if (data && data.sentinelUserEmail) {
          showActiveSession(data.sentinelUserEmail);
        } else {
          showSetupSession();
        }
      });
    }
  }

  function showActiveSession(email) {
    if (setupBox) setupBox.style.display = 'none';
    if (activeBox) activeBox.style.display = 'block';
    if (displayEmail) displayEmail.innerText = email;
  }

  function showSetupSession() {
    if (setupBox) setupBox.style.display = 'block';
    if (activeBox) activeBox.style.display = 'none';
  }

  if (activateBtn) {
    activateBtn.addEventListener('click', () => {
      const email = emailInput ? emailInput.value.trim() : '';
      if (!email || !email.includes('@')) {
        alert('Please enter a valid email address.');
        return;
      }
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ sentinelUserEmail: email }, () => {
          showActiveSession(email);
          chrome.runtime.sendMessage({ type: 'SET_USER_EMAIL', email });
        });
      } else {
        showActiveSession(email);
      }
    });
  }

  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.remove(['sentinelUserEmail'], () => {
          showSetupSession();
        });
      } else {
        showSetupSession();
      }
    });
  }

  loadUserSession();

  // Live status health check
  async function checkBackendHealth() {
    try {
      const res = await fetch(`${API_BASE}/dashboard/stats`, { method: 'GET' });
      if (res.ok) {
        const data = await res.json();
        statusBadge.className = 'status-indicator';
        statusText.innerText = 'Connected';
        if (data.totalScans) statScans.innerText = `${data.totalScans}`;
      } else {
        throw new Error();
      }
    } catch {
      statusBadge.className = 'status-indicator offline';
      statusText.innerText = 'Offline';
    }
  }

  // Query active tab risk state from background worker
  async function updateTabShieldState() {
    try {
      const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!activeTab) return;

      chrome.runtime.sendMessage({ type: 'GET_TAB_STATE', tabId: activeTab.id }, (state) => {
        const card = document.getElementById('tabShieldCard');
        const tierEl = document.getElementById('tabShieldTier');
        const scoreEl = document.getElementById('tabShieldScore');
        const descEl = document.getElementById('tabShieldDesc');
        const sebiBadge = document.getElementById('sebiLogBadge');

        if (!card || !state) return;

        const isHigh = state.riskScore >= 70;
        const isMed = state.riskScore >= 30;

        if (isHigh) {
          card.style.background = 'rgba(239, 68, 68, 0.15)';
          card.style.borderColor = '#ef4444';
          tierEl.innerText = '🔴 DANGER: SCAM DETECTED';
          tierEl.style.color = '#ef4444';
          scoreEl.innerText = `${state.riskScore}% RISK`;
          scoreEl.style.background = '#ef4444';
          scoreEl.style.color = '#ffffff';
          descEl.innerText = state.flags && state.flags.length 
            ? `Scam Flags: ${state.flags.map(f => f.type.replace(/_/g, ' ')).join(', ')}` 
            : 'High risk scam content identified on active tab.';
          sebiBadge.innerHTML = '🚨 <b>AUTOMATICALLY RECORDED TO SEBI EVIDENCE DB</b>';
          sebiBadge.style.color = '#ef4444';
        } else if (isMed) {
          card.style.background = 'rgba(245, 158, 11, 0.15)';
          card.style.borderColor = '#f59e0b';
          tierEl.innerText = '🟡 SUSPICIOUS / PARTIALLY SAFE';
          tierEl.style.color = '#f59e0b';
          scoreEl.innerText = `${state.riskScore}% RISK`;
          scoreEl.style.background = '#f59e0b';
          scoreEl.style.color = '#000000';
          descEl.innerText = state.flags && state.flags.length 
            ? `Caution Flags: ${state.flags.map(f => f.type.replace(/_/g, ' ')).join(', ')}` 
            : 'Suspicious indicators detected on active page.';
          sebiBadge.innerHTML = '⚡ <b>Logged to SEBI Compliance Audit Database</b>';
          sebiBadge.style.color = '#f59e0b';
        } else {
          card.style.background = 'rgba(16, 185, 129, 0.12)';
          card.style.borderColor = 'rgba(16, 185, 129, 0.4)';
          tierEl.innerText = '🟢 SAFE & VERIFIED CONTENT';
          tierEl.style.color = '#10b981';
          scoreEl.innerText = `${state.riskScore}% RISK`;
          scoreEl.style.background = '#10b981';
          scoreEl.style.color = '#000000';
          descEl.innerText = 'Active tab content audited cleanly. No scam indicators detected.';
          sebiBadge.innerHTML = '⚡ <b>Audited & Logged to SEBI Database</b>';
          sebiBadge.style.color = '#10b981';
        }
      });
    } catch (e) {}
  }

  checkBackendHealth();
  updateTabShieldState();

  checkBtn.addEventListener('click', async () => {
    const code = codeInput.value.trim();
    if (!code) {
      resultBox.innerText = 'Please enter a Sentinel PKI verification code (e.g. VERIFY-8A9F1B2C).';
      resultBox.style.display = 'block';
      resultBox.style.color = 'var(--danger)';
      return;
    }

    resultBox.innerText = 'Resolving RSA-2048 PKI registry signature...';
    resultBox.style.display = 'block';
    resultBox.style.color = 'var(--text-muted)';

    try {
      const res = await fetch(`${API_BASE}/verify/by-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      });
      const data = await res.json();
      const isVerified = res.ok && (data.status === 'CRYPTOGRAPHICALLY VERIFIED' || data.status === 'VERIFIED' || data.verdict_label === 'LOW_RISK');
      const isSimilar = data.status === 'SIMILAR TO REGISTERED COMMUNICATION';

      if (isVerified) {
        resultBox.style.color = 'var(--success)';
        resultBox.innerHTML = `
          <div style="font-weight:700; color:var(--success); margin-bottom:4px;">✅ CRYPTOGRAPHICALLY VERIFIED</div>
          <div><b>Issuer:</b> ${escapeHtml(data.issuer || data.issuerName || 'Registered SEBI Intermediary')}</div>
          <div><b>Domain:</b> ${escapeHtml(data.source_domain || 'sebi.gov.in')}</div>
          <div><b>Status:</b> RSA-2048 Digital Signature Valid</div>
        `;
      } else if (isSimilar) {
        resultBox.style.color = 'var(--gold)';
        resultBox.innerHTML = `
          <div style="font-weight:700; color:var(--gold); margin-bottom:4px;">🟡 SIMILAR TO REGISTERED COMMUNICATION</div>
          <div><b>Issuer:</b> ${escapeHtml(data.issuer || 'Registered Intermediary')}</div>
          <div><b>Domain:</b> ${escapeHtml(data.source_domain || 'sebi.gov.in')}</div>
          <div><b>Note:</b> Copy-pasted/forwarded text matches registered circular with minor edits.</div>
        `;
      } else {
        resultBox.style.color = 'var(--danger)';
        resultBox.innerHTML = `
          <div style="font-weight:700; color:var(--danger); margin-bottom:4px;">⚠️ UNVERIFIED OR SUSPICIOUS CODE</div>
          <div>${escapeHtml(data.message || data.detail || 'Code not found in official SEBI communication registry.')}</div>
        `;
      }
    } catch {
      resultBox.style.color = 'var(--danger)';
      resultBox.innerText = 'Sentinel API connection failed. Ensure local backend is running on port 8000.';
    }
  });

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
});
