document.addEventListener('DOMContentLoaded', async () => {
  const checkBtn = document.getElementById('check');
  const codeInput = document.getElementById('code');
  const resultBox = document.getElementById('result');
  const statusBadge = document.getElementById('statusBadge');
  const statusText = document.getElementById('statusText');
  const statScans = document.getElementById('statScans');

  const API_BASE = 'http://127.0.0.1:8000';

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

  checkBackendHealth();

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
      if (res.ok && data.status === 'VERIFIED') {
        resultBox.style.color = 'var(--success)';
        resultBox.innerHTML = `
          <div style="font-weight:700; color:var(--success); margin-bottom:4px;">✅ VERIFIED AUTHENTIC COMMUNICATION</div>
          <div><b>Issuer:</b> ${escapeHtml(data.issuer || data.issuerName || 'Registered SEBI Intermediary')}</div>
          <div><b>Status:</b> RSA-2048 PKI Signature Valid</div>
          <div><b>Registered:</b> ${escapeHtml(data.created_at || 'Authentic Record')}</div>
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
