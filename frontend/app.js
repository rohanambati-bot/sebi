// SentinelSEBI — Core Application Module
// Config, session management, auth, navigation, role toggle, toast, initialization

// HTML escaping utility for XSS protection
function escapeHtml(text) {
  if (typeof text !== 'string') return text;
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// App Config
const CONFIG = {
  apiEndpoint: 'http://127.0.0.1:8000',
  currentTab: 'dashboard',
  currentRole: 'investor',
  username: 'investor'
};

// ─────────────────── Session & Authenticated Requests ───────────────────
//
// Privileged endpoints (regulatory reports, alert publishing, PKI registry,
// audit trail) now require an admin bearer token. Scan and verify endpoints
// stay open so investors can use the tooling without an account.

const SESSION_KEY = 'sentinel_session';

const Session = {
  get() {
    try { return JSON.parse(sessionStorage.getItem(SESSION_KEY)) || null; }
    catch { return null; }
  },
  set(session) { sessionStorage.setItem(SESSION_KEY, JSON.stringify(session)); },
  clear() { sessionStorage.removeItem(SESSION_KEY); },
  get token() { return this.get()?.access_token || null; },
  get role() { return this.get()?.role || 'anonymous'; },
  isAdmin() { return this.role === 'admin'; }
};

/**
 * fetch wrapper that attaches the bearer token and surfaces auth failures
 * as readable toasts rather than silent empty renders.
 */
async function apiFetch(endpoint, options = {}) {
  const headers = { ...(options.headers || {}) };
  const token = Session.token;
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${CONFIG.apiEndpoint}${endpoint}`, { ...options, headers });

  if (res.status === 401) {
    Session.clear();
    updateAuthUI();
    showToast('Session expired or not signed in. Sign in as a SEBI administrator to continue.');
    throw new Error('UNAUTHENTICATED');
  }
  if (res.status === 403) {
    showToast('This action requires SEBI administrator privileges.');
    throw new Error('FORBIDDEN');
  }
  return res;
}

/** JSON POST helper for privileged actions. */
function apiPostJson(endpoint, body) {
  return apiFetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
}

async function signIn(username, password) {
  const res = await fetch(`${CONFIG.apiEndpoint}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });

  if (!res.ok) {
    showToast('Sign-in failed. Check your credentials.');
    return false;
  }

  const session = await res.json();
  Session.set(session);
  CONFIG.currentRole = session.role;
  CONFIG.username = session.username;
  updateAuthUI();
  showToast(`Signed in as ${session.username} (${session.role}).`);
  return true;
}

function signOut() {
  Session.clear();
  CONFIG.currentRole = 'investor';
  CONFIG.username = 'investor';
  updateAuthUI();
  showToast('Signed out.');
}

/** Reflect session state in the profile badge. */
function updateAuthUI() {
  const session = Session.get();
  const name = session ? session.username : 'investor';
  const roleLabel = session
    ? (session.role === 'admin' ? 'SEBI Administrator' : 'Retail Investor')
    : 'Retail Investor (not signed in)';

  const nameEl = document.getElementById('profile-username');
  const roleEl = document.getElementById('profile-role');
  const avatarEl = document.getElementById('avatar-char');
  if (nameEl) nameEl.innerText = name;
  if (roleEl) roleEl.innerText = roleLabel;
  if (avatarEl) avatarEl.innerText = name.charAt(0).toUpperCase();
}

/** Prompt for credentials when a privileged action needs a token. */
async function ensureAdmin() {
  if (Session.isAdmin()) return true;

  const username = prompt('SEBI administrator username:');
  if (!username) return false;
  const password = prompt(`Password for ${username}:`);
  if (!password) return false;

  const ok = await signIn(username, password);
  if (ok && !Session.isAdmin()) {
    showToast('That account does not have administrator privileges.');
    return false;
  }
  return ok;
}

// Global variables
let threatChartInstance = null;
let activeScanChannel = 'text';

// Quiz state
const quizData = [
  {
    q: "You receive an SMS from 'NSE-Alert' claiming your account is blocked, linking to 'nse-verify.info'. What is the safest action?",
    options: [
      { text: "Click the link and fill out the details immediately.", correct: false },
      { text: "Ignore the link, copy/paste it into Sentinel to scan, and search official registry.", correct: true },
      { text: "Reply directly to the SMS with your details to verify.", correct: false }
    ]
  },
  {
    q: "A video features a market advisor promising guaranteed 100% returns if you join their Telegram tips channel. What signals suggest it is a deepfake?",
    options: [
      { text: "Expert videos on social media are always verified, so it must be authentic.", correct: false },
      { text: "The advisor is famous, so they are allowed to guarantee high profits.", correct: false },
      { text: "SEBI prohibits guaranteed return claims, and voice/video deepfakes commonly impersonate experts.", correct: true }
    ]
  },
  {
    q: "How can you verify that a circular received on social media is genuinely from SEBI?",
    options: [
      { text: "Confirm if it has the official SEBI logo on the document header.", correct: false },
      { text: "Paste the printed Sentinel Verify Code in the registry, or check official sebi.gov.in.", correct: true },
      { text: "Assume it's true if multiple members forwarded it inside WhatsApp groups.", correct: false }
    ]
  }
];
let currentQuizIdx = 0;

// PWA Service worker register
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js')
      .then(reg => console.log('ServiceWorker registered:', reg))
      .catch(err => console.log('ServiceWorker registration failed:', err));
  });
}

// Initialize App
window.addEventListener('DOMContentLoaded', () => {
  switchTab('dashboard');
  toggleRole('investor');
  loadTextSample(true);
  initQuiz();
});

// Toast notifier
function showToast(msg) {
  const t = document.getElementById('system-toast');
  t.innerText = msg;
  t.style.display = 'block';
  setTimeout(() => {
    t.style.display = 'none';
  }, 3000);
}

// Switch Tabs
function switchTab(tabId) {
  CONFIG.currentTab = tabId;
  
  // Manage active sidebar buttons
  document.querySelectorAll('.nav-btn').forEach(btn => {
    if (btn.dataset.tab === tabId) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  // Show panel
  document.querySelectorAll('.tab-panel').forEach(panel => {
    if (panel.id === `panel-${tabId}`) {
      panel.classList.add('active');
    } else {
      panel.classList.remove('active');
    }
  });

  // Update Titles
  const titleEl = document.getElementById('view-title');
  const descEl = document.getElementById('view-desc');
  
  if (tabId === 'dashboard') {
    titleEl.innerText = "Dashboard Overview";
    descEl.innerText = "Protecting retail investors from AI-driven financial fraud in India's capital markets.";
    loadDashboard();
  } else if (tabId === 'scanner') {
    titleEl.innerText = "Fraud Detection Engines";
    descEl.innerText = "Analyze text, images, audio, or video files for synthetic media and phishing signatures.";
  } else if (tabId === 'verify') {
    titleEl.innerText = "Verify Communication";
    descEl.innerText = "Verify digital signatures of official communications or register new publications.";
    loadRegistry();
  } else if (tabId === 'alerts') {
    titleEl.innerText = "Alerts & Warnings";
    descEl.innerText = "Live bulletins regarding current scam campaigns targeting retail market participants.";
    loadAlerts();
  } else if (tabId === 'reports') {
    titleEl.innerText = "Reports Queue";
    descEl.innerText = "SEBI Admin queue to review auto-reported incidents and take regulatory actions.";
    loadReports();
    loadCampaigns();
  } else if (tabId === 'social') {
    titleEl.innerText = "Social Media Monitor";
    descEl.innerText = "Sentinel public channels scraper feed scanning Twitter and Telegram for broker scams.";
    loadSocialFeed();
  } else if (tabId === 'insights') {
    titleEl.innerText = "Market Insights";
    descEl.innerText = "Active bulletins explaining rising trends in capital market fraud.";
  } else if (tabId === 'learning') {
    titleEl.innerText = "Learning Center";
    descEl.innerText = "Spot generative media manipulation artifacts and test your safety check scores.";
  } else if (tabId === 'settings') {
    titleEl.innerText = "Console Settings";
    descEl.innerText = "Manage diagnostics, issuer RSA keys, and simulate administrator privileges.";
  }
}

// Switch scan channel inside Scanner
function switchScanChannel(chan) {
  activeScanChannel = chan;
  document.querySelectorAll('.channel-btn').forEach(btn => {
    const text = btn.innerText.toLowerCase();
    if (text.includes(chan) || (chan === 'text' && text.includes('sms')) || (chan === 'image' && text.includes('screenshot'))) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  const textCont = document.getElementById('scan-input-text-container');
  const fileCont = document.getElementById('scan-input-file-container');

  if (chan === 'text') {
    textCont.style.display = 'block';
    fileCont.style.display = 'none';
  } else {
    textCont.style.display = 'none';
    fileCont.style.display = 'block';
    const label = document.getElementById('file-drop-label');
    if (chan === 'eml') label.innerText = 'Click or Drag & Drop EML Email File';
    else if (chan === 'image') label.innerText = 'Click or Drag & Drop Screenshot / Image (QR Code quishing support)';
    else if (chan === 'audio') label.innerText = 'Click or Drag & Drop Audio File (MP3/WAV deepfake check)';
    else if (chan === 'video') label.innerText = 'Click or Drag & Drop Video File (MP4/AVI forensics)';
  }
}

function handleFileSelected(input) {
  const label = document.getElementById('file-drop-label');
  if (input.files && input.files[0]) {
    label.innerText = `Selected File: ${input.files[0].name}`;
  }
}

async function runAnalysis() {
  const scoreEl = document.getElementById('verdict-score');
  const tierEl = document.getElementById('verdict-tier');
  const badgeEl = document.getElementById('verdict-badge');
  const expEl = document.getElementById('verdict-explanation');

  if (activeScanChannel === 'text') {
    const text = document.getElementById('scan-text-input').value;
    if (!text.trim()) { showToast("Please paste text to analyze."); return; }

    scoreEl.innerText = '...';
    expEl.innerText = 'Analyzing text Shannon entropy, typosquatting domains, and SEBI circular contradictions...';

    try {
      const res = await fetch(`${CONFIG.apiEndpoint}/phishing/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: text, channel: 'sms' })
      });
      const data = await res.json();
      const score = data.risk_score || data.risk_fusion?.calibrated_score || 0;
      scoreEl.innerText = `${score}%`;
      tierEl.innerText = data.verdict || (score >= 70 ? 'HIGH_RISK_PHISHING' : score >= 30 ? 'MODERATE_RISK' : 'SAFE');
      
      if (score >= 70) {
        badgeEl.className = 'badge-tag badge-danger';
        badgeEl.innerText = 'HIGH RISK PHISHING';
      } else if (score >= 30) {
        badgeEl.className = 'badge-tag badge-suspicious';
        badgeEl.innerText = 'SUSPICIOUS';
      } else {
        badgeEl.className = 'badge-tag badge-safe';
        badgeEl.innerText = 'SAFE';
      }

      const flagDetails = (data.flags || []).map(f => `• ${f.detail}`).join('<br>') || 'No scam indicators detected.';
      expEl.innerHTML = flagDetails;
    } catch (e) {
      scoreEl.innerText = 'ERR';
      expEl.innerText = 'Analysis connection failed.';
    }
  } else {
    const fileEl = document.getElementById('scan-file-input');
    const file = fileEl.files[0];
    if (!file) { showToast("Please select a file to analyze."); return; }

    scoreEl.innerText = '...';
    expEl.innerText = `Analyzing file artifact (${file.name})...`;

    const formData = new FormData();
    formData.append('file', file);
    
    let endpoint = '/forensics/media';
    if (activeScanChannel === 'eml') endpoint = '/eml/analyze';
    else if (activeScanChannel === 'image') endpoint = '/media/scan-qr';
    else if (activeScanChannel === 'audio') endpoint = '/forensics/audio';
    else if (activeScanChannel === 'video') endpoint = '/forensics/video';

    try {
      const res = await fetch(`${CONFIG.apiEndpoint}${endpoint}`, {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      const score = data.riskScore || data.risk_score || data.risk_fusion?.calibrated_score || 0;
      scoreEl.innerText = `${score}%`;
      tierEl.innerText = data.verdict || (score >= 70 ? 'HIGH_RISK' : 'SAFE');

      if (score >= 70) {
        badgeEl.className = 'badge-tag badge-danger';
        badgeEl.innerText = 'HIGH RISK ARTIFACT';
      } else {
        badgeEl.className = 'badge-tag badge-safe';
        badgeEl.innerText = 'SAFE / AUDITED';
      }

      const flagDetails = (data.flags || []).map(f => `• ${f.detail || f.description || f.type}`).join('<br>') || 'Artifact audited cleanly.';
      expEl.innerHTML = flagDetails;
    } catch (e) {
      scoreEl.innerText = 'ERR';
      expEl.innerText = 'File analysis failed.';
    }
  }
}

// Load samples helper
function loadTextSample(isPhishing = true) {
  const textEl = document.getElementById('scan-text-input');
  if (isPhishing) {
    textEl.value = "Dear Customer, SEBI URGENT NOTICE: Your trading account will be suspended within 24 hours. Verify immediately by clicking http://sebi-goviin.com/verify and enter your OTP and UPI PIN. Guaranteed returns on our exclusive pre-IPO shares, join our telegram now!";
  } else {
    textEl.value = "Hi, your Zerodha contract note for June 2026 is now available in the console under Reports. Please inspect. No action needed.";
  }
}

// Role Toggler
//
// This only reveals or hides UI surface. It grants no privilege: the backend
// authorizes every privileged action from the bearer token, so switching to
// the admin view without signing in still yields 401/403 on the API.
function toggleRole(role) {
  CONFIG.currentRole = role;
  CONFIG.username = role === 'sebi_admin' ? 'sebi_admin' : 'investor';

  // Update user badge
  document.getElementById('profile-username').innerText = CONFIG.username;
  document.getElementById('profile-role').innerText = role === 'sebi_admin' ? 'SEBI Administrator' : 'Retail Investor';
  document.getElementById('avatar-char').innerText = role === 'sebi_admin' ? 'S' : 'I';
  document.getElementById('meta-role-display').innerText = role === 'sebi_admin' ? 'SEBI Admin' : 'Investor';

  if (role === 'sebi_admin' && !Session.isAdmin()) {
    showToast('Admin view enabled. Privileged actions will prompt for sign-in.');
  }

  // Show/hide SEBI only buttons/panels
  const sebiBtn = document.querySelector('.nav-btn.sebi-only');
  const issuerLock = document.getElementById('issuer-lock-screen');
  const alertsLock = document.getElementById('alerts-lock-screen');
  const createAlertLock = document.getElementById('create-alert-panel');
  
  if (role === 'sebi_admin') {
    sebiBtn.style.display = 'flex';
    if(issuerLock) issuerLock.style.display = 'none';
    if(alertsLock) alertsLock.style.display = 'none';
    if(createAlertLock) createAlertLock.classList.remove('lock-overlay');
    
    document.getElementById('toggle-sebi-role').style.background = 'var(--gold)';
    document.getElementById('toggle-sebi-role').style.color = 'var(--bg-dark)';
    document.getElementById('toggle-investor-role').style.background = 'var(--bg-panel)';
    document.getElementById('toggle-investor-role').style.color = 'var(--text-primary)';
  } else {
    sebiBtn.style.display = 'none';
    if(issuerLock) issuerLock.style.display = 'flex';
    if(alertsLock) alertsLock.style.display = 'flex';
    if(createAlertLock) createAlertLock.classList.add('lock-overlay');
    
    document.getElementById('toggle-investor-role').style.background = 'var(--gold)';
    document.getElementById('toggle-investor-role').style.color = 'var(--bg-dark)';
    document.getElementById('toggle-sebi-role').style.background = 'var(--bg-panel)';
    document.getElementById('toggle-sebi-role').style.color = 'var(--text-primary)';
    
    if(CONFIG.currentTab === 'reports') {
      switchTab('dashboard');
    }
  }
  
  showToast(`Role switched to ${role === 'sebi_admin' ? 'SEBI Admin' : 'Investor'}`);
}

function saveSettings() {
  const host = document.getElementById('setting-api-host').value.trim();
  if (!host) { showToast("Enter a valid API server host."); return; }
  CONFIG.apiEndpoint = host;
  showToast(`Backend API host set to ${host}`);
}

async function clearDatabase() {
  if (!confirm("Are you sure you want to clear and reset the entire database? All scan history and campaign graphs will be reset.")) {
    return;
  }

  showToast("Clearing database...");

  try {
    const res = await fetch(`${CONFIG.apiEndpoint}/api/clear-database`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast("Database cleared and baseline environment re-seeded!");
      loadDashboard();
      if (typeof loadReports === 'function') loadReports();
      if (window.threat3D) window.threat3D.initDefaultNodes();
    } else {
      showToast(data.detail || "Database clear failed.");
    }
  } catch (e) {
    showToast("Failed to connect to backend server for database clear.");
  }
}

function openExtensionGuide() {
  const modal = document.getElementById('extension-modal');
  if (modal) modal.style.display = 'flex';
}

function closeExtensionGuide() {
  const modal = document.getElementById('extension-modal');
  if (modal) modal.style.display = 'none';
}

function dismissExtensionBanner() {
  const banner = document.getElementById('extension-banner');
  if (banner) banner.style.display = 'none';
  sessionStorage.setItem('extension_banner_dismissed', 'true');
}

// Auto check banner dismissal state on load
window.addEventListener('DOMContentLoaded', () => {
  if (sessionStorage.getItem('extension_banner_dismissed') === 'true') {
    const banner = document.getElementById('extension-banner');
    if (banner) banner.style.display = 'none';
  }
});
