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
  document.querySelectorAll('.channel-tab-btn').forEach(btn => {
    if (btn.dataset.channel === chan) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  document.querySelectorAll('.scan-channel-panel').forEach(panel => {
    if (panel.id === `scan-chan-${chan}`) {
      panel.style.display = 'block';
    } else {
      panel.style.display = 'none';
    }
  });

  // Hide result box when switching channels
  document.getElementById('scan-result-box').style.display = 'none';
}

// Load samples helper
function loadTextSample(isPhishing) {
  const textEl = document.getElementById('scan-text-input');
  const senderEl = document.getElementById('scan-text-sender');
  if (isPhishing) {
    textEl.value = "Dear Customer, SEBI URGENT NOTICE: Your trading account will be suspended within 24 hours. Verify immediately by clicking http://sebi-goviin.com/verify and enter your OTP and UPI PIN. Guaranteed returns on our exclusive pre-IPO shares, join our telegram now!";
    senderEl.value = "alerts@sebi-goviin.com";
  } else {
    textEl.value = "Hi, your Zerodha contract note for June 2026 is now available in the console under Reports. Please inspect. No action needed.";
    senderEl.value = "noreply@zerodha.com";
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
