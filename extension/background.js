/**
 * SentinelSEBI Browser Extension Background Service Worker
 * Manages tab risk states, dynamic extension badges (🟢 Safe, 🟡 Suspicious, 🔴 Scam Alert),
 * and automatic ingestion of scam evidence into the SEBI database platform.
 */

let API_BASE = 'http://127.0.0.1:8000';
const tabStateMap = {};
let activeUserEmail = 'investor@sebi.gov.in';

// Load saved user email and backend API host from persistent chrome.storage
if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
  chrome.storage.local.get(['sentinelUserEmail', 'sentinelApiBase'], (data) => {
    if (data && data.sentinelUserEmail) activeUserEmail = data.sentinelUserEmail;
    if (data && data.sentinelApiBase) API_BASE = data.sentinelApiBase.replace(/\/$/, '');
  });
}

chrome.runtime.onInstalled.addListener(() => {
  console.log('🛡️ SentinelSEBI Extension Background Service Worker initialized.');
  try {
    chrome.contextMenus.create({
      id: 'sentinel-scan-text',
      title: '🛡️ Scan Selected Text with SentinelSEBI',
      contexts: ['selection']
    });
  } catch (e) {}
});

// Handle Context Menu Right-Click Scanning
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'sentinel-scan-text' && info.selectionText) {
    try {
      const res = await fetch(`${API_BASE}/phishing/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: info.selectionText, channel: 'selection' })
      });
      const analysis = await res.json();
      
      const riskScore = analysis.risk_score || 0;
      const verdict = analysis.verdict || 'SAFE';
      
      let badgeText = riskScore >= 70 ? 'ALERT' : riskScore >= 30 ? 'WARN' : 'OK';
      let badgeColor = riskScore >= 70 ? '#ef4444' : riskScore >= 30 ? '#f59e0b' : '#10b981';

      if (tab && tab.id) {
        chrome.action.setBadgeText({ tabId: tab.id, text: badgeText });
        chrome.action.setBadgeBackgroundColor({ tabId: tab.id, color: badgeColor });
        
        tabStateMap[tab.id] = {
          tabId: tab.id,
          url: tab.url,
          title: tab.title,
          userEmail: activeUserEmail,
          channel: 'selection',
          riskScore,
          verdict,
          tier: riskScore >= 70 ? 'DANGER' : riskScore >= 30 ? 'SUSPICIOUS' : 'SAFE',
          badgeColor,
          flags: analysis.flags || [],
          iocs: analysis.iocs || [],
          mlProbability: analysis.ml_probability,
          riskFusion: analysis.risk_fusion,
          loggedToSebi: true,
          lastUpdated: new Date().toISOString()
        };
      }
    } catch (e) {}
  }
});

// Listen for messages from contentScript.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SET_USER_EMAIL' && message.email) {
    activeUserEmail = message.email;
    sendResponse({ status: 'EMAIL_UPDATED' });
    return true;
  }

  const tabId = sender.tab ? sender.tab.id : null;

  if (message.type === 'ANALYSIS_RESULT' && tabId) {
    const { analysis, url, title, channel } = message;
    
    const riskScore = analysis.risk_score || 0;
    const verdict = analysis.verdict || 'SAFE';

    // Prevent low-risk generic background page text from overwriting a higher-risk email/chat scan!
    const existing = tabStateMap[tabId];
    if (existing && existing.riskScore > riskScore && channel === 'web') {
      sendResponse({ status: 'PRESERVED_HIGHER_RISK' });
      return true;
    }
    
    // Determine risk status color tier
    // 🟢 Green = Safe (<30), 🟡 Yellow = Suspicious (30-69), 🔴 Red = Scam / High Risk (>=70)
    let tier = 'SAFE';
    let badgeText = 'OK';
    let badgeColor = '#10b981'; // Green

    if (riskScore >= 70) {
      tier = 'DANGER';
      badgeText = 'ALERT';
      badgeColor = '#ef4444'; // Red
    } else if (riskScore >= 30) {
      tier = 'SUSPICIOUS';
      badgeText = 'WARN';
      badgeColor = '#f59e0b'; // Yellow
    }

    // Set dynamic extension badge for active tab
    try {
      chrome.action.setBadgeText({ tabId, text: badgeText });
      chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
    } catch (e) {}

    // Store state for popup display
    tabStateMap[tabId] = {
      tabId,
      url,
      title,
      userEmail: activeUserEmail,
      channel: channel || 'web',
      riskScore,
      verdict,
      tier,
      badgeColor,
      flags: analysis.flags || [],
      iocs: analysis.iocs || [],
      mlProbability: analysis.ml_probability,
      riskFusion: analysis.risk_fusion,
      loggedToSebi: true,
      lastUpdated: new Date().toISOString()
    };

    sendResponse({ status: 'STATE_UPDATED', tier });
  }

  if (message.type === 'GET_TAB_STATE') {
    const activeTabId = message.tabId;
    sendResponse(tabStateMap[activeTabId] || null);
  }

  return true;
});

// Clean up state when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabStateMap[tabId];
});
