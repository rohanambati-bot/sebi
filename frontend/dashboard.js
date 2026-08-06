// SentinelSEBI — Dashboard Module
// Dashboard stats loading, Chart.js doughnut, recent scans table

// Call dashboard API
async function loadDashboard() {
  try {
    const statsRes = await fetch(`${CONFIG.apiEndpoint}/dashboard/stats`);
    const stats = await statsRes.json();
    
    // Update counters safely
    const totalCount = stats.totalScans ?? stats.total_scans ?? 0;
    const highRiskCount = stats.phishingBlocked ?? stats.high_risk_scans ?? 0;
    const verifiedCount = stats.verifiedCommunications ?? stats.registered_comms ?? 0;

    const totalEl = document.getElementById('stat-total-scans');
    const highEl = document.getElementById('stat-high-risk');
    const verEl = document.getElementById('stat-registered');

    if (totalEl) totalEl.innerText = totalCount;
    if (highEl) highEl.innerText = highRiskCount;
    if (verEl) verEl.innerText = verifiedCount;

    const breakdown = stats.breakdown || { phishing_emails: 0, deepfake_videos: 0, fake_audios: 0, manipulated_images: 0 };

    // Update threat details list
    const breakPhish = document.getElementById('break-phish');
    const breakVideo = document.getElementById('break-video');
    const breakAudio = document.getElementById('break-audio');
    const breakImage = document.getElementById('break-image');

    if (breakPhish) breakPhish.innerText = breakdown.phishing_emails || 0;
    if (breakVideo) breakVideo.innerText = breakdown.deepfake_videos || 0;
    if (breakAudio) breakAudio.innerText = breakdown.fake_audios || 0;
    if (breakImage) breakImage.innerText = breakdown.manipulated_images || 0;

    // Update Chart.js Donut
    updateChart(breakdown);

    // Load Recent Scans Table
    const recentRes = await fetch(`${CONFIG.apiEndpoint}/dashboard/recent`);
    const recentData = await recentRes.json();
    const scans = recentData.recentScans || (Array.isArray(recentData) ? recentData : []);
    
    const tbody = document.getElementById('recent-scans-body');
    if (!scans || scans.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">No recent scans on record.</td></tr>';
    } else {
      tbody.innerHTML = scans.map(s => {
        const dateObj = s.created_at ? new Date(s.created_at) : new Date();
        const formattedTime = dateObj.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        const label = (s.content_type || 'TEXT').toUpperCase();
        const dispText = (s.text_or_filename || 'Content').slice(0, 50);
        const verdictStr = s.verdict || 'SAFE';
        const verdClass = verdictStr.toLowerCase();
        return `<tr>
          <td>${formattedTime}</td>
          <td><span class="code-chip" style="font-size:10px; color:var(--text-primary); margin-right:8px;">${label}</span>${escapeHtml(dispText)}</td>
          <td>${escapeHtml(s.sender || 'Direct Upload')}</td>
          <td class="verd-${verdClass}" style="font-weight:600;">${verdictStr.replace(/_/g,' ')}</td>
          <td style="font-family:var(--font-mono); font-weight:bold;">${s.risk_score || 0}</td>
        </tr>`;
      }).join('');
    }

    // Load Alerts preview
    const alertsRes = await fetch(`${CONFIG.apiEndpoint}/alerts/feed`);
    const alertsData = await alertsRes.json();
    const alerts = alertsData.alerts || (Array.isArray(alertsData) ? alertsData : []);
    const alertBox = document.getElementById('dashboard-alerts-feed');
    if (!alerts || alerts.length === 0) {
      alertBox.innerHTML = '<p class="text-secondary" style="font-size:12px; text-align:center;">No active bulletins.</p>';
    } else {
      alertBox.innerHTML = alerts.slice(0, 3).map(a => {
        const urgencyClass = a.severity === 'critical' || a.severity === 'high' ? 'crit' : (a.severity === 'medium' ? 'warn' : 'info');
        return `<div class="feed-item" style="padding: 10px 0;">
          <div class="feed-badge ${urgencyClass}"></div>
          <div class="feed-details">
            <h4 style="font-size:12px;">${escapeHtml(a.title)}</h4>
            <p style="font-size:11px; margin-top:2px;">${escapeHtml((a.description || a.title).slice(0, 100))}...</p>
          </div>
        </div>`;
      }).join('');
    }

  } catch (e) {
    console.error(e);
    showToast("Cannot connect to the backend API.");
  }
}

// Setup / Update Chart.js
function updateChart(breakdown) {
  const ctx = document.getElementById('threatChart').getContext('2d');
  const dataVals = [
    breakdown.phishing_emails,
    breakdown.deepfake_videos,
    breakdown.fake_audios,
    breakdown.manipulated_images
  ];

  if (threatChartInstance) {
    threatChartInstance.data.datasets[0].data = dataVals;
    threatChartInstance.update();
  } else {
    threatChartInstance = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Phishing Text', 'Deepfake Video', 'Voice Clone', 'Image Forensics'],
        datasets: [{
          data: dataVals,
          backgroundColor: ['#f59e0b', '#ef4444', '#8b5cf6', '#10b981'],
          borderColor: '#0a0f1d',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        cutout: '75%'
      }
    });
  }
}
