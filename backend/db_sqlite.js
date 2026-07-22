/**
 * SentinelSEBI SQLite Database Manager (sentinel.db)
 * 
 * Provides real persistent database storage for:
 * 1. Users & Authentication (PBKDF2 Password Hashing)
 * 2. Scan History & Forensics Audit Trail
 * 3. Public Threat Bulletins & Security Alerts
 * 4. Regulatory Incident Takedowns & CERT-In / DoT / NPCI Directives
 * 5. Registered Issuer Cryptographic PKI Communications
 * 6. Scraped Social Media Threat Feed
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');

const DB_PATH = path.join(__dirname, 'sentinel.db');
const db = new sqlite3.Database(DB_PATH);

// Initialize Tables synchronously
db.serialize(() => {
  // 1. Users Table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  // Seed default admin and investor if users table is empty
  db.get(`SELECT COUNT(*) as count FROM users`, (err, row) => {
    if (row && row.count === 0) {
      const createDefaultUser = (username, password, role) => {
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
        db.run(
          `INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)`,
          [username, hash, salt, role, new Date().toISOString()]
        );
      };

      createDefaultUser('admin', 'sebi_admin_2026', 'admin');
      createDefaultUser('sebi', 'sebi_official_2026', 'admin');
      createDefaultUser('investor', 'investor123', 'investor');
    }
  });

  // 2. Scans Table
  db.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      content_type TEXT NOT NULL,
      text_or_filename TEXT NOT NULL,
      sender TEXT NOT NULL,
      channel TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      verdict TEXT NOT NULL,
      flags_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  // 3. Threat Alerts Table
  db.run(`
    CREATE TABLE IF NOT EXISTS threat_alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      severity TEXT NOT NULL,
      date_str TEXT NOT NULL,
      upi_id TEXT NOT NULL,
      domain TEXT NOT NULL
    )
  `);

  // Seed initial alerts if empty
  db.get(`SELECT COUNT(*) as count FROM threat_alerts`, (err, row) => {
    if (row && row.count === 0) {
      db.run(`
        INSERT INTO threat_alerts (title, description, severity, date_str, upi_id, domain)
        VALUES 
        ('Fake Telegram Stock Tip Group Flagged', 'Scammers impersonating SEBI registered research analysts offering 500% guaranteed returns.', 'high', '2026-07-22', 'invest.now@oksbi', 'sebi-official-tips.xyz'),
        ('Spoofed Broker Settlement Emails Detected', 'Phishing campaign spoofing Zerodha contract notes to steal trading credentials.', 'critical', '2026-07-21', 'settlement@paytm', 'broker-zerodha.online')
      `);
    }
  });

  // 4. Takedowns Table
  db.run(`
    CREATE TABLE IF NOT EXISTS takedowns (
      id TEXT PRIMARY KEY,
      target_domain TEXT NOT NULL,
      scam_vpa TEXT NOT NULL,
      target_phone TEXT NOT NULL,
      threat_category TEXT NOT NULL,
      status TEXT NOT NULL,
      dot_dns_status TEXT NOT NULL,
      npci_vpa_status TEXT NOT NULL,
      date_str TEXT NOT NULL,
      legal_notice_text TEXT NOT NULL
    )
  `);

  // Seed initial takedown if empty
  db.get(`SELECT COUNT(*) as count FROM takedowns`, (err, row) => {
    if (row && row.count === 0) {
      db.run(`
        INSERT INTO takedowns (id, target_domain, scam_vpa, target_phone, threat_category, status, dot_dns_status, npci_vpa_status, date_str, legal_notice_text)
        VALUES ('CERT-IN-1721642400000', 'sebi-official-tips.xyz', 'invest.now@oksbi', '+91 9876543210', 'Securities Market Impersonation Fraud', 'DISPATCHED_TO_DOT_NPCI', 'BLOCKED_BY_DOT', 'FROZEN_BY_NPCI', '2026-07-22', 'CERT-In Incident Report Sec 70B IT Act 2000')
      `);
    }
  });

  // 5. Registered Communications PKI Table
  db.run(`
    CREATE TABLE IF NOT EXISTS registered_communications (
      code TEXT PRIMARY KEY,
      issuer_id TEXT NOT NULL,
      issuer_name TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);

  // 6. Social Posts Table
  db.run(`
    CREATE TABLE IF NOT EXISTS social_posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      platform TEXT NOT NULL,
      author TEXT NOT NULL,
      content TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      flagged_at TEXT NOT NULL
    )
  `);
});

class DBSqlite {
  // User Authentication Helper
  static getUserByUsername(username, callback) {
    db.get(`SELECT * FROM users WHERE username = ?`, [username], callback);
  }

  // Scans Helpers
  static addScan(scan, callback) {
    const flagsJson = JSON.stringify(scan.flags || []);
    db.run(
      `INSERT INTO scans (content_type, text_or_filename, sender, channel, risk_score, verdict, flags_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [scan.content_type, scan.text_or_filename, scan.sender, scan.channel, scan.risk_score, scan.verdict, flagsJson, scan.created_at || new Date().toISOString()],
      function (err) {
        callback(err, this ? this.lastID : null);
      }
    );
  }

  static getRecentScans(limit, callback) {
    db.all(`SELECT * FROM scans ORDER BY id DESC LIMIT ?`, [limit || 10], callback);
  }

  static getStats(callback) {
    db.serialize(() => {
      db.get(`SELECT COUNT(*) as totalScans, SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END) as phishingBlocked FROM scans`, (err, scanRow) => {
        db.get(`SELECT COUNT(*) as registeredComms FROM registered_communications`, (err, commRow) => {
          db.get(`SELECT COUNT(*) as activeAlerts FROM threat_alerts`, (err, alertRow) => {
            db.all(`SELECT content_type, COUNT(*) as count FROM scans GROUP BY content_type`, (err, breakdownRows) => {
              const breakdown = {
                phishing_emails: 0,
                deepfake_videos: 0,
                fake_audios: 0,
                manipulated_images: 0
              };

              (breakdownRows || []).forEach(r => {
                if (r.content_type === 'text' || r.content_type === 'eml') breakdown.phishing_emails += r.count;
                else if (r.content_type === 'video') breakdown.deepfake_videos += r.count;
                else if (r.content_type === 'audio') breakdown.fake_audios += r.count;
                else if (r.content_type === 'image') breakdown.manipulated_images += r.count;
              });

              callback(null, {
                totalScans: scanRow ? (scanRow.totalScans || 0) : 0,
                phishingBlocked: scanRow ? (scanRow.phishingBlocked || 0) : 0,
                verifiedCommunications: commRow ? (commRow.registeredComms || 0) : 0,
                activeAlerts: alertRow ? (alertRow.activeAlerts || 0) : 0,
                breakdown
              });
            });
          });
        });
      });
    });
  }

  // Alerts
  static getAlerts(callback) {
    db.all(`SELECT * FROM threat_alerts ORDER BY id DESC`, [], callback);
  }

  static addAlert(alert, callback) {
    db.run(
      `INSERT INTO threat_alerts (title, description, severity, date_str, upi_id, domain) VALUES (?, ?, ?, ?, ?, ?)`,
      [alert.title, alert.description, alert.severity, alert.date || new Date().toISOString().split('T')[0], alert.upiId || 'N/A', alert.domain || 'N/A'],
      function (err) {
        callback(err, this ? this.lastID : null);
      }
    );
  }

  // Takedowns
  static getTakedowns(callback) {
    db.all(`SELECT * FROM takedowns ORDER BY date_str DESC`, [], callback);
  }

  static addTakedown(takedown, callback) {
    db.run(
      `INSERT OR REPLACE INTO takedowns (id, target_domain, scam_vpa, target_phone, threat_category, status, dot_dns_status, npci_vpa_status, date_str, legal_notice_text)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [takedown.id, takedown.target_domain, takedown.scam_vpa, takedown.target_phone, takedown.threat_category, takedown.status, takedown.dot_dns_status, takedown.npci_vpa_status, takedown.date_str, takedown.legal_notice_text],
      callback
    );
  }

  static updateTakedownStatus(id, status, callback) {
    db.run(`UPDATE takedowns SET status = ? WHERE id = ?`, [status, id], callback);
  }

  // Registered Communications
  static addRegisteredComm(record, callback) {
    db.run(
      `INSERT OR REPLACE INTO registered_communications (code, issuer_id, issuer_name, content_hash, created_at) VALUES (?, ?, ?, ?, ?)`,
      [record.code, record.issuerId, record.issuerName, record.contentHash, record.createdAt || new Date().toISOString()],
      callback
    );
  }

  static getRegisteredComms(callback) {
    db.all(`SELECT * FROM registered_communications ORDER BY created_at DESC`, [], callback);
  }

  // Social Posts
  static getSocialPosts(callback) {
    db.all(`SELECT * FROM social_posts ORDER BY id DESC`, [], callback);
  }

  static addSocialPost(post, callback) {
    db.run(
      `INSERT INTO social_posts (platform, author, content, risk_score, flagged_at) VALUES (?, ?, ?, ?, ?)`,
      [post.platform, post.author, post.content, post.riskScore, post.flaggedAt || new Date().toISOString()],
      function (err) {
        callback(err, this ? this.lastID : null);
      }
    );
  }
}

module.exports = DBSqlite;
