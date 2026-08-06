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
 * 7. Tamper-Evident Hash-Chained Audit Log (Phase 0 item 0.3)
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');
const Audit = require('./audit');
const Evidence = require('./evidence');

const DB_PATH = process.env.SENTINEL_DB_PATH || path.join(__dirname, 'sentinel.db');
const db = new sqlite3.Database(DB_PATH);

// Enforce foreign keys — off by default in SQLite, so the user_id FKs added in
// Phase 0 item 0.2 would otherwise be documentation rather than a constraint.
db.run('PRAGMA foreign_keys = ON');

/**
 * Add a column to an existing table if it is missing.
 *
 * Deployed databases already contain scans/takedowns rows without user_id, and
 * SQLite cannot add a column to a table retroactively via CREATE TABLE IF NOT
 * EXISTS. Existing rows get NULL, which correctly reads as "actor unknown,
 * recorded before attribution existed" rather than falsely naming someone.
 */
function ensureColumn(table, column, definition) {
  return new Promise((resolve) => {
    db.all(`PRAGMA table_info(${table})`, (err, rows) => {
      if (err || !rows) return resolve(false);
      if (rows.some((r) => r.name === column)) return resolve(false);

      db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`, (alterErr) => {
        if (alterErr) {
          console.error(`[db] migration failed: ${table}.${column} — ${alterErr.message}`);
        } else {
          console.log(`[db] migration applied: added ${table}.${column}`);
        }
        resolve(!alterErr);
      });
    });
  });
}

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

  // Default users are seeded by seedDefaultUsers() in the migration chain below,
  // which must run after the legacy-schema check to avoid racing the rebuild.

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
      created_at TEXT NOT NULL,
      user_id INTEGER REFERENCES users(id),
      source_ip TEXT,
      full_text TEXT,
      forensics_json TEXT,
      iocs_json TEXT,
      evidence_sha256 TEXT
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
      legal_notice_text TEXT NOT NULL,
      user_id INTEGER REFERENCES users(id)
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
      created_at TEXT NOT NULL,
      user_id INTEGER REFERENCES users(id)
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

  // 7. Tamper-Evident Audit Log (append-only, hash-chained)
  //
  // No UPDATE or DELETE helper is exposed for this table anywhere in the
  // codebase. `entry_hash` covers the row content plus `prev_hash`, so editing
  // history breaks the chain at the point of tampering.
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id INTEGER,
      actor_username TEXT NOT NULL,
      actor_role TEXT NOT NULL,
      action TEXT NOT NULL,
      target_type TEXT,
      target_id TEXT,
      outcome TEXT NOT NULL,
      source_ip TEXT,
      user_agent TEXT,
      metadata_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      entry_hash TEXT NOT NULL
    )
  `);

  db.run(`CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_username)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)`);

  // 8. Evidence Artifacts — chain of custody for uploaded files (Phase 1 item 1D)
  //
  // Retention happens before analysis runs (see evidence.js::retain), so
  // sha256/md5 here provably describe the bytes that were analyzed, not a
  // post-hoc recomputation. `prev_hash`/`entry_hash` chain the same way the
  // Phase 0 audit_log does: altering or removing a row breaks the chain from
  // that point forward.
  db.run(`
    CREATE TABLE IF NOT EXISTS evidence_artifacts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER REFERENCES scans(id),
      sha256 TEXT NOT NULL,
      md5 TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      mime_type TEXT,
      original_filename TEXT,
      stored_path TEXT,
      user_id INTEGER REFERENCES users(id),
      source_ip TEXT,
      created_at TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      entry_hash TEXT NOT NULL
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence_artifacts(sha256)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence_artifacts(scan_id)`);

  // ─────────────────── Phase 2: IOC Graph & Campaigns ───────────────────
  //
  // 9. IOCs — one row per distinct indicator, regardless of how many scans
  // sighted it. `sighting_count` and first/last_seen turn a repeated indicator
  // into a trend rather than duplicate rows.
  db.run(`
    CREATE TABLE IF NOT EXISTS iocs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      value TEXT NOT NULL,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      sighting_count INTEGER NOT NULL DEFAULT 1,
      confidence INTEGER NOT NULL DEFAULT 50,
      max_risk_score INTEGER NOT NULL DEFAULT 0,
      UNIQUE(type, value)
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)`);

  // 10. IOC links — edges. Every edge carries the scan that evidenced it;
  // an unsourced edge in a dossier is a liability, because a reviewer will ask
  // "how do you know" and there must be a row to point at.
  db.run(`
    CREATE TABLE IF NOT EXISTS ioc_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_ioc_id INTEGER NOT NULL REFERENCES iocs(id),
      target_ioc_id INTEGER NOT NULL REFERENCES iocs(id),
      relationship TEXT NOT NULL,
      evidence_scan_id INTEGER REFERENCES scans(id),
      confidence INTEGER NOT NULL DEFAULT 50,
      first_seen TEXT NOT NULL,
      UNIQUE(source_ioc_id, target_ioc_id, relationship)
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_links_source ON ioc_links(source_ioc_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_links_target ON ioc_links(target_ioc_id)`);

  // 11. Scan ↔ IOC join: which scan sighted which indicator. Enables
  // "show me every scan that mentioned this VPA" and campaign clustering.
  db.run(`
    CREATE TABLE IF NOT EXISTS scan_iocs (
      scan_id INTEGER NOT NULL REFERENCES scans(id),
      ioc_id INTEGER NOT NULL REFERENCES iocs(id),
      created_at TEXT NOT NULL,
      UNIQUE(scan_id, ioc_id)
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_scan_iocs_scan ON scan_iocs(scan_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_scan_iocs_ioc ON scan_iocs(ioc_id)`);

  // 12. Campaigns — connected components of the IOC graph, recomputed on
  // demand rather than maintained incrementally (see rebuildCampaigns).
  db.run(`
    CREATE TABLE IF NOT EXISTS campaigns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      label TEXT NOT NULL,
      cluster_method TEXT NOT NULL,
      member_count INTEGER NOT NULL DEFAULT 0,
      max_risk_score INTEGER NOT NULL DEFAULT 0,
      first_seen TEXT,
      last_seen TEXT,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      created_at TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS campaign_members (
      campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
      ioc_id INTEGER NOT NULL REFERENCES iocs(id),
      UNIQUE(campaign_id, ioc_id)
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_campaign_members_campaign ON campaign_members(campaign_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_campaign_members_ioc ON campaign_members(ioc_id)`);

  // ─────────────────── Phase 3: Enrichment Cache ───────────────────
  //
  // 13. Cached external lookups. Without a cache, one bulk scan would exhaust
  // the RDAP/crt.sh rate limits and get the host blocked mid-investigation.
  // `retrieved_at` is stored so a stale record is never presented as current.
  db.run(`
    CREATE TABLE IF NOT EXISTS enrichment_cache (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      indicator_type TEXT NOT NULL,
      indicator_value TEXT NOT NULL,
      source TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      retrieved_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      UNIQUE(indicator_type, indicator_value, source)
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_enrichment_lookup ON enrichment_cache(indicator_type, indicator_value)`);

  // ─────────────────── Phase 4: Correlation Artifacts ───────────────────
  //
  // 14. Biometric and perceptual fingerprints for cross-case matching.
  // Voiceprints are biometric data under the DPDP Act: retention is purpose-
  // limited and a match is investigative lead quality, never proof.
  db.run(`
    CREATE TABLE IF NOT EXISTS fingerprints (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER REFERENCES scans(id),
      kind TEXT NOT NULL,
      vector_json TEXT,
      hash_value TEXT,
      dimensions INTEGER,
      created_at TEXT NOT NULL
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_fingerprints_kind ON fingerprints(kind)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_fingerprints_hash ON fingerprints(hash_value)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_fingerprints_scan ON fingerprints(scan_id)`);

  // 15. Confirmed matches between fingerprints, with the score that produced
  // them so a threshold can be audited after the fact.
  db.run(`
    CREATE TABLE IF NOT EXISTS fingerprint_matches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kind TEXT NOT NULL,
      fingerprint_a INTEGER NOT NULL REFERENCES fingerprints(id),
      fingerprint_b INTEGER NOT NULL REFERENCES fingerprints(id),
      score REAL NOT NULL,
      threshold REAL NOT NULL,
      method TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(fingerprint_a, fingerprint_b, kind)
    )
  `);
  // 16. Brand Watch Proactive CT-Log Alerts
  db.run(`
    CREATE TABLE IF NOT EXISTS brandwatch_alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain_variant TEXT UNIQUE NOT NULL,
      target_brand TEXT NOT NULL,
      brand_name TEXT NOT NULL,
      cert_count INTEGER NOT NULL DEFAULT 1,
      earliest_issuance TEXT,
      latest_issuance TEXT,
      related_domains_json TEXT,
      risk_score INTEGER NOT NULL,
      severity TEXT NOT NULL,
      threat_type TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'NEW_THREAT_DETECTED',
      created_at TEXT NOT NULL
    )
  `);
  db.run(`CREATE INDEX IF NOT EXISTS idx_brandwatch_brand ON brandwatch_alerts(target_brand)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_brandwatch_status ON brandwatch_alerts(status)`);
});

/**
 * Upgrade a legacy users table to the salted-hash schema.
 *
 * Databases created by an earlier build have users(id, username, password, role)
 * storing passwords in cleartext. `CREATE TABLE IF NOT EXISTS` silently skips
 * such a table, so the mismatch surfaced only at login time as a crash inside
 * pbkdf2Sync (salt undefined) — an unauthenticated denial of service.
 *
 * The legacy role value 'sebi_admin' is normalized to 'admin' so it matches the
 * role names the authorization layer checks.
 */
function migrateLegacyUsers() {
  return new Promise((resolve) => {
    db.all(`PRAGMA table_info(users)`, (err, columns) => {
      if (err || !columns || columns.length === 0) return resolve(false);

      const names = columns.map((c) => c.name);
      const isLegacy = names.includes('password') && !names.includes('salt');
      if (!isLegacy) return resolve(false);

      console.log('[db] legacy users table detected (cleartext passwords) — migrating to PBKDF2 salted hashes');

      db.all(`SELECT id, username, password, role FROM users`, (readErr, legacyRows) => {
        if (readErr) return resolve(false);

        db.serialize(() => {
          db.run(`ALTER TABLE users RENAME TO users_legacy_backup`);
          db.run(`
            CREATE TABLE users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              salt TEXT NOT NULL,
              role TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
          `);

          for (const row of legacyRows || []) {
            const salt = crypto.randomBytes(16).toString('hex');
            const hash = crypto.pbkdf2Sync(row.password || '', salt, 210000, 64, 'sha512').toString('hex');
            // Normalize legacy role naming to the values the RBAC layer checks.
            const role = row.role === 'sebi_admin' ? 'admin' : row.role;

            db.run(
              `INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)`,
              [row.username, hash, salt, role, new Date().toISOString()]
            );
          }

          // Drop the backup so cleartext passwords do not linger on disk.
          db.run(`DROP TABLE users_legacy_backup`, (dropErr) => {
            if (dropErr) {
              console.error(`[db] could not drop legacy users backup: ${dropErr.message}`);
            }
            console.log(`[db] migrated ${(legacyRows || []).length} user(s) to salted PBKDF2 hashes`);
            resolve(true);
          });
        });
      });
    });
  });
}

/**
 * Upgrade a legacy `scans` table to the current schema.
 *
 * Databases created by an earlier build define the flags column as
 * `explanation TEXT NOT NULL` and `created_at REAL`. `CREATE TABLE IF NOT
 * EXISTS` skips such a table, so every INSERT from addScan failed with
 * "table scans has no column named flags_json" — silently, because addScan's
 * callback ignores the error and the route only reads `id`. The visible symptom
 * was an empty IOC graph despite apparently successful scans.
 *
 * Existing rows are preserved: `explanation` carries forward into `flags_json`
 * (it held the same JSON payload), and REAL epoch timestamps are converted to
 * ISO-8601 strings to match what every other table and the API contract use.
 */
function migrateLegacyScans() {
  return new Promise((resolve) => {
    db.all(`PRAGMA table_info(scans)`, (err, columns) => {
      if (err || !columns || columns.length === 0) return resolve(false);

      const names = columns.map((c) => c.name);
      const isLegacy = names.includes('explanation') && !names.includes('flags_json');
      if (!isLegacy) return resolve(false);

      console.log('[db] legacy scans table detected (explanation/REAL created_at) — migrating to flags_json');

      db.all(`SELECT * FROM scans ORDER BY id ASC`, (readErr, legacyRows) => {
        if (readErr) {
          console.error(`[db] could not read legacy scans: ${readErr.message}`);
          return resolve(false);
        }

        db.serialize(() => {
          db.run(`PRAGMA foreign_keys = OFF`);

          // legacy_alter_table = ON is required here. With modern ALTER TABLE
          // semantics, renaming `scans` also rewrites every *other* table's
          // foreign keys to point at the new name — so ioc_links.evidence_scan_id
          // would silently start referencing scans_legacy_backup, and every
          // insert would fail with "no such table" once the backup is dropped.
          db.run(`PRAGMA legacy_alter_table = ON`);
          db.run(`ALTER TABLE scans RENAME TO scans_legacy_backup`);
          db.run(`
            CREATE TABLE scans (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              content_type TEXT NOT NULL,
              text_or_filename TEXT NOT NULL,
              sender TEXT NOT NULL,
              channel TEXT NOT NULL,
              risk_score INTEGER NOT NULL,
              verdict TEXT NOT NULL,
              flags_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              user_id INTEGER REFERENCES users(id),
              source_ip TEXT,
              full_text TEXT,
              forensics_json TEXT,
              iocs_json TEXT,
              evidence_sha256 TEXT
            )
          `);

          const stmt = db.prepare(`
            INSERT INTO scans (id, content_type, text_or_filename, sender, channel, risk_score,
                               verdict, flags_json, created_at, user_id, source_ip, full_text,
                               forensics_json, iocs_json, evidence_sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `);

          for (const row of legacyRows || []) {
            // created_at was a REAL epoch (seconds or ms). Normalize to ISO.
            let createdAt = row.created_at;
            if (typeof createdAt === 'number') {
              const ms = createdAt < 1e12 ? createdAt * 1000 : createdAt;
              createdAt = new Date(ms).toISOString();
            } else if (!createdAt) {
              createdAt = new Date().toISOString();
            }

            stmt.run(
              row.id, row.content_type, row.text_or_filename,
              row.sender || 'Unknown', row.channel || 'unknown',
              row.risk_score, row.verdict,
              row.explanation || '[]', createdAt,
              row.user_id ?? null, row.source_ip ?? null, row.full_text ?? null,
              row.forensics_json ?? null, row.iocs_json ?? null, row.evidence_sha256 ?? null
            );
          }

          stmt.finalize(() => {
            db.run(`DROP TABLE scans_legacy_backup`, (dropErr) => {
              if (dropErr) console.error(`[db] could not drop legacy scans backup: ${dropErr.message}`);
              db.run(`PRAGMA legacy_alter_table = OFF`);
              db.run(`PRAGMA foreign_keys = ON`);
              console.log(`[db] migrated ${(legacyRows || []).length} scan row(s) to the current schema`);
              resolve(true);
            });
          });
        });
      });
    });
  });
}

/**
 * Seed default accounts when the users table is empty.
 * Runs after the legacy migration so it cannot race the rebuild above.
 */
function seedDefaultUsers() {
  return new Promise((resolve) => {
    db.get(`SELECT COUNT(*) as count FROM users`, (err, row) => {
      if (err || !row || row.count > 0) return resolve(false);

      const create = (username, password, role) => {
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.pbkdf2Sync(password, salt, 210000, 64, 'sha512').toString('hex');
        db.run(
          `INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)`,
          [username, hash, salt, role, new Date().toISOString()]
        );
      };

      // Development defaults. Documented in the README as requiring rotation
      // before any non-local deployment.
      create('admin', process.env.SEED_ADMIN_PASSWORD || 'sebi_admin_2026', 'admin');
      create('sebi', process.env.SEED_SEBI_PASSWORD || 'sebi_official_2026', 'admin');
      create('investor', process.env.SEED_INVESTOR_PASSWORD || 'investor123', 'investor');
      resolve(true);
    });
  });
}

/**
 * Migrate databases created before Phase 0, then build dependent indexes.
 *
 * Runs after the CREATE TABLE block so the tables exist on a fresh database.
 * Ordering matters: CREATE INDEX on a column added via ALTER TABLE must wait for
 * that ALTER to finish, or it fails with "no such column" on an existing
 * sentinel.db. Awaited sequentially for exactly that reason.
 */
const migrationsReady = (async () => {
  await migrateLegacyUsers();
  await seedDefaultUsers();

  // Must run before the ensureColumn calls below: the legacy rebuild recreates
  // the scans table with every current column already present.
  await migrateLegacyScans();

  await ensureColumn('scans', 'user_id', 'INTEGER REFERENCES users(id)');
  await ensureColumn('scans', 'source_ip', 'TEXT');
  await ensureColumn('scans', 'full_text', 'TEXT');
  await ensureColumn('scans', 'forensics_json', 'TEXT');
  await ensureColumn('scans', 'iocs_json', 'TEXT');
  await ensureColumn('scans', 'evidence_sha256', 'TEXT');
  await ensureColumn('takedowns', 'user_id', 'INTEGER REFERENCES users(id)');
  await ensureColumn('registered_communications', 'user_id', 'INTEGER REFERENCES users(id)');

  db.run(`CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)`, (err) => {
    if (err) console.error(`[db] index idx_scans_user failed: ${err.message}`);
  });
})();

/**
 * Serializes audit appends so concurrent requests cannot fork the hash chain
 * by reading the same tail row. See DBSqlite.appendAudit.
 */
let auditQueue = Promise.resolve();

/** Same rationale as auditQueue, for the evidence custody chain. */
let evidenceQueue = Promise.resolve();

class DBSqlite {
  // User Authentication Helper
  static getUserByUsername(username, callback) {
    db.get(`SELECT * FROM users WHERE username = ?`, [username], callback);
  }

  // Scans Helpers
  /**
   * Insert a scan row.
   *
   * Callers historically ignored the error argument, which meant a schema
   * mismatch failed silently and only surfaced downstream as missing data.
   * The error is logged here so a persistence failure is always visible even
   * when the caller does not check it.
   */
  static addScan(scan, callback) {
    const flagsJson = JSON.stringify(scan.flags || []);
    db.run(
      `INSERT INTO scans (content_type, text_or_filename, sender, channel, risk_score, verdict, flags_json, created_at, user_id, source_ip, full_text, forensics_json, iocs_json, evidence_sha256)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        scan.content_type,
        scan.text_or_filename,
        scan.sender,
        scan.channel,
        scan.risk_score,
        scan.verdict,
        flagsJson,
        scan.created_at || new Date().toISOString(),
        scan.user_id ?? null,
        scan.source_ip ?? null,
        // Phase 1 item 1C: full message text, no longer truncated to 120 chars.
        scan.full_text ?? null,
        scan.forensics ? JSON.stringify(scan.forensics) : null,
        scan.iocs ? JSON.stringify(scan.iocs) : null,
        scan.evidence_sha256 ?? null,
      ],
      function (err) {
        if (err) console.error(`[db] addScan failed: ${err.message}`);
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
      `INSERT OR REPLACE INTO takedowns (id, target_domain, scam_vpa, target_phone, threat_category, status, dot_dns_status, npci_vpa_status, date_str, legal_notice_text, user_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [takedown.id, takedown.target_domain, takedown.scam_vpa, takedown.target_phone, takedown.threat_category, takedown.status, takedown.dot_dns_status, takedown.npci_vpa_status, takedown.date_str, takedown.legal_notice_text, takedown.user_id ?? null],
      callback
    );
  }

  static updateTakedownStatus(id, status, callback) {
    db.run(`UPDATE takedowns SET status = ? WHERE id = ?`, [status, id], callback);
  }

  // Registered Communications
  static addRegisteredComm(record, callback) {
    db.run(
      `INSERT OR REPLACE INTO registered_communications (code, issuer_id, issuer_name, content_hash, created_at, user_id) VALUES (?, ?, ?, ?, ?, ?)`,
      [record.code, record.issuerId, record.issuerName, record.contentHash, record.createdAt || new Date().toISOString(), record.user_id ?? null],
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

  // ───────────────────────────── Audit Log ─────────────────────────────
  //
  // Appends are serialized through `auditQueue`. Two concurrent requests that
  // both read the same tail row would otherwise write two entries sharing one
  // prev_hash, forking the chain and making verification fail on valid data.

  /**
   * Append an audit entry. Resolves with { id, entry_hash }.
   *
   * Never rejects on a write failure — audit logging must not convert a
   * successful business operation into a client-visible error. Failures are
   * logged to stderr for the operator instead.
   */
  static appendAudit(entry) {
    const record = {
      actor_id: entry.actor_id ?? null,
      actor_username: Audit.clamp(entry.actor_username, 128) || 'anonymous',
      actor_role: Audit.clamp(entry.actor_role, 32) || 'anonymous',
      action: Audit.clamp(entry.action, 64) || 'UNKNOWN_ACTION',
      target_type: Audit.clamp(entry.target_type, 64),
      target_id: Audit.clamp(entry.target_id, 128),
      outcome: Audit.clamp(entry.outcome, 32) || 'SUCCESS',
      source_ip: Audit.clamp(entry.source_ip, 64),
      user_agent: Audit.clamp(entry.user_agent, 256),
      metadata_json: Audit.serializeMetadata(entry.metadata),
      created_at: entry.created_at || new Date().toISOString(),
    };

    auditQueue = auditQueue.then(
      () =>
        new Promise((resolve) => {
          db.get(`SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1`, (err, tail) => {
            record.prev_hash = !err && tail ? tail.entry_hash : Audit.GENESIS_HASH;
            const entryHash = Audit.computeHash(record);

            db.run(
              `INSERT INTO audit_log
                 (actor_id, actor_username, actor_role, action, target_type, target_id,
                  outcome, source_ip, user_agent, metadata_json, created_at, prev_hash, entry_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              [
                record.actor_id, record.actor_username, record.actor_role, record.action,
                record.target_type, record.target_id, record.outcome, record.source_ip,
                record.user_agent, record.metadata_json, record.created_at,
                record.prev_hash, entryHash,
              ],
              function (insertErr) {
                if (insertErr) {
                  console.error(`[audit] append failed for ${record.action}: ${insertErr.message}`);
                  return resolve({ id: null, entry_hash: null, error: insertErr.message });
                }
                resolve({ id: this.lastID, entry_hash: entryHash });
              }
            );
          });
        })
    );

    return auditQueue;
  }

  // ────────────────────── Evidence Chain of Custody ──────────────────────

  /**
   * Record a retained artifact (see evidence.js::retain) and chain it to the
   * previous artifact's hash. Resolves with { id, entry_hash }; never rejects,
   * for the same reason appendAudit never rejects — a custody-log failure must
   * not turn a successful upload into a client-visible error.
   */
  static addEvidenceArtifact(entry) {
    const record = {
      scan_id: entry.scan_id ?? null,
      sha256: entry.sha256,
      md5: entry.md5,
      size_bytes: entry.size_bytes,
      mime_type: entry.mime_type ?? null,
      original_filename: entry.original_filename ?? null,
      stored_path: entry.stored_path ?? null,
      user_id: entry.user_id ?? null,
      source_ip: entry.source_ip ?? null,
      created_at: entry.created_at || new Date().toISOString(),
    };

    evidenceQueue = evidenceQueue.then(
      () =>
        new Promise((resolve) => {
          db.get(`SELECT entry_hash FROM evidence_artifacts ORDER BY id DESC LIMIT 1`, (err, tail) => {
            record.prev_hash = !err && tail ? tail.entry_hash : Evidence.GENESIS_HASH;
            const entryHash = Evidence.computeEntryHash(record);

            db.run(
              `INSERT INTO evidence_artifacts
                 (scan_id, sha256, md5, size_bytes, mime_type, original_filename,
                  stored_path, user_id, source_ip, created_at, prev_hash, entry_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              [
                record.scan_id, record.sha256, record.md5, record.size_bytes,
                record.mime_type, record.original_filename, record.stored_path,
                record.user_id, record.source_ip, record.created_at,
                record.prev_hash, entryHash,
              ],
              function (insertErr) {
                if (insertErr) {
                  console.error(`[evidence] append failed for ${record.sha256}: ${insertErr.message}`);
                  return resolve({ id: null, entry_hash: null, error: insertErr.message });
                }
                resolve({ id: this.lastID, entry_hash: entryHash });
              }
            );
          });
        })
    );

    return evidenceQueue;
  }

  static getEvidenceBySha256(sha256, callback) {
    db.all(`SELECT * FROM evidence_artifacts WHERE sha256 = ? ORDER BY id ASC`, [sha256], callback);
  }

  static getEvidenceForScan(scanId, callback) {
    db.all(`SELECT * FROM evidence_artifacts WHERE scan_id = ?`, [scanId], callback);
  }

  static verifyEvidenceChain(callback) {
    db.all(`SELECT * FROM evidence_artifacts ORDER BY id ASC`, (err, rows) => {
      if (err) return callback(err);

      let expectedPrev = Evidence.GENESIS_HASH;
      for (const row of rows || []) {
        if (row.prev_hash !== expectedPrev) {
          return callback(null, {
            valid: false, entriesChecked: rows.length, brokenAtId: row.id,
            reason: 'PREV_HASH_MISMATCH',
            detail: `Artifact ${row.id} expected prev_hash ${expectedPrev.slice(0, 12)}… but stored ${String(row.prev_hash).slice(0, 12)}….`,
          });
        }
        const recomputed = Evidence.computeEntryHash(row);
        if (recomputed !== row.entry_hash) {
          return callback(null, {
            valid: false, entriesChecked: rows.length, brokenAtId: row.id,
            reason: 'ENTRY_HASH_MISMATCH',
            detail: `Artifact ${row.id} content does not match its stored hash.`,
          });
        }
        expectedPrev = row.entry_hash;
      }

      callback(null, {
        valid: true,
        entriesChecked: (rows || []).length,
        headHash: expectedPrev === Evidence.GENESIS_HASH ? null : expectedPrev,
      });
    });
  }

  // ───────────────────── Phase 2: IOC Graph & Campaigns ─────────────────────

  /**
   * Upsert an IOC node. Resolves with its row id.
   *
   * Re-sighting an existing indicator bumps sighting_count, refreshes last_seen,
   * and raises max_risk_score — it does not create a duplicate row. Confidence
   * grows with corroboration (more independent sightings = more confidence),
   * capped so a single noisy extractor cannot drive it to certainty.
   */
  static upsertIoc({ type, value, riskScore = 0, seenAt }) {
    const now = seenAt || new Date().toISOString();

    return new Promise((resolve) => {
      db.run(
        `INSERT INTO iocs (type, value, first_seen, last_seen, sighting_count, confidence, max_risk_score)
         VALUES (?, ?, ?, ?, 1, 50, ?)
         ON CONFLICT(type, value) DO UPDATE SET
           last_seen = excluded.last_seen,
           sighting_count = sighting_count + 1,
           confidence = MIN(95, confidence + 5),
           max_risk_score = MAX(max_risk_score, excluded.max_risk_score)`,
        [type, value, now, now, riskScore],
        (err) => {
          if (err) {
            console.error(`[graph] upsertIoc failed for ${type}:${value} — ${err.message}`);
            return resolve(null);
          }
          // lastID is unreliable for an upsert that took the UPDATE path, so
          // read the id back explicitly.
          db.get(`SELECT id FROM iocs WHERE type = ? AND value = ?`, [type, value], (selErr, row) => {
            resolve(!selErr && row ? row.id : null);
          });
        }
      );
    });
  }

  static linkIocs({ sourceIocId, targetIocId, relationship, evidenceScanId, seenAt }) {
    if (!sourceIocId || !targetIocId || sourceIocId === targetIocId) return Promise.resolve(false);
    const now = seenAt || new Date().toISOString();

    return new Promise((resolve) => {
      db.run(
        `INSERT INTO ioc_links (source_ioc_id, target_ioc_id, relationship, evidence_scan_id, confidence, first_seen)
         VALUES (?, ?, ?, ?, 60, ?)
         ON CONFLICT(source_ioc_id, target_ioc_id, relationship) DO UPDATE SET
           confidence = MIN(95, confidence + 5)`,
        [sourceIocId, targetIocId, relationship, evidenceScanId ?? null, now],
        (err) => {
          if (err) console.error(`[graph] linkIocs failed — ${err.message}`);
          resolve(!err);
        }
      );
    });
  }

  static linkScanToIoc(scanId, iocId, seenAt) {
    if (!scanId || !iocId) return Promise.resolve(false);
    return new Promise((resolve) => {
      db.run(
        `INSERT OR IGNORE INTO scan_iocs (scan_id, ioc_id, created_at) VALUES (?, ?, ?)`,
        [scanId, iocId, seenAt || new Date().toISOString()],
        (err) => resolve(!err)
      );
    });
  }

  /**
   * Persist a scan's whole graph contribution: nodes, scan↔node links, and edges.
   * Resolves with a summary so the caller can put counts in the audit metadata.
   *
   * Never rejects — graph ingestion is secondary to returning the scan verdict,
   * so a failure here is logged rather than surfaced to the client.
   */
  static async ingestScanGraph({ scanId, nodes = [], edges = [], seenAt }) {
    const now = seenAt || new Date().toISOString();
    const idByKey = new Map();

    try {
      for (const node of nodes) {
        const id = await this.upsertIoc({
          type: node.type, value: node.value, riskScore: node.riskScore || 0, seenAt: now,
        });
        if (id) {
          idByKey.set(`${node.type}:${node.value}`, id);
          await this.linkScanToIoc(scanId, id, now);
        }
      }

      let edgesWritten = 0;
      for (const edge of edges) {
        const sourceId = idByKey.get(`${edge.source.type}:${edge.source.value}`);
        const targetId = idByKey.get(`${edge.target.type}:${edge.target.value}`);
        const ok = await this.linkIocs({
          sourceIocId: sourceId, targetIocId: targetId,
          relationship: edge.relationship, evidenceScanId: scanId, seenAt: now,
        });
        if (ok) edgesWritten++;
      }

      return { nodesWritten: idByKey.size, edgesWritten };
    } catch (err) {
      console.error(`[graph] ingestScanGraph failed for scan ${scanId}: ${err.message}`);
      return { nodesWritten: 0, edgesWritten: 0, error: err.message };
    }
  }

  /**
   * Read the whole graph for visualization. Returns nodes with their sighting
   * counts and edges with their evidencing scan.
   *
   * `minRisk` lets the console show only indicators from scans that actually
   * scored as risky, so a benign-but-mentioned domain does not clutter the view.
   */
  static getIocGraph({ minRisk = 0, limit = 500 } = {}, callback) {
    db.all(
      `SELECT * FROM iocs WHERE max_risk_score >= ? ORDER BY sighting_count DESC, id ASC LIMIT ?`,
      [minRisk, Math.min(Number(limit) || 500, 2000)],
      (err, nodes) => {
        if (err) return callback(err);

        const ids = (nodes || []).map((n) => n.id);
        if (ids.length === 0) return callback(null, { nodes: [], links: [] });

        const placeholders = ids.map(() => '?').join(',');
        db.all(
          `SELECT * FROM ioc_links
           WHERE source_ioc_id IN (${placeholders}) AND target_ioc_id IN (${placeholders})`,
          [...ids, ...ids],
          (linkErr, links) => {
            if (linkErr) return callback(linkErr);
            callback(null, { nodes: nodes || [], links: links || [] });
          }
        );
      }
    );
  }

  static getIocByValue(type, value, callback) {
    db.get(`SELECT * FROM iocs WHERE type = ? AND value = ?`, [type, value], callback);
  }

  /** Every scan that sighted a given indicator — the "how do you know" query. */
  static getScansForIoc(iocId, callback) {
    db.all(
      `SELECT s.id, s.content_type, s.sender, s.channel, s.risk_score, s.verdict, s.created_at
       FROM scans s
       JOIN scan_iocs si ON si.scan_id = s.id
       WHERE si.ioc_id = ?
       ORDER BY s.id DESC`,
      [iocId],
      callback
    );
  }

  /**
   * Recompute campaigns as connected components of the IOC graph.
   *
   * Full recompute rather than incremental update: clustering is not
   * incrementally stable (one new edge can merge two existing campaigns), and
   * at the data volumes this system handles a rebuild is cheap and always
   * correct. If the graph grows to where this is slow, the fix is incremental
   * union-find with periodic reconciliation, not partial updates here.
   */
  static rebuildCampaigns(callback) {
    const Graph = require('./engines/graph_engine');

    db.all(`SELECT id, type, value, max_risk_score, first_seen, last_seen FROM iocs`, (err, iocRows) => {
      if (err) return callback(err);
      if (!iocRows || iocRows.length === 0) return callback(null, { campaigns: 0, clustered: 0 });

      db.all(`SELECT source_ioc_id, target_ioc_id FROM ioc_links`, (linkErr, linkRows) => {
        if (linkErr) return callback(linkErr);

        const adjacency = new Map();
        for (const row of iocRows) adjacency.set(row.id, []);
        for (const link of linkRows || []) {
          if (adjacency.has(link.source_ioc_id) && adjacency.has(link.target_ioc_id)) {
            adjacency.get(link.source_ioc_id).push(link.target_ioc_id);
            adjacency.get(link.target_ioc_id).push(link.source_ioc_id);
          }
        }

        const iocById = new Map(iocRows.map((r) => [r.id, r]));
        const components = Graph.findConnectedComponents(
          iocRows.map((r) => r.id),
          adjacency
        );

        // Only clusters of 2+ linked indicators are campaigns. A lone indicator
        // is an observation, not an operation — labelling it a "campaign" would
        // inflate the numbers a reviewer sees.
        const realCampaigns = components.filter((c) => c.length >= 2);

        db.serialize(() => {
          db.run(`DELETE FROM campaign_members`);
          db.run(`DELETE FROM campaigns`, (delErr) => {
            if (delErr) return callback(delErr);
            if (realCampaigns.length === 0) return callback(null, { campaigns: 0, clustered: 0 });

            let remaining = realCampaigns.length;
            let clustered = 0;
            const now = new Date().toISOString();

            for (const component of realCampaigns) {
              const members = component.map((id) => iocById.get(id)).filter(Boolean);
              const label = Graph.labelForCampaign(members);
              const maxRisk = Math.max(...members.map((m) => m.max_risk_score || 0));
              const firstSeen = members.map((m) => m.first_seen).filter(Boolean).sort()[0] || null;
              const lastSeen = members.map((m) => m.last_seen).filter(Boolean).sort().pop() || null;

              db.run(
                `INSERT INTO campaigns (label, cluster_method, member_count, max_risk_score, first_seen, last_seen, status, created_at)
                 VALUES (?, 'connected_components', ?, ?, ?, ?, 'ACTIVE', ?)`,
                [label, members.length, maxRisk, firstSeen, lastSeen, now],
                function (insErr) {
                  if (insErr) {
                    console.error(`[graph] campaign insert failed: ${insErr.message}`);
                    if (--remaining === 0) callback(null, { campaigns: realCampaigns.length, clustered });
                    return;
                  }

                  const campaignId = this.lastID;
                  clustered += members.length;

                  const stmt = db.prepare(`INSERT OR IGNORE INTO campaign_members (campaign_id, ioc_id) VALUES (?, ?)`);
                  for (const member of members) stmt.run(campaignId, member.id);
                  stmt.finalize(() => {
                    if (--remaining === 0) callback(null, { campaigns: realCampaigns.length, clustered });
                  });
                }
              );
            }
          });
        });
      });
    });
  }

  static getCampaigns(callback) {
    db.all(
      `SELECT * FROM campaigns ORDER BY max_risk_score DESC, member_count DESC`,
      [],
      callback
    );
  }

  static getCampaignDetail(campaignId, callback) {
    db.get(`SELECT * FROM campaigns WHERE id = ?`, [campaignId], (err, campaign) => {
      if (err) return callback(err);
      if (!campaign) return callback(null, null);

      db.all(
        `SELECT i.* FROM iocs i
         JOIN campaign_members cm ON cm.ioc_id = i.id
         WHERE cm.campaign_id = ?
         ORDER BY i.sighting_count DESC`,
        [campaignId],
        (memberErr, members) => {
          if (memberErr) return callback(memberErr);

          const ids = (members || []).map((m) => m.id);
          if (ids.length === 0) return callback(null, { ...campaign, members: [], scans: [] });

          const placeholders = ids.map(() => '?').join(',');
          db.all(
            `SELECT DISTINCT s.id, s.content_type, s.sender, s.risk_score, s.verdict, s.created_at
             FROM scans s JOIN scan_iocs si ON si.scan_id = s.id
             WHERE si.ioc_id IN (${placeholders})
             ORDER BY s.id DESC`,
            ids,
            (scanErr, scans) => {
              callback(null, { ...campaign, members: members || [], scans: scans || [] });
            }
          );
        }
      );
    });
  }

  static getGraphStats(callback) {
    db.get(`SELECT COUNT(*) AS iocCount FROM iocs`, (err, iocRow) => {
      db.get(`SELECT COUNT(*) AS linkCount FROM ioc_links`, (e2, linkRow) => {
        db.get(`SELECT COUNT(*) AS campaignCount FROM campaigns`, (e3, campRow) => {
          db.all(`SELECT type, COUNT(*) AS count FROM iocs GROUP BY type ORDER BY count DESC`, (e4, typeRows) => {
            callback(null, {
              iocCount: iocRow?.iocCount || 0,
              linkCount: linkRow?.linkCount || 0,
              campaignCount: campRow?.campaignCount || 0,
              byType: typeRows || [],
            });
          });
        });
      });
    });
  }

  // ───────────────────── Phase 3: Enrichment Cache ─────────────────────

  /**
   * Read a cached lookup, or null when absent or expired.
   * Expiry is checked in JS rather than SQL so the caller can distinguish
   * "never fetched" from "fetched but stale" if that becomes useful.
   */
  static getEnrichment(indicatorType, indicatorValue, source, callback) {
    db.get(
      `SELECT * FROM enrichment_cache WHERE indicator_type = ? AND indicator_value = ? AND source = ?`,
      [indicatorType, indicatorValue, source],
      (err, row) => {
        if (err || !row) return callback(err || null, null);
        if (Date.parse(row.expires_at) < Date.now()) return callback(null, null);

        let payload = null;
        try { payload = JSON.parse(row.payload_json); } catch { /* corrupt row reads as a miss */ }
        callback(null, payload ? { ...row, payload } : null);
      }
    );
  }

  static putEnrichment({ indicatorType, indicatorValue, source, payload, ttlHours = 24 }) {
    const now = new Date();
    const expires = new Date(now.getTime() + ttlHours * 3600 * 1000);

    return new Promise((resolve) => {
      db.run(
        `INSERT INTO enrichment_cache (indicator_type, indicator_value, source, payload_json, retrieved_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(indicator_type, indicator_value, source) DO UPDATE SET
           payload_json = excluded.payload_json,
           retrieved_at = excluded.retrieved_at,
           expires_at = excluded.expires_at`,
        [indicatorType, indicatorValue, source, JSON.stringify(payload), now.toISOString(), expires.toISOString()],
        (err) => {
          if (err) console.error(`[enrichment] cache write failed for ${indicatorValue}: ${err.message}`);
          resolve(!err);
        }
      );
    });
  }

  static getEnrichmentStats(callback) {
    db.get(`SELECT COUNT(*) AS cached FROM enrichment_cache`, (err, row) => {
      db.all(`SELECT source, COUNT(*) AS count FROM enrichment_cache GROUP BY source`, (e2, rows) => {
        callback(null, { cachedEntries: row?.cached || 0, bySource: rows || [] });
      });
    });
  }

  // ───────────────────── Phase 4: Fingerprints ─────────────────────

  static addFingerprint({ scanId, kind, vector, hashValue, dimensions }) {
    return new Promise((resolve) => {
      db.run(
        `INSERT INTO fingerprints (scan_id, kind, vector_json, hash_value, dimensions, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          scanId ?? null, kind,
          vector ? JSON.stringify(vector) : null,
          hashValue ?? null, dimensions ?? null,
          new Date().toISOString(),
        ],
        function (err) {
          if (err) {
            console.error(`[fingerprint] insert failed (${kind}): ${err.message}`);
            return resolve(null);
          }
          resolve(this.lastID);
        }
      );
    });
  }

  static getFingerprintsByKind(kind, callback) {
    db.all(`SELECT * FROM fingerprints WHERE kind = ? ORDER BY id ASC`, [kind], callback);
  }

  static recordFingerprintMatch({ kind, a, b, score, threshold, method }) {
    // Order the pair so (a,b) and (b,a) collapse to one row under the UNIQUE
    // constraint rather than being stored twice.
    const [lo, hi] = a <= b ? [a, b] : [b, a];

    return new Promise((resolve) => {
      db.run(
        `INSERT OR IGNORE INTO fingerprint_matches (kind, fingerprint_a, fingerprint_b, score, threshold, method, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [kind, lo, hi, score, threshold, method, new Date().toISOString()],
        (err) => {
          if (err) console.error(`[fingerprint] match insert failed: ${err.message}`);
          resolve(!err);
        }
      );
    });
  }

  static getFingerprintMatches(callback) {
    db.all(
      `SELECT m.*, fa.scan_id AS scan_a, fb.scan_id AS scan_b
       FROM fingerprint_matches m
       JOIN fingerprints fa ON fa.id = m.fingerprint_a
       JOIN fingerprints fb ON fb.id = m.fingerprint_b
       ORDER BY m.score DESC`,
      [],
      callback
    );
  }

  static getAuditLog({ limit = 100, offset = 0, action, actor } = {}, callback) {
    const where = [];
    const params = [];
    if (action) { where.push('action = ?'); params.push(action); }
    if (actor) { where.push('actor_username = ?'); params.push(actor); }

    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    params.push(Math.min(Number(limit) || 100, 1000), Number(offset) || 0);

    db.all(`SELECT * FROM audit_log ${clause} ORDER BY id DESC LIMIT ? OFFSET ?`, params, callback);
  }

  /**
   * Recompute the chain and report the first break, if any.
   *
   * Reads the whole table, so this is an on-demand integrity check rather than
   * something to call per request. At Phase 0 log volumes that is fine; if the
   * log grows large this wants checkpointing.
   */
  static verifyAuditChain(callback) {
    db.all(`SELECT * FROM audit_log ORDER BY id ASC`, (err, rows) => {
      if (err) return callback(err);

      let expectedPrev = Audit.GENESIS_HASH;

      for (const row of rows || []) {
        if (row.prev_hash !== expectedPrev) {
          return callback(null, {
            valid: false,
            entriesChecked: rows.length,
            brokenAtId: row.id,
            reason: 'PREV_HASH_MISMATCH',
            detail: `Entry ${row.id} expected prev_hash ${expectedPrev.slice(0, 12)}… but stored ${String(row.prev_hash).slice(0, 12)}…. An entry was altered or removed.`,
          });
        }

        const recomputed = Audit.computeHash(row);
        if (recomputed !== row.entry_hash) {
          return callback(null, {
            valid: false,
            entriesChecked: rows.length,
            brokenAtId: row.id,
            reason: 'ENTRY_HASH_MISMATCH',
            detail: `Entry ${row.id} content does not match its stored hash. The row was modified in place.`,
          });
        }

        expectedPrev = row.entry_hash;
      }

      callback(null, {
        valid: true,
        entriesChecked: (rows || []).length,
        headHash: expectedPrev === Audit.GENESIS_HASH ? null : expectedPrev,
        note: 'Chain is internally consistent. This does not prove the log was not rewritten wholesale; that requires an external timestamp anchor.',
      });
    });
  }

  // ─────────────────── Brand Watch Accessors ───────────────────
  static addBrandwatchAlert(alert, callback) {
    const query = `
      INSERT INTO brandwatch_alerts (
        domain_variant, target_brand, brand_name, cert_count,
        earliest_issuance, latest_issuance, related_domains_json,
        risk_score, severity, threat_type, status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(domain_variant) DO UPDATE SET
        cert_count = excluded.cert_count,
        latest_issuance = excluded.latest_issuance,
        risk_score = excluded.risk_score,
        status = excluded.status
    `;
    const params = [
      alert.domain_variant,
      alert.target_brand,
      alert.brand_name || alert.target_brand,
      alert.cert_count || 1,
      alert.earliest_issuance || new Date().toISOString(),
      alert.latest_issuance || new Date().toISOString(),
      JSON.stringify(alert.related_domains || []),
      alert.risk_score || 85,
      alert.severity || 'high',
      alert.threat_type || 'Proactive CT-Log Typosquat Infrastructure',
      alert.status || 'NEW_THREAT_DETECTED',
      alert.created_at || new Date().toISOString(),
    ];

    db.run(query, params, function (err) {
      if (callback) callback(err, this ? this.lastID : null);
    });
  }

  static getBrandwatchAlerts(callback) {
    db.all(`SELECT * FROM brandwatch_alerts ORDER BY created_at DESC LIMIT 100`, (err, rows) => {
      if (err) return callback(err);
      const parsed = (rows || []).map((r) => ({
        ...r,
        related_domains: r.related_domains_json ? JSON.parse(r.related_domains_json) : [],
      }));
      callback(null, parsed);
    });
  }

  /**
   * Reset the database to a clean baseline state.
   *
   * Deletes all user-generated data (scans, IOCs, campaigns, alerts, takedowns,
   * social posts, registered communications, enrichment cache, fingerprints, and
   * brandwatch alerts) and re-seeds the default seed rows. The audit log and
   * evidence artifacts are intentionally NOT cleared — they are the chain of
   * custody and clearing them would constitute evidence destruction.
   *
   * The SYSTEM_RESET audit entry is written before the truncation begins, so
   * the actor and timestamp are preserved even in the reset state.
   *
   * @param {function} callback - (err, result) where result.tablesCleared is
   *   the number of tables truncated.
   */
  static resetDatabase(callback) {
    const tablesToClear = [
      'campaign_members',
      'campaigns',
      'scan_iocs',
      'ioc_links',
      'iocs',
      'fingerprint_matches',
      'fingerprints',
      'enrichment_cache',
      'social_posts',
      'brandwatch_alerts',
      'scans',
      'threat_alerts',
      'takedowns',
      'registered_communications',
    ];

    db.serialize(() => {
      db.run('PRAGMA foreign_keys = OFF');

      let cleared = 0;
      let errored = null;

      for (const table of tablesToClear) {
        db.run(`DELETE FROM ${table}`, (err) => {
          if (err) {
            console.error(`[reset] failed to clear ${table}: ${err.message}`);
            errored = err;
          } else {
            cleared++;
          }
        });
      }

      // Re-seed the two baseline threat_alerts rows after clearing
      db.run(`
        INSERT INTO threat_alerts (title, description, severity, date_str, upi_id, domain)
        VALUES
          ('Fake Telegram Stock Tip Group Flagged', 'Scammers impersonating SEBI registered research analysts offering 500% guaranteed returns.', 'high', '2026-07-22', 'invest.now@oksbi', 'sebi-official-tips.xyz'),
          ('Spoofed Broker Settlement Emails Detected', 'Phishing campaign spoofing Zerodha contract notes to steal trading credentials.', 'critical', '2026-07-21', 'settlement@paytm', 'broker-zerodha.online')
      `);

      // Re-seed the baseline takedown row
      db.run(`
        INSERT INTO takedowns (id, target_domain, scam_vpa, target_phone, threat_category, status, dot_dns_status, npci_vpa_status, date_str, legal_notice_text)
        VALUES ('CERT-IN-1721642400000', 'sebi-official-tips.xyz', 'invest.now@oksbi', '+91 9876543210', 'Securities Market Impersonation Fraud', 'DISPATCHED_TO_DOT_NPCI', 'BLOCKED_BY_DOT', 'FROZEN_BY_NPCI', '2026-07-22', 'CERT-In Incident Report Sec 70B IT Act 2000')
      `);

      db.run('PRAGMA foreign_keys = ON', () => {
        if (errored) return callback(errored);
        callback(null, { tablesCleared: tablesToClear.length, reseeded: true });
      });
    });
  }
}

// Resolves once Phase 0 column migrations have been applied. Tests await this
// instead of sleeping on a fixed timer.
DBSqlite.ready = migrationsReady;

module.exports = DBSqlite;
