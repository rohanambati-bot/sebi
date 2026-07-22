const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data/db.json');

class DBManager {
  static load() {
    try {
      if (!fs.existsSync(DB_PATH)) {
        return {
          scans: [],
          threatAlerts: [],
          takedowns: [],
          registeredCommunications: [],
          socialPosts: []
        };
      }
      const raw = fs.readFileSync(DB_PATH, 'utf8');
      return JSON.parse(raw);
    } catch (err) {
      console.error('Error loading DB, resetting to default:', err);
      return {
        scans: [],
        threatAlerts: [],
        takedowns: [],
        registeredCommunications: [],
        socialPosts: []
      };
    }
  }

  static save(data) {
    try {
      const dir = path.dirname(DB_PATH);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
      return true;
    } catch (err) {
      console.error('Error saving DB:', err);
      return false;
    }
  }
}

module.exports = DBManager;
