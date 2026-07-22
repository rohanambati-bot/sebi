/**
 * Python ML Bridge — Calls ml_service.py from Node.js via child_process.
 * Falls back gracefully if Python or ML libraries are unavailable.
 */

const { execFile } = require('child_process');
const path = require('path');

const ML_SERVICE_PATH = path.join(__dirname, '..', 'ml_service.py');
const PYTHON_CMD = process.platform === 'win32' ? 'python' : 'python3';
const TIMEOUT_MS = 30000; // 30 second timeout for ML analysis

/**
 * Call the Python ML service with a mode and file path.
 * @param {'audio'|'image'|'video'|'status'} mode
 * @param {string} [filePath] — absolute path to media file
 * @returns {Promise<object>} — parsed JSON result from Python
 */
function callPythonML(mode, filePath) {
  return new Promise((resolve) => {
    const args = [ML_SERVICE_PATH, mode];
    if (filePath) args.push(filePath);

    execFile(PYTHON_CMD, args, { timeout: TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) {
        resolve({
          success: false,
          engine: 'python_ml_bridge',
          error: `Python ML service unavailable: ${error.message}`,
          stderr: stderr?.trim() || '',
          fallback: true,
        });
        return;
      }

      try {
        const result = JSON.parse(stdout.trim());
        resolve(result);
      } catch (parseErr) {
        resolve({
          success: false,
          engine: 'python_ml_bridge',
          error: `Failed to parse ML service output: ${parseErr.message}`,
          rawOutput: stdout?.substring(0, 500),
          fallback: true,
        });
      }
    });
  });
}

/**
 * Check if Python ML service is available and which libraries are installed.
 */
async function checkMLStatus() {
  return callPythonML('status');
}

module.exports = { callPythonML, checkMLStatus };
