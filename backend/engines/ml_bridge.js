/**
 * Python ML Bridge — Persistent subprocess with stdin/stdout JSON-RPC.
 *
 * On first call, spawns `python3 ml_service.py --serve` as a long-running
 * child process. Subsequent calls send JSON requests to stdin and read JSON
 * responses from stdout — no library reload between calls.
 *
 * Falls back gracefully to a cold-start execFile if:
 *  - Python is not installed
 *  - The persistent process crashes and cannot be restarted
 *  - The service is not available
 */

const { spawn, execFile } = require('child_process');
const path = require('path');
const readline = require('readline');

const ML_SERVICE_PATH = path.join(__dirname, '..', 'ml_service.py');
const PYTHON_CMD = process.platform === 'win32' ? 'python' : 'python3';
const TIMEOUT_MS = 30000; // 30 second timeout for ML analysis
const RESTART_DELAY_MS = 2000;
const MAX_RESTART_ATTEMPTS = 3;

let persistentProcess = null;
let responseReader = null;
let pendingRequests = new Map(); // id -> { resolve, timer }
let nextRequestId = 1;
let serviceReady = false;
let startAttempts = 0;
let starting = false;

/**
 * Start the persistent Python subprocess.
 * Returns a promise that resolves when the process signals readiness.
 */
function startPersistentProcess() {
  if (starting) return;
  starting = true;

  return new Promise((resolve) => {
    try {
      const proc = spawn(PYTHON_CMD, [ML_SERVICE_PATH, '--serve'], {
        stdio: ['pipe', 'pipe', 'pipe'],
        // Don't let the child keep the parent alive
        detached: false,
      });

      proc.on('error', (err) => {
        console.error(`[ml_bridge] Failed to start Python ML service: ${err.message}`);
        persistentProcess = null;
        serviceReady = false;
        starting = false;
        resolve(false);
      });

      proc.on('exit', (code, signal) => {
        console.error(`[ml_bridge] Python ML service exited (code=${code}, signal=${signal})`);
        persistentProcess = null;
        serviceReady = false;
        starting = false;

        // Reject any pending requests
        for (const [id, pending] of pendingRequests) {
          clearTimeout(pending.timer);
          pending.resolve({
            success: false,
            engine: 'python_ml_bridge',
            error: 'Python ML service process exited unexpectedly',
            fallback: true,
          });
        }
        pendingRequests.clear();

        // Auto-restart if we haven't exceeded attempts
        if (startAttempts < MAX_RESTART_ATTEMPTS) {
          setTimeout(() => startPersistentProcess(), RESTART_DELAY_MS);
        }
      });

      // Read stdout line by line for JSON responses
      const rl = readline.createInterface({ input: proc.stdout, crlfDelay: Infinity });

      rl.on('line', (line) => {
        const trimmed = line.trim();
        if (!trimmed) return;

        try {
          const data = JSON.parse(trimmed);

          // First message is the readiness signal
          if (data.ready && !serviceReady) {
            serviceReady = true;
            persistentProcess = proc;
            responseReader = rl;
            startAttempts = 0;
            starting = false;
            console.log('[ml_bridge] Python ML service ready (persistent mode)');
            resolve(true);
            return;
          }

          // Correlated response
          const reqId = data.id;
          if (reqId !== undefined && pendingRequests.has(reqId)) {
            const pending = pendingRequests.get(reqId);
            clearTimeout(pending.timer);
            pendingRequests.delete(reqId);
            pending.resolve(data);
          }
        } catch (parseErr) {
          // Non-JSON output from Python (e.g. warnings) — ignore
        }
      });

      // Capture stderr for debugging
      proc.stderr.on('data', (chunk) => {
        const msg = chunk.toString().trim();
        if (msg) console.error(`[ml_bridge:stderr] ${msg}`);
      });

      // Timeout for initial startup
      setTimeout(() => {
        if (!serviceReady) {
          starting = false;
          startAttempts++;
          resolve(false);
        }
      }, 10000);

    } catch (err) {
      starting = false;
      resolve(false);
    }
  });
}

/**
 * Send a request to the persistent Python process.
 */
function sendPersistentRequest(mode, filePath) {
  return new Promise((resolve) => {
    if (!persistentProcess || !serviceReady) {
      resolve(null); // Caller should fall back
      return;
    }

    const id = nextRequestId++;
    const request = { id, mode };
    if (filePath) request.filepath = filePath;

    const timer = setTimeout(() => {
      pendingRequests.delete(id);
      resolve({
        success: false,
        engine: 'python_ml_bridge',
        error: `ML analysis timed out after ${TIMEOUT_MS}ms`,
        fallback: true,
      });
    }, TIMEOUT_MS);

    pendingRequests.set(id, { resolve, timer });

    try {
      persistentProcess.stdin.write(JSON.stringify(request) + '\n');
    } catch (writeErr) {
      clearTimeout(timer);
      pendingRequests.delete(id);
      resolve(null);
    }
  });
}

/**
 * Cold-start fallback — original execFile behavior for when persistent mode
 * is unavailable.
 */
function callPythonMLColdStart(mode, filePath) {
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
 * Call the Python ML service with a mode and file path.
 * Tries persistent subprocess first, falls back to cold-start.
 *
 * @param {'audio'|'image'|'video'|'status'} mode
 * @param {string} [filePath] — absolute path to media file
 * @returns {Promise<object>} — parsed JSON result from Python
 */
async function callPythonML(mode, filePath) {
  // Try to start persistent process if not running
  if (!persistentProcess && !starting && startAttempts < MAX_RESTART_ATTEMPTS) {
    await startPersistentProcess();
  }

  // Try persistent mode
  if (persistentProcess && serviceReady) {
    const result = await sendPersistentRequest(mode, filePath);
    if (result !== null) return result;
  }

  // Fall back to cold-start
  return callPythonMLColdStart(mode, filePath);
}

/**
 * Check if Python ML service is available and which libraries are installed.
 */
async function checkMLStatus() {
  const result = await callPythonML('status');
  // Add persistent mode info
  result.persistentMode = serviceReady;
  result.coldStartFallback = !serviceReady;
  return result;
}

module.exports = { callPythonML, checkMLStatus };
