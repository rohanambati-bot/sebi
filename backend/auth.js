/**
 * SentinelSEBI — Authentication & Authorization Middleware
 *
 * Phase 0 (Trust Foundation) items 0.1 / 0.5 / 0.6.
 *
 * Exposes:
 *   - JWT_SECRET            resolved secret (fails closed in production)
 *   - signToken(user)       issue a 24h access token
 *   - requireAuth           reject unless a valid token is present
 *   - requireRole(...roles) reject unless the token carries an allowed role
 *   - attachUser            populate req.user when a token is present, else anonymous
 *
 * Design note: `attachUser` exists so that investor-facing scan endpoints stay
 * usable without a login while still recording an actor when one is known.
 * Regulatory endpoints that emit legal notices use requireRole('admin').
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const TOKEN_TTL = '24h';

/**
 * Resolve the JWT signing secret.
 *
 * A hardcoded fallback secret in source control makes token verification
 * worthless, so production refuses to start without JWT_SECRET. Development
 * gets a random per-process secret (tokens simply do not survive a restart).
 */
function resolveSecret() {
  const fromEnv = process.env.JWT_SECRET;

  if (fromEnv && fromEnv.length >= 32) return fromEnv;

  if (process.env.NODE_ENV === 'production') {
    if (!fromEnv) {
      throw new Error(
        'JWT_SECRET is required when NODE_ENV=production. Refusing to start with an insecure default.'
      );
    }
    throw new Error(
      `JWT_SECRET must be at least 32 characters (received ${fromEnv.length}). Refusing to start.`
    );
  }

  if (fromEnv) {
    console.warn(
      `[auth] WARNING: JWT_SECRET is only ${fromEnv.length} chars; 32+ required in production.`
    );
    return fromEnv;
  }

  console.warn(
    '[auth] WARNING: JWT_SECRET not set. Using an ephemeral random secret for this process.\n' +
    '[auth]          Tokens will be invalidated on restart. Set JWT_SECRET for stable sessions.'
  );
  return crypto.randomBytes(48).toString('hex');
}

const JWT_SECRET = resolveSecret();

function signToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: TOKEN_TTL }
  );
}

/** Pull a bearer token out of the Authorization header. */
function extractToken(req) {
  const header = req.headers['authorization'] || '';
  const [scheme, token] = header.split(' ');
  if (!token || !/^Bearer$/i.test(scheme)) return null;
  return token.trim() || null;
}

const ANONYMOUS = Object.freeze({
  id: null,
  username: 'anonymous',
  role: 'anonymous',
  authenticated: false,
});

/**
 * Populate req.user from a token when present. Never rejects.
 * An invalid or expired token is treated as anonymous rather than an error so
 * that public endpoints stay available to unauthenticated investors.
 */
function attachUser(req, res, next) {
  const token = extractToken(req);
  if (!token) {
    req.user = ANONYMOUS;
    return next();
  }

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    req.user = err
      ? ANONYMOUS
      : { id: payload.id, username: payload.username, role: payload.role, authenticated: true };
    next();
  });
}

/** Reject the request unless a valid token is present. */
function requireAuth(req, res, next) {
  const token = extractToken(req);
  if (!token) {
    return res.status(401).json({ detail: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) {
      const expired = err.name === 'TokenExpiredError';
      return res.status(401).json({
        detail: expired ? 'Access token expired' : 'Invalid access token',
        code: expired ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID',
      });
    }
    req.user = { id: payload.id, username: payload.username, role: payload.role, authenticated: true };
    next();
  });
}

/**
 * Reject the request unless the authenticated user holds one of `roles`.
 * Implies requireAuth.
 */
function requireRole(...roles) {
  const allowed = new Set(roles.flat());

  return function roleGuard(req, res, next) {
    requireAuth(req, res, (err) => {
      if (err) return next(err);
      if (!allowed.has(req.user.role)) {
        return res.status(403).json({
          detail: `Insufficient privileges. Requires role: ${[...allowed].join(' or ')}.`,
          code: 'ROLE_FORBIDDEN',
        });
      }
      next();
    });
  };
}

module.exports = {
  JWT_SECRET,
  TOKEN_TTL,
  ANONYMOUS,
  signToken,
  attachUser,
  requireAuth,
  requireRole,
};
