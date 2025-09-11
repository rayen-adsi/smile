// api/src/auth.js
import jwt from 'jsonwebtoken';

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

/* ---------- Login ---------- */
export async function login(email, password) {
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    console.warn('ADMIN_EMAIL or ADMIN_PASSWORD not set; refusing admin login.');
    return null;
  }
  if (!email || !password) return null;
  if (email.toLowerCase() !== ADMIN_EMAIL.toLowerCase()) return null;
  if (password !== ADMIN_PASSWORD) return null;

  const token = jwt.sign(
    { sub: 'admin', role: 'admin', email: ADMIN_EMAIL },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  return { token };
}

/* ---------- Helpers ---------- */
function extractBearer(req) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer (.+)$/);
  return m ? m[1] : '';
}

function verifyAdmin(token) {
  if (!token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return payload?.role === 'admin' ? payload : null;
  } catch {
    return null;
  }
}

function unauthorized(res) {
  return res.status(401).json({ error: 'Unauthorized' });
}

/* ---------- Middleware ---------- */
/** Strict guard: only Authorization: Bearer is accepted. */
export function requireAdmin(req, res, next) {
  const payload = verifyAdmin(extractBearer(req));
  if (!payload) return unauthorized(res);
  req.user = payload;
  next();
}

/**
 * Lenient guard for download links: accepts Authorization header
 * OR a `?token=...` query param (use ONLY on routes that must work via <a href>).
 */
export function requireAdminAllowQuery(req, res, next) {
  let token = extractBearer(req);
  if (!token && typeof req.query.token === 'string') token = req.query.token;

  const payload = verifyAdmin(token);
  if (!payload) return unauthorized(res);
  req.user = payload;
  next();
}
