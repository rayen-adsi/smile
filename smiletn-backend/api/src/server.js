// api/src/server.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import multer from 'multer';
import rateLimit from 'express-rate-limit';
import { extname } from 'path';
import { randomUUID } from 'crypto';
import fs from 'fs';
import mime from 'mime-types';
import { z } from 'zod';

import { query } from './db.js';
import { login, requireAdmin, requireAdminAllowQuery } from './auth.js';

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = process.env.UPLOAD_DIR || '/data/uploads';

// ensure upload dir exists
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* ---------- CORS ---------- */
const defaultOrigins = [
  'http://127.0.0.1:5500',
  'http://localhost:5500',
  'http://127.0.0.1:3000',
  'http://localhost:3000',
];
const allowed = (process.env.CORS_ORIGINS || defaultOrigins.join(','))
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const corsMw = cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true); // curl/postman
    return allowed.includes(origin) ? cb(null, true) : cb(new Error('CORS blocked: ' + origin));
  },
  credentials: true,
  methods: ['GET','HEAD','PUT','PATCH','POST','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  maxAge: 86400,
});
app.use(corsMw);
app.options('*', corsMw);

/* ---------- Security & common ---------- */
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(morgan('tiny'));
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true }));

/* ---------- Health ---------- */
app.get('/api/health', (_req, res) => res.json({ ok: true }));

/* ---------- Uploads (multer) ---------- */
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => cb(null, randomUUID() + extname(file.originalname || '').toLowerCase()),
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024, files: 10 }, // 10MB, 10 files
});

/* ---------- Rate limit (public submit) ---------- */
const limitQuotes = rateLimit({ windowMs: 60 * 60 * 1000, max: 20 });

/* ---------- DB feature detection (urgency column) ---------- */
let HAS_URGENCY = null;
async function hasUrgencyColumn() {
  if (HAS_URGENCY !== null) return HAS_URGENCY;
  try {
    const { rowCount } = await query(
      `SELECT 1
         FROM information_schema.columns
        WHERE table_name = 'quotes' AND column_name = 'urgency'`
    );
    HAS_URGENCY = rowCount > 0;
  } catch {
    HAS_URGENCY = false;
  }
  return HAS_URGENCY;
}

/* ---------- PUBLIC: submit quote (multipart) ---------- */
const QuoteSchema = z.object({
  name: z.string().min(2),
  treatment: z.string().optional(),
  email: z.string().email(),
  phone: z.string().min(4),
  whatsapp: z.string().optional(),
  country: z.string().optional(),
  // comes from the segmented control in the form:
  urgency: z.enum(['Dès que possible', 'Dans 1–3 mois', 'Plus tard']).optional(),
  notes: z.string().max(5000).optional(),
  consent: z.enum(['true', 'false']).optional(),
});

app.post('/api/quotes/multipart', limitQuotes, upload.array('files'), async (req, res) => {
  try {
    const data = QuoteSchema.parse(req.body);
    const consent = data.consent === 'true';

    const cols = ['name','treatment','email','phone','whatsapp','country'];
    const vals = [data.name, data.treatment || null, data.email, data.phone, data.whatsapp || null, data.country || null];

    if (await hasUrgencyColumn()) {
      cols.push('urgency');
      vals.push(data.urgency || null);
    }

    cols.push('notes','consent');
    vals.push(data.notes || null, consent);

    const placeholders = vals.map((_, i) => `$${i + 1}`).join(',');
    const { rows } = await query(
      `INSERT INTO quotes (${cols.join(',')})
       VALUES (${placeholders})
       RETURNING id, created_at`,
      vals
    );
    const quoteId = rows[0].id;

    for (const f of (req.files || [])) {
      await query(
        `INSERT INTO files (quote_id, original_name, mime_type, size, path)
         VALUES ($1,$2,$3,$4,$5)`,
        [quoteId, f.originalname, f.mimetype, f.size, f.filename]
      );
    }
    res.json({ id: quoteId });
  } catch (e) {
    if (e instanceof z.ZodError) return res.status(400).json({ error: 'Invalid payload' });
    console.error('multipart submit error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ---------- AUTH ---------- */
const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = LoginSchema.parse(req.body);
    const out = await login(email, password); // { token } or null
    if (!out?.token) return res.status(401).json({ error: 'Bad credentials' });
    res.json(out);
  } catch (e) {
    if (e instanceof z.ZodError) return res.status(400).json({ error: 'Invalid login payload' });
    console.error('login error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ---------- ADMIN: list quotes ---------- */
app.get('/api/admin/quotes', requireAdmin, async (req, res) => {
  try {
    const allowedStatuses = new Set(['pending','reviewing','quoted','scheduled','closed','cancelled']);
    const status = (typeof req.query.status === 'string' && allowedStatuses.has(req.query.status))
      ? req.query.status : null;

    const q = (req.query.q ?? '').toString().trim().toLowerCase();
    const limit = Math.max(1, Math.min(200, parseInt(req.query.limit, 10) || 20));
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);

    const where = [];
    const params = [];

    if (status) { params.push(status); where.push(`status = $${params.length}`); }
    if (q) {
      const pat = `%${q}%`;
      params.push(pat, pat, pat);
      where.push(`(
        LOWER(name) LIKE $${params.length - 2} OR
        LOWER(email) LIKE $${params.length - 1} OR
        LOWER(COALESCE(notes,'')) LIKE $${params.length}
      )`);
    }

    const wsql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    params.push(limit, offset);

    const { rows } = await query(
      `SELECT id, name, treatment, status, created_at,
              LEFT(COALESCE(notes,''),160) AS snippet
         FROM quotes
        ${wsql}
        ORDER BY created_at DESC
        LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );
    res.json(rows);
  } catch (e) {
    console.error('LIST /api/admin/quotes failed:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ---------- ADMIN: quote details ---------- */
app.get('/api/admin/quotes/:id', requireAdmin, async (req, res) => {
  try {
    const { rows } = await query('SELECT * FROM quotes WHERE id=$1', [req.params.id]);
    const quote = rows[0];
    if (!quote) return res.status(404).json({ error: 'Not found' });

    const files = (await query(
      'SELECT id, original_name, mime_type, size FROM files WHERE quote_id=$1',
      [quote.id]
    )).rows;

    res.json({ quote, files });
  } catch (e) {
    console.error('admin details error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ---------- ADMIN: update status ---------- */
app.patch('/api/admin/quotes/:id/status', requireAdmin, async (req, res) => {
  try {
    const allowed = ['pending','reviewing','quoted','scheduled','closed','cancelled'];
    const status = (req.body?.status || '').toString();
    if (!allowed.includes(status)) return res.status(400).json({ error: 'Bad status' });

    const { rows } = await query(
      `UPDATE quotes SET status=$1, updated_at=now() WHERE id=$2
       RETURNING id, status, updated_at`,
      [status, req.params.id]
    );
    if (!rows[0]) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch (e) {
    console.error('admin update status error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ---------- ADMIN: secure file download ---------- */
/* Accepts Authorization: Bearer OR ?token=... for <a> links */
app.get('/api/admin/files/:id', requireAdminAllowQuery, async (req, res) => {
  try {
    const { rows } = await query('SELECT * FROM files WHERE id=$1', [req.params.id]);
    const f = rows[0];
    if (!f) return res.status(404).json({ error: 'Not found' });

    const full = `${UPLOAD_DIR}/${f.path}`;
    if (!fs.existsSync(full)) return res.status(404).json({ error: 'Missing file' });

    res.type(f.mime_type || mime.lookup(f.original_name) || 'application/octet-stream');
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(f.original_name)}"`);
    fs.createReadStream(full).pipe(res);
  } catch (e) {
    console.error('admin file error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ---------- Global error guard ---------- */
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Server error' });
});

app.listen(PORT, () => console.log(`API listening on http://localhost:${PORT}`));
