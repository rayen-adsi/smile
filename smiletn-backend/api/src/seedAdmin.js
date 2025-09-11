import 'dotenv/config';
import bcrypt from 'bcryptjs';
import { query } from './db.js';

const email = process.env.ADMIN_EMAIL;
const pass  = process.env.ADMIN_PASSWORD;

if (!email || !pass) {
  console.error('Set ADMIN_EMAIL and ADMIN_PASSWORD env vars.');
  process.exit(1);
}

const hash = await bcrypt.hash(pass, 10);
await query(
  `INSERT INTO admin_users (email, password_hash)
   VALUES ($1,$2)
   ON CONFLICT (email) DO NOTHING`,
  [email, hash]
);

console.log('Admin ready:', email);
process.exit(0);
