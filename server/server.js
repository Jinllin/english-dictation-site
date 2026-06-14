import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
const DATABASE_PATH = process.env.DATABASE_PATH || path.join(__dirname, 'data', 'dictation.sqlite');
const FRONTEND_ROOT = process.env.FRONTEND_ROOT || path.join(__dirname, '..');
const WORD_AUDIO_DIR = process.env.WORD_AUDIO_DIR || path.join(FRONTEND_ROOT, 'assets', 'audio', 'words');
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
const DEFAULT_ALLOWED_ORIGINS = [
  'https://myechopet.com',
  'https://www.myechopet.com',
  'http://myechopet.com',
  'http://www.myechopet.com',
  'http://43.135.34.31',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];
const ALLOWED_ORIGINS = new Set([...DEFAULT_ALLOWED_ORIGINS, ...CORS_ORIGINS]);
const SNAPSHOT_KEYS = ['ds4', 'eb4', 'cu4', 'fv4', 'sho4', 'dk4', 'sm4', 'pet4', 'guide4'];
const FREE_SNAPSHOT_BYTES = 10 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 100 * 1024 * 1024;

fs.mkdirSync(path.dirname(DATABASE_PATH), { recursive: true });
const db = new Database(DATABASE_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  nickname TEXT NOT NULL,
  is_paid INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_snapshots (
  user_id INTEGER PRIMARY KEY,
  version INTEGER NOT NULL DEFAULT 1,
  payload_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pronunciations (
  normalized_word TEXT PRIMARY KEY,
  audio_url TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'system',
  hit_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
const userColumns = db.prepare('PRAGMA table_info(users)').all().map(col => col.name);
if (!userColumns.includes('is_paid')) {
  db.prepare('ALTER TABLE users ADD COLUMN is_paid INTEGER NOT NULL DEFAULT 0').run();
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: false }));
const corsOptions = {
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.has(origin)) return cb(null, true);
    return cb(null, false);
  },
  credentials: false
};
app.use(cors(corsOptions));
app.options('/api/*', cors(corsOptions));
app.use(express.json({ limit: `${MAX_PAYLOAD_BYTES}b` }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function normalizeWord(input) {
  return String(input || '')
    .trim()
    .toLowerCase()
    .replace(/[’‘]/g, "'")
    .replace(/^[^a-z]+|[^a-z]+$/g, '')
    .replace(/[^a-z'-]/g, '');
}

function wordAudioFileName(word) {
  return `${word.replace(/'/g, '').replace(/[^a-z-]/g, '-')}.mp3`;
}

function publicUser(row) {
  return row ? { id: row.id, email: row.email, nickname: row.nickname, isPaid: !!row.is_paid, plan: row.is_paid ? 'paid' : 'free', createdAt: row.created_at } : null;
}

function signToken(user) {
  return jwt.sign({ sub: String(user.id), email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

function requireAuth(req, res, next) {
  const header = req.get('authorization') || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(payload.sub));
    if (!user) return res.status(401).json({ error: 'unauthorized' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'unauthorized' });
  }
}

function validateSnapshot(input, user) {
  if (!input || typeof input !== 'object') throw new Error('snapshot must be an object');
  const version = Number(input.version || 1);
  const data = input.data && typeof input.data === 'object' ? input.data : null;
  if (!data) throw new Error('snapshot.data is required');
  const clean = {};
  for (const key of SNAPSHOT_KEYS) {
    if (Object.prototype.hasOwnProperty.call(data, key)) clean[key] = data[key];
  }
  const payload = {
    version: Number.isFinite(version) ? version : 1,
    updatedAt: new Date().toISOString(),
    data: clean
  };
  const json = JSON.stringify(payload);
  const bytes = Buffer.byteLength(json, 'utf8');
  const limit = user?.is_paid ? MAX_PAYLOAD_BYTES : FREE_SNAPSHOT_BYTES;
  if (bytes > limit) {
    throw new Error(user?.is_paid ? '同步数据过大，请联系管理员扩容' : '免费账号云端空间最多 10MB，请精简自定义词库或升级');
  }
  return { payload, json };
}

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'english-dictation-server', time: new Date().toISOString() });
});

app.get('/api/pronunciation', (req, res) => {
  const word = normalizeWord(req.query?.word);
  if (!word || word.length > 64 || !/^[a-z][a-z'-]*$/.test(word)) {
    return res.status(400).json({ found: false, error: 'invalid_word' });
  }

  const cached = db.prepare('SELECT audio_url, source FROM pronunciations WHERE normalized_word = ?').get(word);
  if (cached) {
    db.prepare('UPDATE pronunciations SET hit_count = hit_count + 1, updated_at = CURRENT_TIMESTAMP WHERE normalized_word = ?').run(word);
    return res.json({ found: true, word, url: cached.audio_url, source: cached.source });
  }

  const fileName = wordAudioFileName(word);
  const filePath = path.join(WORD_AUDIO_DIR, fileName);
  if (fs.existsSync(filePath)) {
    const url = `/assets/audio/words/${fileName}`;
    db.prepare(`
      INSERT INTO pronunciations (normalized_word, audio_url, source, hit_count, updated_at)
      VALUES (?, ?, 'system', 1, CURRENT_TIMESTAMP)
      ON CONFLICT(normalized_word) DO UPDATE SET
        audio_url = excluded.audio_url,
        source = excluded.source,
        hit_count = pronunciations.hit_count + 1,
        updated_at = CURRENT_TIMESTAMP
    `).run(word, url);
    return res.json({ found: true, word, url, source: 'system' });
  }

  return res.json({ found: false, word });
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || '');
  const nickname = String(req.body?.nickname || email.split('@')[0] || 'EchoPet用户').trim().slice(0, 24);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: '请输入有效邮箱' });
  if (password.length < 6) return res.status(400).json({ error: '密码至少 6 位' });
  const passwordHash = await bcrypt.hash(password, 10);
  try {
    const info = db.prepare('INSERT INTO users (email, password_hash, nickname) VALUES (?, ?, ?)').run(email, passwordHash, nickname);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).json({ token: signToken(user), user: publicUser(user) });
  } catch (err) {
    if (String(err.message).includes('UNIQUE')) return res.status(409).json({ error: '该邮箱已注册' });
    throw err;
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || '');
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: '邮箱或密码不正确' });
  }
  res.json({ token: signToken(user), user: publicUser(user) });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.get('/api/sync', requireAuth, (req, res) => {
  const row = db.prepare('SELECT version, payload_json, updated_at FROM user_snapshots WHERE user_id = ?').get(req.user.id);
  if (!row) return res.json({ snapshot: null });
  const snapshot = JSON.parse(row.payload_json);
  res.json({ snapshot: { ...snapshot, savedAt: row.updated_at } });
});

app.put('/api/sync', requireAuth, (req, res) => {
  try {
    const { payload, json } = validateSnapshot(req.body, req.user);
    db.prepare(`
      INSERT INTO user_snapshots (user_id, version, payload_json, updated_at)
      VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(user_id) DO UPDATE SET
        version = excluded.version,
        payload_json = excluded.payload_json,
        updated_at = CURRENT_TIMESTAMP
    `).run(req.user.id, payload.version, json);
    res.json({ ok: true, snapshot: payload });
  } catch (err) {
    res.status(400).json({ error: err.message || '保存失败' });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: '服务器暂时不可用' });
});

app.listen(PORT, () => {
  console.log(`English dictation server listening on http://localhost:${PORT}`);
});
