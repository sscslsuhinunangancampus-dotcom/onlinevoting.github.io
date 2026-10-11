import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false });
const PgSession = connectPgSimple(session);
const PORT = Number(process.env.PORT || 3000);
const TZ = process.env.VOTING_TIME_ZONE || 'Asia/Manila';
const START = Date.parse(process.env.VOTING_START || '2026-10-11T00:00:00+08:00');
const END = Date.parse(process.env.VOTING_END || '2026-10-31T23:59:59+08:00');
const ID_PEPPER = process.env.SESSION_SECRET;

if (!process.env.DATABASE_URL || !ID_PEPPER || ID_PEPPER.length < 32 || !process.env.ADMIN_PASSWORD_HASH) {
  console.error('Set DATABASE_URL, SESSION_SECRET (32+ chars), and ADMIN_PASSWORD_HASH before starting.');
  process.exit(1);
}

const hashStudentId = (id) => crypto.createHmac('sha256', ID_PEPPER).update(id.trim().toUpperCase()).digest('hex');
const localDate = () => new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
const votingOpen = () => Date.now() >= START && Date.now() <= END;

app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:', 'https:'], connectSrc: ["'self'"], objectSrc: ["'none'"],
  frameAncestors: ["'none'"], upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
}}}));
app.use(express.json({ limit: '20kb' }));
app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: ID_PEPPER, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 }
}));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, 'public')));

const requireStudent = (req, res, next) => req.session.studentHash ? next() : res.status(401).json({ error: 'Verify your student ID first.' });
const requireAdmin = (req, res, next) => req.session.isAdmin ? next() : res.status(401).json({ error: 'Administrator login required.' });
async function audit(action, details = {}) {
  await pool.query('INSERT INTO admin_audit(action, details) VALUES ($1, $2)', [action, JSON.stringify(details)]);
}

app.get('/api/status', async (_req, res) => {
  const count = await pool.query('SELECT COUNT(*)::int AS candidates FROM candidates WHERE active = TRUE');
  res.json({ event: "People's Choice Award", votingOpen: votingOpen(), start: new Date(START).toISOString(), end: new Date(END).toISOString(), candidates: count.rows[0].candidates });
});

// This endpoint checks that an ID exists in the administrator-imported roster.
// ID-only verification is not proof of identity: for a real election, pair it with campus SSO,
// a one-time code to a verified campus email/phone, or in-person identity verification.
app.post('/api/verify-student', rateLimit({ windowMs: 15 * 60_000, limit: 8 }), async (req, res) => {
  const id = String(req.body?.studentId || '').trim();
  if (!/^[A-Za-z0-9-]{4,32}$/.test(id)) return res.status(400).json({ error: 'Enter a valid student ID format.' });
  const digest = hashStudentId(id);
  const result = await pool.query('SELECT active FROM students WHERE student_id_hash = $1', [digest]);
  if (!result.rowCount || !result.rows[0].active) return res.status(403).json({ error: 'Student ID not found in the eligible voter roster. Contact the administrator.' });
  req.session.studentHash = digest;
  res.json({ ok: true, message: 'Student ID matched the eligible roster.' });
});

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get('/api/candidates', async (_req, res) => {
  const result = await pool.query(`SELECT c.id, c.name, c.title, c.photo_url,
    COUNT(v.id)::int AS votes FROM candidates c LEFT JOIN votes v ON v.candidate_id=c.id
    WHERE c.active=TRUE GROUP BY c.id ORDER BY c.id`);
  res.json({ candidates: result.rows });
});

app.get('/api/me', requireStudent, async (req, res) => {
  const result = await pool.query('SELECT COUNT(*)::int AS used, MAX(local_vote_date)::text AS last_vote_date FROM votes WHERE student_id_hash=$1', [req.session.studentHash]);
  const used = result.rows[0].used;
  const today = await pool.query('SELECT 1 FROM votes WHERE student_id_hash=$1 AND local_vote_date=$2', [req.session.studentHash, localDate()]);
  res.json({ verified: true, votesUsed: used, votesRemaining: Math.max(0, 3-used), votedToday: today.rowCount > 0 });
});

app.post('/api/vote', requireStudent, async (req, res) => {
  if (!votingOpen()) return res.status(403).json({ error: 'Voting is not currently open.' });
  const candidateId = Number(req.body?.candidateId);
  if (!Number.isSafeInteger(candidateId) || candidateId < 1) return res.status(400).json({ error: 'Choose a valid candidate.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Lock eligible voter row to serialize concurrent requests from the same student.
    const student = await client.query('SELECT student_id_hash FROM students WHERE student_id_hash=$1 AND active=TRUE FOR UPDATE', [req.session.studentHash]);
    if (!student.rowCount) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Voter is no longer eligible.' }); }
    const candidate = await client.query('SELECT id FROM candidates WHERE id=$1 AND active=TRUE', [candidateId]);
    if (!candidate.rowCount) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Candidate is unavailable.' }); }
    const usage = await client.query('SELECT COUNT(*)::int AS used FROM votes WHERE student_id_hash=$1', [req.session.studentHash]);
    if (usage.rows[0].used >= 3) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'You have used all 3 votes.' }); }
    try {
      await client.query('INSERT INTO votes(student_id_hash,candidate_id,local_vote_date) VALUES ($1,$2,$3)', [req.session.studentHash, candidateId, localDate()]);
    } catch (e) {
      if (e.code === '23505') { await client.query('ROLLBACK'); return res.status(409).json({ error: 'You have already voted today. Please return tomorrow.' }); }
      throw e;
    }
    await client.query('COMMIT');
    res.json({ ok: true, message: 'Your vote has been recorded.' });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('Vote error', e.message);
    res.status(500).json({ error: 'Unable to record vote. Please try again.' });
  } finally { client.release(); }
});

// Admin: login, candidate management, voter roster import, audit log.
// Use a strong bcrypt hash in ADMIN_PASSWORD_HASH; never store plaintext admin passwords.
app.post('/api/admin/login', rateLimit({ windowMs: 15 * 60_000, limit: 5 }), async (req, res) => {
  const password = String(req.body?.password || '');
  if (!await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH)) return res.status(401).json({ error: 'Invalid administrator credentials.' });
  req.session.isAdmin = true;
  await audit('admin_login');
  res.json({ ok: true });
});
app.post('/api/admin/logout', requireAdmin, async (req, res) => {
  await audit('admin_logout');
  req.session.isAdmin = false;
  res.json({ ok: true });
});
app.get('/api/admin/summary', requireAdmin, async (_req, res) => {
  const [voters, votes, candidates, auditRows] = await Promise.all([
    pool.query('SELECT COUNT(*)::int AS n FROM students WHERE active=TRUE'),
    pool.query('SELECT COUNT(*)::int AS n FROM votes'),
    pool.query('SELECT id,name,title,photo_url,active FROM candidates ORDER BY id'),
    pool.query('SELECT action,details,created_at FROM admin_audit ORDER BY id DESC LIMIT 50')
  ]);
  res.json({ eligibleVoters: voters.rows[0].n, totalVotes: votes.rows[0].n, candidates: candidates.rows, audit: auditRows.rows });
});
app.post('/api/admin/candidates', requireAdmin, async (req, res) => {
  const name = String(req.body?.name || '').trim().slice(0, 120);
  const title = String(req.body?.title || '').trim().slice(0, 120);
  const photoUrl = String(req.body?.photoUrl || '').trim().slice(0, 500);
  if (!name) return res.status(400).json({ error: 'Candidate name is required.' });
  if (photoUrl && !/^https:\/\/[^\s]+$/i.test(photoUrl)) return res.status(400).json({ error: 'Photo URL must use HTTPS.' });
  const r = await pool.query('INSERT INTO candidates(name,title,photo_url) VALUES ($1,$2,$3) RETURNING id,name,title,photo_url,active', [name,title,photoUrl]);
  await audit('candidate_created', { id: r.rows[0].id, name });
  res.json({ candidate: r.rows[0] });
});
app.patch('/api/admin/candidates/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const active = req.body?.active;
  if (!Number.isSafeInteger(id) || typeof active !== 'boolean') return res.status(400).json({ error: 'Provide candidate ID and active boolean.' });
  const r = await pool.query('UPDATE candidates SET active=$1 WHERE id=$2 RETURNING id,name,active', [active,id]);
  if (!r.rowCount) return res.status(404).json({ error: 'Candidate not found.' });
  await audit('candidate_status_changed', { id, active });
  res.json({ candidate: r.rows[0] });
});
app.post('/api/admin/roster', requireAdmin, async (req, res) => {
  const ids = req.body?.studentIds;
  if (!Array.isArray(ids) || ids.length > 5000) return res.status(400).json({ error: 'Provide studentIds array (maximum 5000 per request).' });
  let added = 0;
  for (const raw of ids) {
    const id = String(raw || '').trim();
    if (!/^[A-Za-z0-9-]{4,32}$/.test(id)) continue;
    const digest = hashStudentId(id);
    const r = await pool.query('INSERT INTO students(student_id_hash) VALUES ($1) ON CONFLICT (student_id_hash) DO UPDATE SET active=TRUE', [digest]);
    added += 1;
  }
  await audit('roster_imported', { processed: added });
  res.json({ processed: added, note: 'Student IDs are stored as keyed hashes, not plaintext. Import only eligible students and protect the source file.' });
});
app.get('/api/admin/export-votes', requireAdmin, async (_req, res) => {
  const r = await pool.query(`SELECT c.name AS candidate, COUNT(v.id)::int AS votes FROM candidates c LEFT JOIN votes v ON v.candidate_id=c.id GROUP BY c.id ORDER BY votes DESC, c.name`);
  res.json({ results: r.rows });
});

app.get('/admin', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const migration = await fs.readFile(path.join(__dirname, 'migrations', '001_init.sql'), 'utf8');
await pool.query(migration);
app.listen(PORT, () => console.log(`FairVote running on port ${PORT}`));
