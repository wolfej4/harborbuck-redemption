const express    = require('express');
const session    = require('express-session');
const bcrypt     = require('bcryptjs');
const { authenticator } = require('otplib');
const QRCode     = require('qrcode');
const Database   = require('better-sqlite3');
const path       = require('path');
const fs         = require('fs');
const crypto     = require('crypto');

const app     = express();
const PORT    = process.env.PORT    || 3000;
const DB_PATH = process.env.DB_PATH || '/data/harborbucks.db';

const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    totp_secret   TEXT,
    totp_enabled  INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS entries (
    id            TEXT PRIMARY KEY,
    serials       TEXT NOT NULL DEFAULT '[]',
    check_number  TEXT NOT NULL,
    voucher_count INTEGER NOT NULL,
    amount        REAL NOT NULL,
    manager       TEXT NOT NULL,
    voided        INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
  );
`);

function getOrCreateSecret() {
  const row = db.prepare('SELECT value FROM config WHERE key = ?').get('session_secret');
  if (row) return row.value;
  const secret = crypto.randomBytes(48).toString('hex');
  db.prepare('INSERT INTO config (key, value) VALUES (?, ?)').run('session_secret', secret);
  return secret;
}

const SESSION_SECRET = getOrCreateSecret();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(session({
  secret:            SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 },
}));

function hasUsers() { return db.prepare('SELECT COUNT(*) as c FROM users').get().c > 0; }
function requireAuth(req, res, next) {
  if (req.session?.authenticated) return next();
  res.redirect('/login');
}
function sendPage(res, file) {
  res.sendFile(path.join(__dirname, 'public', file));
}

// HTML routes
app.get('/',          requireAuth, (_req, res) => sendPage(res, 'index.html'));
app.get('/login',     (req, res) => {
  if (req.session?.authenticated) return res.redirect('/');
  if (!hasUsers()) return res.redirect('/setup');
  sendPage(res, 'login.html');
});
app.get('/setup',     (req, res) => {
  if (hasUsers()) return res.redirect('/login');
  sendPage(res, 'setup.html');
});
app.get('/mfa',       (req, res) => {
  if (!req.session?.mfaPending) return res.redirect('/login');
  sendPage(res, 'mfa.html');
});
app.get('/setup-mfa', (req, res) => {
  if (!req.session?.setupMfa) return res.redirect('/login');
  sendPage(res, 'mfa-setup.html');
});
app.get('/auth/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

// Auth API
app.post('/auth/setup', async (req, res) => {
  if (hasUsers()) return res.status(403).json({ error: 'Setup already complete.' });
  const { username, password, confirmPassword } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
  if (password !== confirmPassword) return res.status(400).json({ error: 'Passwords do not match.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  try {
    const hash = await bcrypt.hash(password, 12);
    db.prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)')
      .run(username.trim().toLowerCase(), hash, Date.now());
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create account.' });
  }
});

app.post('/auth/login', async (req, res) => {
  if (!hasUsers()) return res.status(403).json({ error: 'No accounts exist.' });
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim().toLowerCase());
  if (!user) return res.status(401).json({ error: 'Invalid username or password.' });
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid username or password.' });
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Session error.' });
    req.session.userId = user.id;
    if (!user.totp_enabled) {
      req.session.setupMfa = true;
      return res.json({ redirect: '/setup-mfa' });
    }
    req.session.mfaPending = true;
    res.json({ redirect: '/mfa' });
  });
});

app.get('/auth/setup-mfa/qr', (req, res) => {
  if (!req.session?.setupMfa) return res.status(403).json({ error: 'Unauthorized.' });
  const user   = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  const secret = authenticator.generateSecret();
  req.session.pendingTotpSecret = secret;
  const otpauth = authenticator.keyuri(user.username, 'Harborbucks', secret);
  QRCode.toDataURL(otpauth, { width: 220, margin: 1 }, (err, url) => {
    if (err) return res.status(500).json({ error: 'Failed to generate QR code.' });
    res.json({ qrDataUrl: url, secret });
  });
});

app.post('/auth/setup-mfa/verify', (req, res) => {
  if (!req.session?.setupMfa) return res.status(403).json({ error: 'Unauthorized.' });
  const { token } = req.body;
  const secret    = req.session.pendingTotpSecret;
  if (!secret || !token) return res.status(400).json({ error: 'Missing token.' });
  const valid = authenticator.verify({ token: String(token).trim(), secret });
  if (!valid) return res.status(401).json({ error: 'Invalid code. Try again.' });
  db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?').run(secret, req.session.userId);
  delete req.session.setupMfa;
  delete req.session.pendingTotpSecret;
  req.session.authenticated = true;
  res.json({ redirect: '/' });
});

app.post('/auth/mfa', (req, res) => {
  if (!req.session?.mfaPending) return res.status(403).json({ error: 'Unauthorized.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!user?.totp_secret) return res.status(500).json({ error: 'MFA not configured.' });
  const { token } = req.body;
  const valid = authenticator.verify({ token: String(token).trim(), secret: user.totp_secret });
  if (!valid) return res.status(401).json({ error: 'Invalid code. Try again.' });
  delete req.session.mfaPending;
  req.session.authenticated = true;
  res.json({ redirect: '/' });
});

// Entries API (all protected)
function rowToEntry(row) {
  return {
    id: row.id, serials: JSON.parse(row.serials),
    checkNumber: row.check_number, voucherCount: row.voucher_count,
    amount: row.amount, manager: row.manager,
    voided: row.voided === 1, createdAt: row.created_at,
  };
}
function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }

app.get('/api/entries', requireAuth, (req, res) => {
  try { res.json(db.prepare('SELECT * FROM entries ORDER BY created_at DESC').all().map(rowToEntry)); }
  catch (err) { res.status(500).json({ error: 'Failed to fetch entries.' }); }
});

app.post('/api/entries', requireAuth, (req, res) => {
  const { serials, checkNumber, voucherCount, amount, manager } = req.body;
  if (!Array.isArray(serials) || !serials.length) return res.status(400).json({ error: 'At least one serial number is required.' });
  if (!checkNumber) return res.status(400).json({ error: 'Check number is required.' });
  if (!voucherCount || voucherCount < 1) return res.status(400).json({ error: 'Valid voucher count is required.' });
  if (amount == null || isNaN(amount) || amount < 0) return res.status(400).json({ error: 'Valid amount is required.' });
  if (!manager) return res.status(400).json({ error: 'Manager name is required.' });
  try {
    const entry = { id: uid(), serials: JSON.stringify(serials), check_number: checkNumber,
      voucher_count: voucherCount, amount: parseFloat(amount), manager: manager.trim(), voided: 0, created_at: Date.now() };
    db.prepare(`INSERT INTO entries (id,serials,check_number,voucher_count,amount,manager,voided,created_at)
                VALUES (@id,@serials,@check_number,@voucher_count,@amount,@manager,@voided,@created_at)`).run(entry);
    res.status(201).json(rowToEntry(entry));
  } catch (err) { res.status(500).json({ error: 'Failed to create entry.' }); }
});

app.put('/api/entries/:id', requireAuth, (req, res) => {
  const { serials, checkNumber, voucherCount, amount, manager } = req.body;
  const { id } = req.params;
  if (!Array.isArray(serials) || !serials.length || !checkNumber || !voucherCount || amount == null || !manager)
    return res.status(400).json({ error: 'All fields are required.' });
  try {
    const result = db.prepare(`UPDATE entries SET serials=@serials,check_number=@check_number,
      voucher_count=@voucher_count,amount=@amount,manager=@manager WHERE id=@id`)
      .run({ id, serials: JSON.stringify(serials), check_number: checkNumber,
             voucher_count: voucherCount, amount: parseFloat(amount), manager: manager.trim() });
    if (!result.changes) return res.status(404).json({ error: 'Entry not found.' });
    res.json(rowToEntry(db.prepare('SELECT * FROM entries WHERE id = ?').get(id)));
  } catch (err) { res.status(500).json({ error: 'Failed to update entry.' }); }
});

app.patch('/api/entries/:id/void', requireAuth, (req, res) => {
  const { id } = req.params;
  try {
    const row = db.prepare('SELECT * FROM entries WHERE id = ?').get(id);
    if (!row) return res.status(404).json({ error: 'Entry not found.' });
    db.prepare('UPDATE entries SET voided = ? WHERE id = ?').run(row.voided ? 0 : 1, id);
    res.json(rowToEntry(db.prepare('SELECT * FROM entries WHERE id = ?').get(id)));
  } catch (err) { res.status(500).json({ error: 'Failed to toggle void.' }); }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Harborbucks running on http://0.0.0.0:${PORT}`);
  console.log(`Database: ${DB_PATH}`);
});
