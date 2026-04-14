const express        = require('express');
const session        = require('express-session');
const bcrypt         = require('bcryptjs');
const { authenticator } = require('otplib');
const QRCode         = require('qrcode');
const Database       = require('better-sqlite3');
const nodemailer     = require('nodemailer');
const morgan         = require('morgan');
const path           = require('path');
const fs             = require('fs');
const crypto         = require('crypto');

const app     = express();
const PORT    = process.env.PORT    || 3000;
const DB_PATH = process.env.DB_PATH || '/data/harborbucks.db';

// ── LOGGER ─────────────────────────────────────
const LOG_PATH = process.env.LOG_PATH || path.join(path.dirname(DB_PATH), 'harborbucks.log');
const MAX_LOG_BYTES = 10 * 1024 * 1024; // 10 MB before rotation

function log(level, event, details = {}) {
  const entry = { ts: Date.now(), level, event, ...details };
  const line  = JSON.stringify(entry);
  // Coloured stdout for docker logs
  const colour = { info: '\x1b[36m', warn: '\x1b[33m', error: '\x1b[31m' }[level] || '';
  process.stdout.write(`${colour}[${level.toUpperCase()}]\x1b[0m ${new Date(entry.ts).toISOString()} ${event}${details.user ? ' user='+details.user : ''}${details.ip ? ' ip='+details.ip : ''}${details.msg ? ' — '+details.msg : ''}\n`);
  try {
    // Rotate if over limit
    try {
      const stat = fs.statSync(LOG_PATH);
      if (stat.size > MAX_LOG_BYTES) {
        fs.renameSync(LOG_PATH, LOG_PATH + '.1');
      }
    } catch {}
    fs.appendFileSync(LOG_PATH, line + '\n');
  } catch (e) {
    process.stderr.write('Logger write error: ' + e.message + '\n');
  }
}

// Helper to extract IP from request (handles reverse proxy)
function ip(req) {
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

// ── DATABASE ───────────────────────────────────
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
    email         TEXT,
    password_hash TEXT NOT NULL,
    initials      TEXT UNIQUE NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    mfa_type      TEXT NOT NULL DEFAULT 'none',
    totp_secret   TEXT,
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
  CREATE TABLE IF NOT EXISTS auth_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    purpose    TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ── MIGRATIONS ─────────────────────────────────
// Safely add columns that may not exist in databases created by older versions
(function runMigrations() {
  const existingCols = db.prepare('PRAGMA table_info(users)').all().map(r => r.name);
  const migrations = [
    { col: 'email',       sql: 'ALTER TABLE users ADD COLUMN email TEXT' },
    { col: 'initials',    sql: "ALTER TABLE users ADD COLUMN initials TEXT NOT NULL DEFAULT ''" },
    { col: 'role',        sql: "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'" },
    { col: 'mfa_type',    sql: "ALTER TABLE users ADD COLUMN mfa_type TEXT NOT NULL DEFAULT 'none'" },
    { col: 'totp_secret', sql: 'ALTER TABLE users ADD COLUMN totp_secret TEXT' },
    { col: 'avatar_data', sql: 'ALTER TABLE users ADD COLUMN avatar_data TEXT' },
  ];
  for (const m of migrations) {
    if (!existingCols.includes(m.col)) {
      db.prepare(m.sql).run();
      log('info', 'db.migration', { msg: `Added column users.${m.col}` });
    }
  }

  // Add status column to entries and backfill from voided
  const entryCols = db.prepare('PRAGMA table_info(entries)').all().map(r => r.name);
  if (!entryCols.includes('status')) {
    db.prepare("ALTER TABLE entries ADD COLUMN status TEXT NOT NULL DEFAULT 'active'").run();
    db.prepare("UPDATE entries SET status = 'voided' WHERE voided = 1").run();
    log('info', 'db.migration', { msg: 'Added column entries.status and backfilled from voided' });
  }

  // Backfill initials for any users that have an empty string (from the migration default)
  // Use username as a fallback so the UNIQUE constraint doesn't block login
  const blankInitials = db.prepare("SELECT id, username FROM users WHERE initials = ''").all();
  for (const u of blankInitials) {
    const candidate = u.username.slice(0, 4).toUpperCase();
    // Make it unique by appending a digit if needed
    let initials = candidate;
    let suffix = 1;
    while (db.prepare('SELECT id FROM users WHERE initials = ? AND id != ?').get(initials, u.id)) {
      initials = candidate.slice(0, 3) + suffix++;
    }
    db.prepare('UPDATE users SET initials = ? WHERE id = ?').run(initials, u.id);
    log('warn', 'db.migration.backfill', { msg: `Set initials for user "${u.username}" → "${initials}". Update in Admin → Users.` });
  }
})();

// ── CONFIG HELPERS ─────────────────────────────
function getConfig(key, def = null) {
  const row = db.prepare('SELECT value FROM config WHERE key = ?').get(key);
  return row ? row.value : def;
}
function setConfig(key, value) {
  db.prepare('INSERT INTO config (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key, value);
}
function getOrCreateSecret() {
  const existing = getConfig('session_secret');
  if (existing) return existing;
  const s = crypto.randomBytes(48).toString('hex');
  setConfig('session_secret', s);
  return s;
}

// ── SMTP ───────────────────────────────────────
function getSmtpConfig() {
  const raw = getConfig('smtp_config');
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}
async function getTransporter() {
  const cfg = getSmtpConfig();
  if (!cfg?.host) return null;
  return nodemailer.createTransport({
    host: cfg.host, port: cfg.port || 587, secure: cfg.secure || false,
    auth: cfg.user ? { user: cfg.user, pass: cfg.pass } : undefined,
  });
}
async function sendEmail({ to, subject, text, html }) {
  const t = await getTransporter();
  if (!t) throw new Error('SMTP not configured.');
  const cfg = getSmtpConfig();
  await t.sendMail({ from: cfg.from || cfg.user, to, subject, text, html });
}

// ── MIDDLEWARE ─────────────────────────────────
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// HTTP request logging (only non-static, non-noisy routes)
app.use(morgan((tokens, req, res) => {
  const status = tokens.status(req, res);
  const url    = tokens.url(req, res);
  // Skip favicon and static-ish GETs that aren't interesting
  if (url === '/favicon.svg') return null;
  const level = status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info';
  log(level, 'http', {
    method: tokens.method(req, res),
    url,
    status: parseInt(status),
    ms: Math.round(parseFloat(tokens['response-time'](req, res))),
    ip: ip(req),
    user: req.session?.userId
      ? db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username
      : undefined,
  });
  return null; // morgan won't write its own line; we did it above
}));

app.use(session({
  secret:            getOrCreateSecret(),
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, sameSite: 'lax',
    secure:   process.env.SECURE_COOKIES === 'true',
    maxAge:   8 * 60 * 60 * 1000,
  },
}));

// ── AUTH HELPERS ───────────────────────────────
function hasUsers()  { return db.prepare('SELECT COUNT(*) as c FROM users').get().c > 0; }
function isAdmin(req){ return req.session?.authenticated && req.session?.userRole === 'admin'; }
function requireAuth(req, res, next) {
  if (req.session?.authenticated) return next();
  res.redirect('/login');
}
function requireAdmin(req, res, next) {
  if (isAdmin(req)) return next();
  res.redirect('/');
}
function page(res, f) { res.sendFile(path.join(__dirname, 'public', f)); }

// ── FAVICON ────────────────────────────────────
app.get('/favicon.svg', (_req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml');
  res.send(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#0c1a2e"/><text x="16" y="23" text-anchor="middle" font-size="20" fill="#c49a3c">⚓</text></svg>`);
});

// ── HTML ROUTES ────────────────────────────────
app.get('/',             requireAuth,  (_req, res) => page(res, 'index.html'));
app.get('/admin',        requireAdmin, (_req, res) => page(res, 'admin.html'));
app.get('/settings',     requireAuth,  (_req, res) => page(res, 'settings.html'));
app.get('/login',        (req, res) => { if (req.session?.authenticated) return res.redirect('/'); if (!hasUsers()) return res.redirect('/setup'); page(res, 'login.html'); });
app.get('/setup',        (req, res) => { if (hasUsers()) return res.redirect('/login'); page(res, 'setup.html'); });
app.get('/register',     (req, res) => { if (!hasUsers()) return res.redirect('/setup'); if (getConfig('allow_registration','1') !== '1') return res.redirect('/login'); page(res, 'register.html'); });
app.get('/mfa',          (req, res) => { if (!req.session?.mfaPending) return res.redirect('/login'); page(res, 'mfa.html'); });
app.get('/setup-mfa',    (req, res) => { if (!req.session?.setupMfa) return res.redirect('/login'); page(res, 'mfa-setup.html'); });
app.get('/reset-request',  (_req, res) => page(res, 'reset-request.html'));
app.get('/reset-confirm',  (_req, res) => page(res, 'reset-confirm.html'));
app.get('/auth/logout', (req, res) => {
  const username = db.prepare('SELECT username FROM users WHERE id=?').get(req.session?.userId)?.username;
  req.session.destroy(() => {
    if (username) log('info', 'auth.logout', { user: username, ip: ip(req) });
    res.redirect('/login');
  });
});

// ── PUBLIC CONFIG ──────────────────────────────
app.get('/api/public-config', (_req, res) => {
  res.json({
    allowRegistration: getConfig('allow_registration','1') === '1',
    smtpConfigured:    !!getSmtpConfig()?.host,
  });
});

// ── AUTH: SETUP (first run) ────────────────────
app.post('/auth/setup', async (req, res) => {
  if (hasUsers()) return res.status(403).json({ error: 'Setup already complete.' });
  const { username, email, password, confirmPassword, initials, mfaType, smtp } = req.body;
  if (!username || !password)          return res.status(400).json({ error: 'Username and password required.' });
  if (password !== confirmPassword)    return res.status(400).json({ error: 'Passwords do not match.' });
  if (password.length < 8)             return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (!initials || !/^[A-Za-z0-9]{2,4}$/.test(initials)) return res.status(400).json({ error: 'Initials must be 2–4 alphanumeric characters.' });

  // Save SMTP config if provided (before user creation so email MFA is valid)
  if (smtp?.host) {
    setConfig('smtp_config', JSON.stringify({
      host: smtp.host, port: smtp.port || 587, user: smtp.user || '',
      pass: smtp.pass || '', from: smtp.from || '', secure: smtp.secure || false,
    }));
    log('info', 'auth.setup.smtp_configured', { host: smtp.host });
  }

  const smtpOk = !!getSmtpConfig()?.host;
  const allowed = smtpOk ? ['none','totp','email'] : ['none','totp'];
  const chosenMfa = allowed.includes(mfaType) ? mfaType : 'none';
  if (chosenMfa === 'email' && !email?.trim()) return res.status(400).json({ error: 'Email address is required for email MFA.' });

  try {
    const hash = await bcrypt.hash(password, 12);
    db.prepare('INSERT INTO users (username,email,password_hash,initials,role,mfa_type,created_at) VALUES (?,?,?,?,?,?,?)')
      .run(username.trim().toLowerCase(), email?.trim()||null, hash, initials.toUpperCase(), 'admin', chosenMfa, Date.now());
    const user = db.prepare('SELECT * FROM users WHERE username=?').get(username.trim().toLowerCase());
    log('info', 'auth.setup', { user: user.username, initials: user.initials, mfa: chosenMfa, ip: ip(req) });
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'Session error.' });
      req.session.userId = user.id; req.session.userRole = 'admin';
      if (chosenMfa === 'totp') { req.session.setupMfa = true; return res.json({ redirect: '/setup-mfa' }); }
      req.session.authenticated = true;
      res.json({ redirect: '/' });
    });
  } catch(e) {
    if (e.message?.includes('UNIQUE')) return res.status(400).json({ error: 'Username or initials already taken.' });
    log('error', 'auth.setup.error', { msg: e.message });
    res.status(500).json({ error: 'Failed to create account.' });
  }
});

// ── AUTH: REGISTER ─────────────────────────────
app.post('/auth/register', async (req, res) => {
  if (getConfig('allow_registration','1') !== '1') return res.status(403).json({ error: 'Registration is disabled.' });
  const { username, email, password, confirmPassword, initials, mfaType } = req.body;
  if (!username || !password)       return res.status(400).json({ error: 'Username and password required.' });
  if (password !== confirmPassword) return res.status(400).json({ error: 'Passwords do not match.' });
  if (password.length < 8)          return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (!initials || !/^[A-Za-z0-9]{2,4}$/.test(initials)) return res.status(400).json({ error: 'Initials must be 2–4 alphanumeric characters.' });
  const smtpOk  = !!getSmtpConfig()?.host;
  const allowed = smtpOk ? ['none','totp','email'] : ['none','totp'];
  const chosenMfa = allowed.includes(mfaType) ? mfaType : 'none';
  if (chosenMfa === 'email' && !email) return res.status(400).json({ error: 'Email required for email MFA.' });
  try {
    const hash = await bcrypt.hash(password, 12);
    db.prepare('INSERT INTO users (username,email,password_hash,initials,role,mfa_type,created_at) VALUES (?,?,?,?,?,?,?)')
      .run(username.trim().toLowerCase(), email?.trim()||null, hash, initials.toUpperCase(), 'user', chosenMfa, Date.now());
    const user = db.prepare('SELECT * FROM users WHERE username=?').get(username.trim().toLowerCase());
    log('info', 'auth.register', { user: user.username, initials: user.initials, ip: ip(req) });
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'Session error.' });
      req.session.userId = user.id; req.session.userRole = 'user';
      if (chosenMfa === 'totp') { req.session.setupMfa = true; return res.json({ redirect: '/setup-mfa' }); }
      req.session.authenticated = true;
      res.json({ redirect: '/' });
    });
  } catch(e) {
    if (e.message?.includes('UNIQUE')) return res.status(400).json({ error: 'Username, email, or initials already taken.' });
    log('error', 'auth.register.error', { msg: e.message, ip: ip(req) });
    res.status(500).json({ error: 'Failed to create account.' });
  }
});

// ── AUTH: LOGIN ────────────────────────────────
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username.trim().toLowerCase());
  if (!user) {
    log('warn', 'auth.login.fail', { user: username.trim(), reason: 'user_not_found', ip: ip(req) });
    return res.status(401).json({ error: 'Invalid username or password.' });
  }
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    log('warn', 'auth.login.fail', { user: user.username, reason: 'bad_password', ip: ip(req) });
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  req.session.regenerate(async err => {
    if (err) return res.status(500).json({ error: 'Session error.' });
    req.session.userId   = user.id;
    req.session.userRole = user.role;

    if (user.mfa_type === 'none') {
      req.session.authenticated = true;
      log('info', 'auth.login.success', { user: user.username, mfa: 'none', ip: ip(req) });
      return res.json({ redirect: '/' });
    }
    if (user.mfa_type === 'totp') {
      if (!user.totp_secret) { req.session.setupMfa = true; return res.json({ redirect: '/setup-mfa' }); }
      req.session.mfaPending = true; req.session.mfaType = 'totp';
      log('info', 'auth.login.mfa_pending', { user: user.username, mfa: 'totp', ip: ip(req) });
      return res.json({ redirect: '/mfa' });
    }
    if (user.mfa_type === 'email') {
      if (!user.email) { req.session.authenticated = true; return res.json({ redirect: '/' }); }
      const code     = String(Math.floor(100000 + Math.random() * 900000));
      const codeHash = crypto.createHash('sha256').update(code).digest('hex');
      req.session.mfaPending = true; req.session.mfaType = 'email';
      req.session.emailCode  = { hash: codeHash, expiresAt: Date.now() + 10*60*1000 };
      try {
        await sendEmail({ to: user.email, subject: 'Harborbucks — Login Code',
          text:  `Your Harborbucks login code is: ${code}\n\nExpires in 10 minutes.`,
          html:  `<p>Your login code is: <strong style="font-size:1.4em">${code}</strong></p><p>Expires in 10 minutes.</p>` });
        log('info', 'auth.login.mfa_pending', { user: user.username, mfa: 'email', ip: ip(req) });
        return res.json({ redirect: '/mfa' });
      } catch(e) {
        log('error', 'auth.mfa.email_send_fail', { user: user.username, msg: e.message });
        return res.status(500).json({ error: 'Failed to send MFA email. Contact your administrator.' });
      }
    }
    req.session.authenticated = true;
    res.json({ redirect: '/' });
  });
});

// ── MFA INFO ───────────────────────────────────
app.get('/auth/mfa-info', (req, res) => {
  if (!req.session?.mfaPending) return res.status(403).json({ error: 'No MFA pending.' });
  res.json({ type: req.session.mfaType || 'totp' });
});

// ── MFA: VERIFY ────────────────────────────────
app.post('/auth/mfa', (req, res) => {
  if (!req.session?.mfaPending) return res.status(403).json({ error: 'Unauthorized.' });
  const { token } = req.body;
  const type = req.session.mfaType || 'totp';
  const user = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId);

  if (type === 'totp') {
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);
    if (!u?.totp_secret) return res.status(500).json({ error: 'MFA not configured.' });
    if (!authenticator.verify({ token: String(token).trim(), secret: u.totp_secret })) {
      log('warn', 'auth.mfa.fail', { user: user?.username, type, ip: ip(req) });
      return res.status(401).json({ error: 'Invalid code. Try again.' });
    }
  } else if (type === 'email') {
    const ec = req.session.emailCode;
    if (!ec) return res.status(400).json({ error: 'No code pending.' });
    if (Date.now() > ec.expiresAt) {
      delete req.session.emailCode;
      log('warn', 'auth.mfa.expired', { user: user?.username, type, ip: ip(req) });
      return res.status(401).json({ error: 'Code expired. Please log in again.' });
    }
    if (crypto.createHash('sha256').update(String(token).trim()).digest('hex') !== ec.hash) {
      log('warn', 'auth.mfa.fail', { user: user?.username, type, ip: ip(req) });
      return res.status(401).json({ error: 'Invalid code. Try again.' });
    }
    delete req.session.emailCode;
  }

  delete req.session.mfaPending; delete req.session.mfaType;
  req.session.authenticated = true;
  log('info', 'auth.login.success', { user: user?.username, mfa: type, ip: ip(req) });
  res.json({ redirect: '/' });
});

// ── MFA: RESEND EMAIL ──────────────────────────
app.post('/auth/mfa/resend', async (req, res) => {
  if (!req.session?.mfaPending || req.session.mfaType !== 'email') return res.status(403).json({ error: 'Unauthorized.' });
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);
  if (!user?.email) return res.status(400).json({ error: 'No email on file.' });
  const code     = String(Math.floor(100000 + Math.random() * 900000));
  const codeHash = crypto.createHash('sha256').update(code).digest('hex');
  req.session.emailCode = { hash: codeHash, expiresAt: Date.now() + 10*60*1000 };
  try {
    await sendEmail({ to: user.email, subject: 'Harborbucks — New Login Code',
      text:  `Your new code is: ${code}\n\nExpires in 10 minutes.`,
      html:  `<p>Your new code is: <strong style="font-size:1.4em">${code}</strong></p><p>Expires in 10 minutes.</p>` });
    log('info', 'auth.mfa.resend', { user: user.username, ip: ip(req) });
    res.json({ ok: true });
  } catch(e) {
    log('error', 'auth.mfa.resend_fail', { user: user.username, msg: e.message });
    res.status(500).json({ error: 'Failed to send email.' });
  }
});

// ── TOTP SETUP ─────────────────────────────────
app.get('/auth/setup-mfa/qr', (req, res) => {
  if (!req.session?.setupMfa) return res.status(403).json({ error: 'Unauthorized.' });
  const user   = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);
  const secret = authenticator.generateSecret();
  req.session.pendingTotpSecret = secret;
  QRCode.toDataURL(authenticator.keyuri(user.username, 'Harborbucks', secret), { width: 220, margin: 1 }, (err, url) => {
    if (err) return res.status(500).json({ error: 'QR generation failed.' });
    res.json({ qrDataUrl: url, secret });
  });
});

app.post('/auth/setup-mfa/verify', (req, res) => {
  if (!req.session?.setupMfa) return res.status(403).json({ error: 'Unauthorized.' });
  const { token } = req.body;
  const secret    = req.session.pendingTotpSecret;
  if (!secret || !token) return res.status(400).json({ error: 'Missing token.' });
  if (!authenticator.verify({ token: String(token).trim(), secret })) {
    log('warn', 'auth.mfa.setup_fail', { user: db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username, ip: ip(req) });
    return res.status(401).json({ error: 'Invalid code. Try again.' });
  }
  db.prepare('UPDATE users SET totp_secret=?, mfa_type=? WHERE id=?').run(secret, 'totp', req.session.userId);
  const username = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username;
  log('info', 'auth.mfa.setup_complete', { user: username, type: 'totp', ip: ip(req) });
  delete req.session.setupMfa; delete req.session.pendingTotpSecret;
  req.session.authenticated = true;
  res.json({ redirect: '/' });
});

// ── PASSWORD RESET ─────────────────────────────
app.post('/auth/reset-request', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required.' });
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email.trim().toLowerCase());
  if (!user) return res.json({ ok: true });
  const token     = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  db.prepare('DELETE FROM auth_tokens WHERE user_id=? AND purpose=?').run(user.id, 'password_reset');
  db.prepare('INSERT INTO auth_tokens (user_id,token_hash,purpose,expires_at) VALUES (?,?,?,?)').run(user.id, tokenHash, 'password_reset', Date.now()+3600000);
  const resetUrl = `${req.protocol}://${req.get('host')}/reset-confirm?token=${token}`;
  try {
    await sendEmail({ to: user.email, subject: 'Harborbucks — Password Reset',
      text:  `Reset your password: ${resetUrl}\n\nExpires in 1 hour.`,
      html:  `<p>Click to reset your password:</p><p><a href="${resetUrl}">${resetUrl}</a></p><p>Expires in 1 hour.</p>` });
    log('info', 'auth.password_reset.requested', { user: user.username, ip: ip(req) });
    res.json({ ok: true });
  } catch(e) {
    log('error', 'auth.password_reset.email_fail', { user: user.username, msg: e.message });
    res.status(500).json({ error: 'Failed to send reset email.' });
  }
});

app.post('/auth/reset-confirm', async (req, res) => {
  const { token, password, confirmPassword } = req.body;
  if (!token || !password)          return res.status(400).json({ error: 'Token and password required.' });
  if (password !== confirmPassword) return res.status(400).json({ error: 'Passwords do not match.' });
  if (password.length < 8)          return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const tokenRow  = db.prepare('SELECT * FROM auth_tokens WHERE token_hash=? AND purpose=? AND used=0').get(tokenHash, 'password_reset');
  if (!tokenRow) return res.status(400).json({ error: 'Invalid or expired reset link.' });
  if (Date.now() > tokenRow.expires_at) {
    db.prepare('DELETE FROM auth_tokens WHERE id=?').run(tokenRow.id);
    return res.status(400).json({ error: 'Reset link has expired.' });
  }
  const hash = await bcrypt.hash(password, 12);
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hash, tokenRow.user_id);
  db.prepare('UPDATE auth_tokens SET used=1 WHERE id=?').run(tokenRow.id);
  const username = db.prepare('SELECT username FROM users WHERE id=?').get(tokenRow.user_id)?.username;
  log('info', 'auth.password_reset.complete', { user: username, ip: ip(req) });
  res.json({ ok: true });
});

// ── ME ─────────────────────────────────────────
app.get('/api/me', requireAuth, (req, res) => {
  const u = db.prepare('SELECT id,username,email,initials,role,mfa_type FROM users WHERE id=?').get(req.session.userId);
  if (!u) return res.status(404).json({ error: 'Not found.' });
  res.json(u);
});

app.post('/api/me/update', requireAuth, async (req, res) => {
  const { field, value, currentPassword, newPassword, confirmPassword, mfaType } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  if (field === 'email') {
    const email = value?.trim() || null;
    try {
      db.prepare('UPDATE users SET email=? WHERE id=?').run(email, user.id);
      log('info', 'account.email_updated', { user: user.username });
      return res.json({ ok: true });
    } catch(e) {
      if (e.message?.includes('UNIQUE')) return res.status(400).json({ error: 'Email already in use.' });
      return res.status(500).json({ error: 'Failed to update email.' });
    }
  }

  if (field === 'initials') {
    const initials = value?.trim().toUpperCase();
    if (!initials || !/^[A-Za-z0-9]{2,4}$/.test(initials))
      return res.status(400).json({ error: 'Initials must be 2–4 letters or numbers.' });
    try {
      db.prepare('UPDATE users SET initials=? WHERE id=?').run(initials, user.id);
      log('info', 'account.initials_updated', { user: user.username, initials });
      return res.json({ ok: true, initials });
    } catch(e) {
      if (e.message?.includes('UNIQUE')) return res.status(400).json({ error: 'Those initials are already taken.' });
      return res.status(500).json({ error: 'Failed to update initials.' });
    }
  }

  if (field === 'password') {
    if (!currentPassword) return res.status(400).json({ error: 'Current password required.' });
    if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    if (newPassword !== confirmPassword) return res.status(400).json({ error: 'Passwords do not match.' });
    const match = await bcrypt.compare(currentPassword, user.password_hash);
    if (!match) {
      log('warn', 'account.password_change.fail', { user: user.username, reason: 'bad_current_password', ip: ip(req) });
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await bcrypt.hash(newPassword, 12), user.id);
    log('info', 'account.password_changed', { user: user.username, ip: ip(req) });
    return res.json({ ok: true });
  }

  if (field === 'mfa') {
    const smtpOk  = !!getSmtpConfig()?.host;
    const allowed = smtpOk ? ['none','totp','email'] : ['none','totp'];
    if (!allowed.includes(mfaType)) return res.status(400).json({ error: 'Invalid MFA type.' });
    if (mfaType === 'email' && !user.email) return res.status(400).json({ error: 'Add an email address before enabling email MFA.' });
    if (mfaType === 'totp') {
      req.session.setupMfa = true;
      db.prepare('UPDATE users SET mfa_type=?, totp_secret=NULL WHERE id=?').run('totp', user.id);
      log('info', 'account.mfa_changed', { user: user.username, from: user.mfa_type, to: 'totp' });
      return res.json({ ok: true, redirect: '/setup-mfa' });
    }
    db.prepare('UPDATE users SET mfa_type=?, totp_secret=NULL WHERE id=?').run(mfaType, user.id);
    log('info', 'account.mfa_changed', { user: user.username, from: user.mfa_type, to: mfaType });
    return res.json({ ok: true });
  }

  res.status(400).json({ error: 'Unknown field.' });
});

// ── USERS: INITIALS LIST ───────────────────────
app.get('/api/users/initials', requireAuth, (_req, res) => {
  res.json(db.prepare('SELECT initials, username FROM users ORDER BY initials').all());
});

// ── ADMIN: USERS ───────────────────────────────
app.get('/api/admin/users', requireAdmin, (_req, res) => {
  res.json(db.prepare('SELECT id,username,email,initials,role,mfa_type,created_at FROM users ORDER BY created_at').all());
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  const { username, email, password, initials, role, mfaType } = req.body;
  if (!username || !password || !initials) return res.status(400).json({ error: 'Username, password, and initials required.' });
  if (!/^[A-Za-z0-9]{2,4}$/.test(initials)) return res.status(400).json({ error: 'Initials must be 2–4 alphanumeric characters.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const smtpOk  = !!getSmtpConfig()?.host;
  const allowed = smtpOk ? ['none','totp','email'] : ['none','totp'];
  const chosenMfa  = allowed.includes(mfaType) ? mfaType : 'none';
  const chosenRole = ['admin','user'].includes(role) ? role : 'user';
  if (chosenMfa === 'email' && !email) return res.status(400).json({ error: 'Email required for email MFA.' });
  try {
    const hash = await bcrypt.hash(password, 12);
    db.prepare('INSERT INTO users (username,email,password_hash,initials,role,mfa_type,created_at) VALUES (?,?,?,?,?,?,?)')
      .run(username.trim().toLowerCase(), email?.trim()||null, hash, initials.toUpperCase(), chosenRole, chosenMfa, Date.now());
    const u = db.prepare('SELECT id,username,email,initials,role,mfa_type,created_at FROM users WHERE username=?').get(username.trim().toLowerCase());
    const adminUser = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username;
    log('info', 'admin.user.created', { admin: adminUser, new_user: u.username, initials: u.initials, role: chosenRole });
    res.status(201).json(u);
  } catch(e) {
    if (e.message?.includes('UNIQUE')) return res.status(400).json({ error: 'Username, email, or initials already taken.' });
    res.status(500).json({ error: 'Failed to create user.' });
  }
});

app.patch('/api/admin/users/:id/reset-password', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const target    = db.prepare('SELECT username FROM users WHERE id=?').get(id);
  const adminUser = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username;
  const result = db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await bcrypt.hash(password, 12), id);
  if (!result.changes) return res.status(404).json({ error: 'User not found.' });
  log('warn', 'admin.user.password_reset', { admin: adminUser, target: target?.username, ip: ip(req) });
  res.json({ ok: true });
});

app.patch('/api/admin/users/:id/reset-mfa', requireAdmin, (req, res) => {
  const { id } = req.params;
  const target    = db.prepare('SELECT username FROM users WHERE id=?').get(id);
  const adminUser = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username;
  const result = db.prepare('UPDATE users SET mfa_type=?,totp_secret=NULL WHERE id=?').run('none', id);
  if (!result.changes) return res.status(404).json({ error: 'User not found.' });
  log('warn', 'admin.user.mfa_reset', { admin: adminUser, target: target?.username });
  res.json({ ok: true });
});

app.patch('/api/admin/users/:id/role', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  if (!['admin','user'].includes(role)) return res.status(400).json({ error: 'Invalid role.' });
  if (role === 'user') {
    const target     = db.prepare('SELECT role FROM users WHERE id=?').get(id);
    const adminCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role='admin'").get().c;
    if (target?.role === 'admin' && adminCount <= 1) return res.status(400).json({ error: 'Cannot remove the last admin.' });
  }
  const target    = db.prepare('SELECT username FROM users WHERE id=?').get(id);
  const adminUser = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username;
  const result = db.prepare('UPDATE users SET role=? WHERE id=?').run(role, id);
  if (!result.changes) return res.status(404).json({ error: 'User not found.' });
  log('info', 'admin.user.role_changed', { admin: adminUser, target: target?.username, new_role: role });
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  if (Number(id) === req.session.userId) return res.status(400).json({ error: "Can't delete your own account." });
  const target     = db.prepare('SELECT username,role FROM users WHERE id=?').get(id);
  const adminCount = db.prepare("SELECT COUNT(*) as c FROM users WHERE role='admin'").get().c;
  if (target?.role === 'admin' && adminCount <= 1) return res.status(400).json({ error: 'Cannot delete the last admin.' });
  const adminUser = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username;
  const result = db.prepare('DELETE FROM users WHERE id=?').run(id);
  if (!result.changes) return res.status(404).json({ error: 'User not found.' });
  log('warn', 'admin.user.deleted', { admin: adminUser, target: target?.username });
  res.json({ ok: true });
});

// ── ADMIN: SETTINGS ────────────────────────────
app.get('/api/admin/settings', requireAdmin, (_req, res) => {
  const smtp = getSmtpConfig() || {};
  res.json({
    allowRegistration: getConfig('allow_registration','1') === '1',
    smtp: { host: smtp.host||'', port: smtp.port||587, user: smtp.user||'', from: smtp.from||'', secure: smtp.secure||false, hasPassword: !!smtp.pass },
  });
});

app.post('/api/admin/settings', requireAdmin, (req, res) => {
  const { allowRegistration, smtp } = req.body;
  const adminUser = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username;
  if (allowRegistration !== undefined) {
    setConfig('allow_registration', allowRegistration ? '1' : '0');
    log('info', 'admin.settings.registration', { admin: adminUser, enabled: allowRegistration });
  }
  if (smtp) {
    const existing = getSmtpConfig() || {};
    setConfig('smtp_config', JSON.stringify({
      host:   smtp.host   || '',
      port:   smtp.port   || 587,
      user:   smtp.user   || '',
      pass:   smtp.pass   ? smtp.pass : (existing.pass || ''),
      from:   smtp.from   || '',
      secure: smtp.secure || false,
    }));
    log('info', 'admin.settings.smtp_updated', { admin: adminUser, host: smtp.host });
  }
  res.json({ ok: true });
});

app.post('/api/admin/settings/test-smtp', requireAdmin, async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'A valid recipient email address is required.' });
  const u = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId);
  try {
    await sendEmail({ to: email, subject: 'Harborbucks — SMTP Test', text: 'SMTP is working correctly.', html: '<p>SMTP is working correctly.</p>' });
    log('info', 'admin.smtp.test_ok', { admin: u?.username, to: email });
    res.json({ ok: true });
  } catch(e) {
    log('error', 'admin.smtp.test_fail', { admin: u?.username, msg: e.message });
    res.status(500).json({ error: e.message });
  }
});

// ── ADMIN: LOGS ────────────────────────────────
app.get('/api/admin/logs', requireAdmin, (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit)  || 500, 2000);
  const level  = req.query.level  || '';
  const search = req.query.search || '';

  if (!fs.existsSync(LOG_PATH)) return res.json([]);
  try {
    const stat      = fs.statSync(LOG_PATH);
    const chunkSize = Math.min(stat.size, 1024 * 1024); // read last 1 MB
    const buf       = Buffer.alloc(chunkSize);
    const fd        = fs.openSync(LOG_PATH, 'r');
    fs.readSync(fd, buf, 0, chunkSize, stat.size - chunkSize);
    fs.closeSync(fd);

    const entries = buf.toString('utf8')
      .split('\n')
      .filter(l => l.trim())
      .map(l => { try { return JSON.parse(l); } catch { return null; } })
      .filter(Boolean)
      .reverse()
      .filter(e => !level  || e.level === level)
      .filter(e => !search || JSON.stringify(e).toLowerCase().includes(search.toLowerCase()))
      .slice(0, limit);

    res.json(entries);
  } catch(e) {
    res.status(500).json({ error: 'Failed to read logs.' });
  }
});

app.get('/api/admin/logs/download', requireAdmin, (req, res) => {
  if (!fs.existsSync(LOG_PATH)) return res.status(404).send('No log file yet.');
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', `attachment; filename="harborbucks-${new Date().toISOString().slice(0,10)}.log"`);
  fs.createReadStream(LOG_PATH).pipe(res);
});

// ── ENTRIES API ────────────────────────────────
function rowToEntry(r) {
  return { id: r.id, serials: JSON.parse(r.serials), checkNumber: r.check_number,
    voucherCount: r.voucher_count, amount: r.amount, manager: r.manager,
    voided: r.status === 'voided', status: r.status || 'active', createdAt: r.created_at };
}
function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2,7); }

app.get('/api/entries', requireAuth, (_req, res) => {
  try { res.json(db.prepare('SELECT * FROM entries ORDER BY created_at DESC').all().map(rowToEntry)); }
  catch(e) { log('error', 'entries.fetch_fail', { msg: e.message }); res.status(500).json({ error: 'Failed to fetch entries.' }); }
});

app.post('/api/entries', requireAuth, (req, res) => {
  const { serials, checkNumber, voucherCount, amount, manager } = req.body;
  if (!Array.isArray(serials)||!serials.length) return res.status(400).json({ error: 'At least one serial required.' });
  if (!checkNumber)                             return res.status(400).json({ error: 'Check number required.' });
  if (!voucherCount||voucherCount<1)            return res.status(400).json({ error: 'Valid voucher count required.' });
  if (amount==null||isNaN(amount)||amount<0)    return res.status(400).json({ error: 'Valid amount required.' });
  if (!manager)                                 return res.status(400).json({ error: 'Manager initials required.' });
  try {
    const e = { id: uid(), serials: JSON.stringify(serials), check_number: checkNumber,
      voucher_count: voucherCount, amount: parseFloat(amount), manager: manager.trim().toUpperCase(), voided: 0, status: 'active', created_at: Date.now() };
    db.prepare('INSERT INTO entries (id,serials,check_number,voucher_count,amount,manager,voided,status,created_at) VALUES (@id,@serials,@check_number,@voucher_count,@amount,@manager,@voided,@status,@created_at)').run(e);
    const username = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username;
    log('info', 'entry.created', { user: username, manager, checkNumber, amount: parseFloat(amount), serials });
    res.status(201).json(rowToEntry(e));
  } catch(e) { log('error', 'entry.create_fail', { msg: e.message }); res.status(500).json({ error: 'Failed to create entry.' }); }
});

app.put('/api/entries/:id', requireAuth, (req, res) => {
  const { serials, checkNumber, voucherCount, amount, manager } = req.body;
  const { id } = req.params;
  if (!Array.isArray(serials)||!serials.length||!checkNumber||!voucherCount||amount==null||!manager)
    return res.status(400).json({ error: 'All fields required.' });
  try {
    const result = db.prepare('UPDATE entries SET serials=@serials,check_number=@check_number,voucher_count=@voucher_count,amount=@amount,manager=@manager WHERE id=@id')
      .run({ id, serials: JSON.stringify(serials), check_number: checkNumber, voucher_count: voucherCount, amount: parseFloat(amount), manager: manager.trim().toUpperCase() });
    if (!result.changes) return res.status(404).json({ error: 'Entry not found.' });
    const username = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username;
    log('info', 'entry.edited', { user: username, entryId: id, checkNumber, amount: parseFloat(amount) });
    res.json(rowToEntry(db.prepare('SELECT * FROM entries WHERE id=?').get(id)));
  } catch(e) { log('error', 'entry.edit_fail', { msg: e.message }); res.status(500).json({ error: 'Failed to update entry.' }); }
});

app.patch('/api/entries/:id/void', requireAuth, (req, res) => {
  const { id } = req.params;
  try {
    const row = db.prepare('SELECT * FROM entries WHERE id=?').get(id);
    if (!row) return res.status(404).json({ error: 'Entry not found.' });
    const newStatus = row.status === 'voided' ? 'active' : 'voided';
    db.prepare('UPDATE entries SET voided=?, status=? WHERE id=?').run(newStatus === 'voided' ? 1 : 0, newStatus, id);
    const updated  = db.prepare('SELECT * FROM entries WHERE id=?').get(id);
    const username = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username;
    log('warn', newStatus === 'voided' ? 'entry.voided' : 'entry.restored', { user: username, entryId: id, checkNumber: row.check_number, amount: row.amount });
    res.json(rowToEntry(updated));
  } catch(e) { log('error', 'entry.void_fail', { msg: e.message }); res.status(500).json({ error: 'Failed to toggle void.' }); }
});

app.patch('/api/entries/:id/archive', requireAuth, (req, res) => {
  const { id } = req.params;
  try {
    const row = db.prepare('SELECT * FROM entries WHERE id=?').get(id);
    if (!row) return res.status(404).json({ error: 'Entry not found.' });
    const newStatus = row.status === 'archived' ? 'active' : 'archived';
    db.prepare('UPDATE entries SET voided=0, status=? WHERE id=?').run(newStatus, id);
    const updated  = db.prepare('SELECT * FROM entries WHERE id=?').get(id);
    const username = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username;
    log('warn', newStatus === 'archived' ? 'entry.archived' : 'entry.restored', { user: username, entryId: id, checkNumber: row.check_number, amount: row.amount });
    res.json(rowToEntry(updated));
  } catch(e) { log('error', 'entry.archive_fail', { msg: e.message }); res.status(500).json({ error: 'Failed to toggle archive.' }); }
});

app.patch('/api/entries/:id/delete', requireAuth, (req, res) => {
  const { id } = req.params;
  try {
    const row = db.prepare('SELECT * FROM entries WHERE id=?').get(id);
    if (!row) return res.status(404).json({ error: 'Entry not found.' });
    const newStatus = row.status === 'deleted' ? 'active' : 'deleted';
    db.prepare('UPDATE entries SET voided=0, status=? WHERE id=?').run(newStatus, id);
    const updated  = db.prepare('SELECT * FROM entries WHERE id=?').get(id);
    const username = db.prepare('SELECT username FROM users WHERE id=?').get(req.session.userId)?.username;
    log('warn', newStatus === 'deleted' ? 'entry.deleted' : 'entry.restored', { user: username, entryId: id, checkNumber: row.check_number, amount: row.amount });
    res.json(rowToEntry(updated));
  } catch(e) { log('error', 'entry.delete_fail', { msg: e.message }); res.status(500).json({ error: 'Failed to toggle delete.' }); }
});

// ── START ──────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  log('info', 'server.start', { port: PORT, db: DB_PATH, log: LOG_PATH });
});
