const express  = require('express');
const session  = require('express-session');
const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
const crypto   = require('crypto');

const app     = express();
const PORT    = process.env.PORT    || 3001;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'lost-items.db');

// ── DATABASE ───────────────────────────────────
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS lost_items (
    id              TEXT PRIMARY KEY,
    item_type       TEXT NOT NULL,
    description     TEXT NOT NULL,
    found_location  TEXT,
    found_by        TEXT NOT NULL,
    found_at        INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'unclaimed',
    customer_name   TEXT,
    customer_phone  TEXT,
    returned_to     TEXT,
    returned_by     TEXT,
    returned_at     INTEGER,
    notes           TEXT,
    created_at      INTEGER NOT NULL
  );
`);

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

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

// ── MIDDLEWARE ─────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(session({
  secret:            getOrCreateSecret(),
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure:   process.env.SECURE_COOKIES === 'true',
    maxAge:   12 * 60 * 60 * 1000,   // 12 hours
  },
}));

// ── AUTH ───────────────────────────────────────
// Simple shared-PIN authentication for restaurant staff.
// Set the PIN via the setup page on first run, or via
// the LOST_ITEMS_PIN environment variable.

function getPIN() {
  return process.env.LOST_ITEMS_PIN || getConfig('pin');
}

function requireAuth(req, res, next) {
  if (req.session?.authenticated) return next();
  res.status(401).json({ error: 'Not authenticated.' });
}

function pageAuth(req, res, next) {
  if (req.session?.authenticated) return next();
  res.redirect('/login');
}

// ── HTML ROUTES ───────────────────────────────
app.get('/', pageAuth, (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  if (req.session?.authenticated) return res.redirect('/');
  if (!getPIN()) return res.redirect('/setup');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/setup', (req, res) => {
  if (getPIN()) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'setup.html'));
});

// ── AUTH API ──────────────────────────────────
app.post('/auth/setup', (req, res) => {
  if (getPIN()) return res.status(403).json({ error: 'Already configured.' });
  const { pin } = req.body;
  if (!pin || pin.length < 4) return res.status(400).json({ error: 'PIN must be at least 4 characters.' });
  setConfig('pin', pin);
  req.session.authenticated = true;
  res.json({ ok: true });
});

app.post('/auth/login', (req, res) => {
  const { pin } = req.body;
  const stored = getPIN();
  if (!stored) return res.status(400).json({ error: 'Not set up yet.' });
  if (pin !== stored) return res.status(401).json({ error: 'Incorrect PIN.' });
  req.session.authenticated = true;
  res.json({ ok: true });
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ── LOST ITEMS API ────────────────────────────
app.get('/api/lost-items', requireAuth, (req, res) => {
  try {
    const { status, type, search } = req.query;
    let sql = 'SELECT * FROM lost_items';
    const conditions = [];
    const params = [];
    if (status && status !== 'all') { conditions.push('status = ?'); params.push(status); }
    if (type && type !== 'all') { conditions.push('item_type = ?'); params.push(type); }
    if (search) {
      conditions.push('(description LIKE ? OR customer_name LIKE ? OR customer_phone LIKE ? OR notes LIKE ? OR found_location LIKE ?)');
      const s = `%${search}%`;
      params.push(s, s, s, s, s);
    }
    if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
    sql += ' ORDER BY created_at DESC';
    res.json(db.prepare(sql).all(...params));
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch lost items.' });
  }
});

app.get('/api/lost-items/stats', requireAuth, (_req, res) => {
  try {
    const unclaimed = db.prepare("SELECT COUNT(*) as c FROM lost_items WHERE status='unclaimed'").get().c;
    const returned  = db.prepare("SELECT COUNT(*) as c FROM lost_items WHERE status='returned'").get().c;
    const disposed  = db.prepare("SELECT COUNT(*) as c FROM lost_items WHERE status='disposed'").get().c;
    const total = unclaimed + returned + disposed;
    const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
    const aging = db.prepare("SELECT COUNT(*) as c FROM lost_items WHERE status='unclaimed' AND found_at < ?").get(thirtyDaysAgo).c;
    res.json({ unclaimed, returned, disposed, total, aging });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch stats.' });
  }
});

app.post('/api/lost-items', requireAuth, (req, res) => {
  const { itemType, description, foundLocation, foundBy, foundAt, customerName, customerPhone, notes } = req.body;
  if (!itemType) return res.status(400).json({ error: 'Item type required.' });
  if (!description?.trim()) return res.status(400).json({ error: 'Description required.' });
  if (!foundBy?.trim()) return res.status(400).json({ error: 'Found-by initials required.' });
  try {
    const item = {
      id: uid(), item_type: itemType, description: description.trim(),
      found_location: foundLocation?.trim() || null,
      found_by: foundBy.trim().toUpperCase(),
      found_at: foundAt || Date.now(), status: 'unclaimed',
      customer_name: customerName?.trim() || null,
      customer_phone: customerPhone?.trim() || null,
      returned_to: null, returned_by: null, returned_at: null,
      notes: notes?.trim() || null, created_at: Date.now()
    };
    db.prepare(`INSERT INTO lost_items (id,item_type,description,found_location,found_by,found_at,status,
      customer_name,customer_phone,returned_to,returned_by,returned_at,notes,created_at)
      VALUES (@id,@item_type,@description,@found_location,@found_by,@found_at,@status,
      @customer_name,@customer_phone,@returned_to,@returned_by,@returned_at,@notes,@created_at)`).run(item);
    res.status(201).json(item);
  } catch (e) {
    res.status(500).json({ error: 'Failed to log item.' });
  }
});

app.put('/api/lost-items/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const { itemType, description, foundLocation, foundBy, foundAt, customerName, customerPhone, notes } = req.body;
  if (!itemType || !description?.trim() || !foundBy?.trim())
    return res.status(400).json({ error: 'Type, description, and found-by required.' });
  try {
    const result = db.prepare(`UPDATE lost_items SET item_type=?, description=?, found_location=?,
      found_by=?, found_at=?, customer_name=?, customer_phone=?, notes=? WHERE id=?`)
      .run(itemType, description.trim(), foundLocation?.trim() || null,
        foundBy.trim().toUpperCase(), foundAt || Date.now(),
        customerName?.trim() || null, customerPhone?.trim() || null,
        notes?.trim() || null, id);
    if (!result.changes) return res.status(404).json({ error: 'Item not found.' });
    res.json(db.prepare('SELECT * FROM lost_items WHERE id=?').get(id));
  } catch (e) {
    res.status(500).json({ error: 'Failed to update item.' });
  }
});

app.patch('/api/lost-items/:id/return', requireAuth, (req, res) => {
  const { id } = req.params;
  const { returnedTo, returnedBy } = req.body;
  if (!returnedTo?.trim()) return res.status(400).json({ error: 'Name of person picking up is required.' });
  if (!returnedBy?.trim()) return res.status(400).json({ error: 'Staff initials required.' });
  try {
    const row = db.prepare('SELECT * FROM lost_items WHERE id=?').get(id);
    if (!row) return res.status(404).json({ error: 'Item not found.' });
    if (row.status !== 'unclaimed') return res.status(400).json({ error: 'Item is not unclaimed.' });
    db.prepare('UPDATE lost_items SET status=?, returned_to=?, returned_by=?, returned_at=? WHERE id=?')
      .run('returned', returnedTo.trim(), returnedBy.trim().toUpperCase(), Date.now(), id);
    res.json(db.prepare('SELECT * FROM lost_items WHERE id=?').get(id));
  } catch (e) {
    res.status(500).json({ error: 'Failed to mark as returned.' });
  }
});

app.patch('/api/lost-items/:id/dispose', requireAuth, (req, res) => {
  const { id } = req.params;
  try {
    const row = db.prepare('SELECT * FROM lost_items WHERE id=?').get(id);
    if (!row) return res.status(404).json({ error: 'Item not found.' });
    if (row.status !== 'unclaimed') return res.status(400).json({ error: 'Item is not unclaimed.' });
    db.prepare("UPDATE lost_items SET status='disposed' WHERE id=?").run(id);
    res.json(db.prepare('SELECT * FROM lost_items WHERE id=?').get(id));
  } catch (e) {
    res.status(500).json({ error: 'Failed to dispose item.' });
  }
});

app.patch('/api/lost-items/:id/reopen', requireAuth, (req, res) => {
  const { id } = req.params;
  try {
    const row = db.prepare('SELECT * FROM lost_items WHERE id=?').get(id);
    if (!row) return res.status(404).json({ error: 'Item not found.' });
    db.prepare("UPDATE lost_items SET status='unclaimed', returned_to=NULL, returned_by=NULL, returned_at=NULL WHERE id=?").run(id);
    res.json(db.prepare('SELECT * FROM lost_items WHERE id=?').get(id));
  } catch (e) {
    res.status(500).json({ error: 'Failed to reopen item.' });
  }
});

app.delete('/api/lost-items/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  try {
    const row = db.prepare('SELECT * FROM lost_items WHERE id=?').get(id);
    if (!row) return res.status(404).json({ error: 'Item not found.' });
    db.prepare('DELETE FROM lost_items WHERE id=?').run(id);
    res.json({ ok: true, id });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete item.' });
  }
});

// ── START ──────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Lost Items Log running on port ${PORT}`);
});
