/**
 * Reimburse backend – Express + SQLite + JWT
 * ==========================================
 *  - Login:         POST /api/auth/login  -> { token, user }
 *  - Current user:  GET  /api/auth/me     -> { user }
 *  - Expenses:      GET  /api/expenses    -> [ ... ]
 *  - Health:        GET  /health          -> { ok: true }
 *
 * CORS:
 *  - Set CORS_ORIGINS in env as comma separated list:
 *      CORS_ORIGINS="https://brown-mouse-202848.hostingersite.com,http://localhost:5500"
 */

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.json());

// ----------------------
// ENV & constants
// ----------------------
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

// Allowed origins for CORS, configured via env
const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin: (origin, cb) => {
    // Allow server-to-server or curl (no origin)
    if (!origin) return cb(null, true);
    const ok = allowedOrigins.includes(origin);
    cb(ok ? null : new Error('Origin not allowed'), ok);
  },
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
// Help caches vary per origin
app.use((req, res, next) => {
  res.header('Vary', 'Origin');
  next();
});

// ----------------------
// SQLite setup
// ----------------------
const DB_FILE = path.join(__dirname, 'database.sqlite');
if (!fs.existsSync(DB_FILE)) {
  fs.closeSync(fs.openSync(DB_FILE, 'w'));
}
const db = new sqlite3.Database(DB_FILE);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, function (err, rows) {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, function (err, row) {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

// Create tables
async function initDb() {
  await run(`
    CREATE TABLE IF NOT EXISTS Users (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE,
      password TEXT,
      role TEXT,
      email TEXT
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS Expenses (
      id TEXT PRIMARY KEY,
      title TEXT,
      category TEXT,
      amount REAL,
      currency TEXT,
      date TEXT,
      employeeId TEXT,
      note TEXT,
      receiptPath TEXT,
      receiptName TEXT,
      receiptMime TEXT,
      mgrStatus TEXT DEFAULT 'Pending',
      acctStatus TEXT DEFAULT 'Pending',
      paid INTEGER DEFAULT 0,
      createdAt TEXT DEFAULT (datetime('now')),
      updatedAt TEXT DEFAULT (datetime('now'))
    )
  `);

  // Seed users if not exists
  const count = await get(`SELECT COUNT(*) as c FROM Users`);
  if (!count || count.c === 0) {
    const users = [
      { id: crypto.randomUUID(), name: 'admin',      password: 'password123', role: 'admin',      email: 'admin@company.local' },
      { id: crypto.randomUUID(), name: 'manager',    password: 'password123', role: 'manager',    email: 'manager@company.local' },
      { id: crypto.randomUUID(), name: 'accountant', password: 'password123', role: 'accountant', email: 'accountant@company.local' },
      { id: crypto.randomUUID(), name: 'alice',      password: 'password123', role: 'employee',   email: 'alice@company.local' }
    ];
    for (const u of users) {
      await run(
        `INSERT INTO Users (id, name, password, role, email) VALUES (?, ?, ?, ?, ?)`,
        [u.id, u.name, u.password, u.role, u.email]
      );
    }
    console.log('Seeded users: admin/manager/accountant/alice with password: password123');
  }
}

// ----------------------
// Auth helpers
// ----------------------
function signToken(user) {
  // NEVER put the password inside token
  const payload = {
    user: {
      id: user.id,
      name: user.name,
      role: user.role,
      email: user.email
    }
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function authRequired(req, res, next) {
  const auth = req.headers.authorization || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'Missing or malformed Authorization header' });

  try {
    const payload = jwt.verify(m[1], JWT_SECRET);
    req.user = payload.user || payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ----------------------
// Routes
// ----------------------

// Health
app.get('/health', (req, res) => res.json({ ok: true }));

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { name, password } = req.body || {};
    if (!name || !password) {
      return res.status(400).json({ error: 'name and password are required' });
    }
    const user = await get(`SELECT * FROM Users WHERE name = ?`, [name]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    // Plain-text passwords only for demo (DO NOT use in production)
    if (user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = signToken(user);
    return res.json({
      token,
      user: { id: user.id, name: user.name, role: user.role, email: user.email }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Current user
app.get('/api/auth/me', authRequired, (req, res) => {
  res.json({ user: req.user });
});

// Expenses list
// - admin/manager/accountant: all expenses
// - employee: only own expenses
app.get('/api/expenses', authRequired, async (req, res) => {
  try {
    const role = req.user.role;
    let rows;
    if (role === 'employee') {
      rows = await all(
        `SELECT e.*, u.name as employeeName FROM Expenses e
         LEFT JOIN Users u ON u.id = e.employeeId
         WHERE employeeId = ? ORDER BY createdAt DESC`,
        [req.user.id]
      );
    } else {
      rows = await all(
        `SELECT e.*, u.name as employeeName FROM Expenses e
         LEFT JOIN Users u ON u.id = e.employeeId
         ORDER BY createdAt DESC`
      );
    }
    res.json(rows || []);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to fetch expenses' });
  }
});

// Return JSON 404 for unknown API routes
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ----------------------
// Start
// ----------------------
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Server started on http://localhost:${PORT}`);
    console.log('Available at your primary URL on Render.');
  });
});
