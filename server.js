// server.js
// ------------------------------------------------------------
// Minimal reimbursement backend with proper CORS preflight.
// - CORS_ORIGINS env var: comma-separated list of allowed origins
// - JWT auth for /api/** routes
// - Seeded users: admin/manager/accountant/alice with password: password123
// ------------------------------------------------------------

const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');

// ------------------------
// App & middleware
// ------------------------
const app = express();
app.use(express.json());

// ------------------------
// CORS CONFIG
// ------------------------
const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin: (origin, cb) => {
    // Allow server-to-server (no Origin)
    if (!origin) return cb(null, true);
    const ok = allowedOrigins.includes(origin);
    cb(ok ? null : new Error('Origin not allowed'), ok);
  },
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 204
};

// Must be before routes
app.use(cors(corsOptions));
// Answer preflight for all routes
app.options('*', cors(corsOptions));

// Help caches differentiate per-origin
app.use((req, res, next) => {
  res.header('Vary', 'Origin');
  next();
});

// ------------------------
// DB INITIALIZATION
// ------------------------
const dbFile = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbFile);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
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
      entryDate TEXT,
      note TEXT,
      mgrStatus TEXT DEFAULT 'Pending',
      acctStatus TEXT DEFAULT 'Pending',
      paid INTEGER DEFAULT 0,
      receiptPath TEXT,
      receiptName TEXT,
      receiptMime TEXT,
      employeeId TEXT,
      createdAt TEXT,
      updatedAt TEXT
    )
  `);

  // Seed default users if not present
  const u = await all(`SELECT name FROM Users`);
  if (!u || u.length === 0) {
    const users = [
      { id: cryptoId(), name: 'admin',      password: 'password123', role: 'admin',      email: 'admin@company.local' },
      { id: cryptoId(), name: 'manager',    password: 'password123', role: 'manager',    email: 'mgr@company.local' },
      { id: cryptoId(), name: 'accountant', password: 'password123', role: 'accountant', email: 'acct@company.local' },
      { id: cryptoId(), name: 'alice',      password: 'password123', role: 'employee',   email: 'alice@company.local' }
    ];
    for (const usr of users) {
      await run(
        `INSERT INTO Users (id, name, password, role, email) VALUES (?,?,?,?,?)`,
        [usr.id, usr.name, usr.password, usr.role, usr.email]
      );
    }
    console.log(`Seeded users: admin/manager/accountant/alice with password: password123`);
  }
}
function cryptoId() {
  return [...crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx']
    ? crypto.randomUUID()
    : 'id-' + Math.random().toString(36).slice(2);
}

// Node 18+ has global crypto; fallback
const crypto = globalThis.crypto || require('crypto').webcrypto;

// ------------------------
// AUTH MIDDLEWARE
// ------------------------
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

function authRequired(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { id, name, role }
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
function requireRole(roles = []) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (roles.length === 0 || roles.includes(req.user.role)) return next();
    return res.status(403).json({ error: 'Forbidden' });
  };
}

// ------------------------
// ROUTES
// ------------------------

// Health
app.get('/health', (req, res) => res.json({ ok: true }));

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { name, password } = req.body || {};
    const user = await get(`SELECT * FROM Users WHERE name = ?`, [name]);
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { id: user.id, name: user.name, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({
      token,
      user: { id: user.id, name: user.name, role: user.role, email: user.email }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Auth failed' });
  }
});

// Get expenses
app.get('/api/expenses', authRequired, async (req, res) => {
  try {
    const role = req.user.role;
    if (role === 'employee') {
      const rows = await all(
        `SELECT e.*, u.name as employeeName, u.email as employeeEmail
         FROM Expenses e
         LEFT JOIN Users u ON u.id = e.employeeId
         WHERE employeeId = ?
         ORDER BY datetime(createdAt) DESC`,
        [req.user.id]
      );
      return res.json(rows);
    } else {
      const rows = await all(
        `SELECT e.*, u.name as employeeName, u.email as employeeEmail
         FROM Expenses e
         LEFT JOIN Users u ON u.id = e.employeeId
         ORDER BY datetime(createdAt) DESC`
      );
      return res.json(rows);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch expenses' });
  }
});

// Create expense (employee)
app.post('/api/expenses', authRequired, requireRole(['employee', 'admin']), async (req, res) => {
  try {
    const {
      title = '',
      category = '',
      amount = 0,
      currency = 'INR',
      date = new Date().toISOString().slice(0, 10),
      note = ''
    } = req.body || {};
    const now = new Date().toISOString();
    const id = cryptoId();

    await run(
      `INSERT INTO Expenses
       (id, title, category, amount, currency, date, entryDate, note,
        mgrStatus, acctStatus, paid, receiptPath, receiptName, receiptMime,
        employeeId, createdAt, updatedAt)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        id, title, category, amount, currency, date, null, note,
        'Pending', 'Pending', 0, null, null, null,
        req.user.id, now, now
      ]
    );

    const row = await get(`SELECT * FROM Expenses WHERE id = ?`, [id]);
    res.json(row);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Create failed' });
  }
});

// Manager decision
app.patch('/api/expenses/:id/mgr', authRequired, requireRole(['manager', 'admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { decision } = req.body; // 'Accepted' or 'Declined'
    const exp = await get(`SELECT * FROM Expenses WHERE id = ?`, [id]);
    if (!exp) return res.status(404).json({ error: 'Not found' });

    const mgrStatus = (decision === 'Accepted') ? 'Accepted' : 'Declined';
    const now = new Date().toISOString();

    await run(
      `UPDATE Expenses SET mgrStatus = ?, updatedAt = ? WHERE id = ?`,
      [mgrStatus, now, id]
    );

    const updated = await get(`SELECT * FROM Expenses WHERE id = ?`, [id]);
    res.json(updated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Manager decision failed' });
  }
});

// Accountant decision
app.patch('/api/expenses/:id/acct', authRequired, requireRole(['accountant', 'admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { decision } = req.body; // 'Approved' or 'Declined'
    const exp = await get(`SELECT * FROM Expenses WHERE id = ?`, [id]);
    if (!exp) return res.status(404).json({ error: 'Not found' });

    // If manager declined, accountant cannot approve
    if (exp.mgrStatus === 'Declined' && decision === 'Approved') {
      return res.status(400).json({ error: 'Manager declined; cannot approve' });
    }

    const acctStatus = (decision === 'Approved') ? 'Approved' : 'Declined';
    const now = new Date().toISOString();

    await run(
      `UPDATE Expenses SET acctStatus = ?, updatedAt = ? WHERE id = ?`,
      [acctStatus, now, id]
    );

    const updated = await get(`SELECT * FROM Expenses WHERE id = ?`, [id]);
    res.json(updated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Accountant decision failed' });
  }
});

// ------------------------
// START SERVER
// ------------------------
(async () => {
  await initDb();

  const PORT = process.env.PORT || 10000;
  app.listen(PORT, () => {
    console.log(`Server started on http://localhost:${PORT}`);
  });
})();
