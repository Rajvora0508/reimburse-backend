/* eslint-disable no-console */
require('dotenv').config();

const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

/* -------------------------------------------------------
   BASIC APP
------------------------------------------------------- */
const app = express();
app.use(helmet());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

/* -------------------------------------------------------
   CORS (accepts CORS_ORIGINS or ALLOWED_ORIGINS)
------------------------------------------------------- */
const envOrigins =
  process.env.CORS_ORIGINS ||
  process.env.ALLOWED_ORIGINS ||
  '';

const allowedOrigins = envOrigins
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const defaultAllowed = [
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];

const ORIGINS = allowedOrigins.length ? allowedOrigins : defaultAllowed;

function corsOrigin(origin, cb) {
  // No-origin (curl, Postman, same-host SSR) -> allow
  if (!origin) return cb(null, true);

  const ok = ORIGINS.includes(origin);
  if (!ok) {
    console.log('[CORS] Blocked:', origin, '| Allowed:', ORIGINS);
  }
  return cb(ok ? null : new Error('Origin not allowed'), ok);
}

const corsOptions = {
  origin: corsOrigin,
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 204
};

// CORS must be before routes
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));      // preflight for all routes
app.use((req, res, next) => {
  res.header('Vary', 'Origin');           // help caches/CDNs
  next();
});

/* -------------------------------------------------------
   DB (SQLite)
------------------------------------------------------- */
const DB_FILE = path.resolve(__dirname, 'database.sqlite');
const db = new sqlite3.Database(DB_FILE);

// Init tables if not exists
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS Users (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE,
      role TEXT,
      password TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS Expenses (
      id TEXT PRIMARY KEY,
      title TEXT,
      category TEXT,
      amount INTEGER,
      currency TEXT,
      date TEXT,
      entryDate TEXT,
      note TEXT,
      mgrStatus TEXT,
      acctStatus TEXT,
      paid INTEGER,
      receiptPath TEXT,
      receiptName TEXT,
      receiptMime TEXT,
      createdAt TEXT,
      updatedAt TEXT,
      employeeId TEXT,
      FOREIGN KEY (employeeId) REFERENCES Users(id)
    )
  `);

  // Seed default users if empty
  db.get(`SELECT COUNT(*) AS c FROM Users`, (err, row) => {
    if (err) return console.error(err);
    if (row.c === 0) {
      const stmt = db.prepare(
        `INSERT INTO Users (id, name, role, password) VALUES (?, ?, ?, ?)`
      );
      const users = [
        ['aea85505-50f0-4bdf-adf7-3b919a88fc9d', 'admin', 'admin', 'password123'],
        ['c379b904-84f8-4b31-9324-d3f3bf378946', 'manager', 'manager', 'password123'],
        ['c7cc2685-1786-4cf3-bd95-ce829a911019', 'accountant', 'accountant', 'password123'],
        ['c7e86224-9251-4d6d-a8c5-7ad33dfe0fb1', 'alice', 'employee', 'password123']
      ];
      users.forEach(u => stmt.run(u));
      stmt.finalize(() =>
        console.log('Seeded users: admin/manager/accountant/alice with password: password123')
      );
    }
  });
});

/* -------------------------------------------------------
   FILE UPLOADS
------------------------------------------------------- */
const UPLOAD_DIR = path.resolve(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => {
    const ts = Date.now();
    const safe = file.originalname.replace(/[^\w.\-]+/g, '_');
    cb(null, `${ts}_${safe}`);
  }
});
const upload = multer({ storage });

/* -------------------------------------------------------
   AUTH
------------------------------------------------------- */
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_only_change_me';

function signToken(user) {
  return jwt.sign(
    { sub: user.id, name: user.name, role: user.role },
    JWT_SECRET,
    { expiresIn: '8h' }
  );
}

function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const m = hdr.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(m[1], JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthenticated' });
    if (!roles.includes(req.user.role) && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

/* -------------------------------------------------------
   ROUTES: AUTH
------------------------------------------------------- */
// POST /api/auth/login { name, password }
app.post('/api/auth/login', (req, res) => {
  const { name, password } = req.body || {};
  if (!name || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }
  db.get(`SELECT * FROM Users WHERE name = ?`, [name], (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = signToken(user);
    res.json({
      token,
      user: { id: user.id, name: user.name, role: user.role }
    });
  });
});

// GET /api/auth/me
app.get('/api/auth/me', auth, (req, res) => {
  db.get(`SELECT id, name, role FROM Users WHERE id = ?`, [req.user.sub], (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json({ user });
  });
});

/* -------------------------------------------------------
   ROUTES: EXPENSES
------------------------------------------------------- */
// GET /api/expenses
// - employee -> own
// - manager/accountant/admin -> all
app.get('/api/expenses', auth, (req, res) => {
  if (req.user.role === 'employee') {
    db.all(
      `SELECT e.*, u.name as employeeName, u.email as email
         FROM Expenses e
         LEFT JOIN Users u ON u.id = e.employeeId
        WHERE employeeId = ?
        ORDER BY datetime(createdAt) DESC`,
      [req.user.sub],
      (err, rows) => err ? res.status(500).json({ error: 'DB error' }) : res.json(rows || [])
    );
  } else {
    db.all(
      `SELECT e.*, u.name as employeeName
         FROM Expenses e
         LEFT JOIN Users u ON u.id = e.employeeId
        ORDER BY datetime(createdAt) DESC`,
      [],
      (err, rows) => err ? res.status(500).json({ error: 'DB error' }) : res.json(rows || [])
    );
  }
});

// POST /api/expenses (employee creates)
// multipart/form-data with "receipt" optional
app.post('/api/expenses', auth, upload.single('receipt'), (req, res) => {
  const { title, category, amount, currency, date, note } = req.body || {};
  if (!title || !category || !amount || !currency || !date) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  const now = new Date().toISOString();
  const id = require('crypto').randomUUID();

  const receiptPath = req.file ? `/uploads/${req.file.filename}` : null;
  const receiptName = req.file ? req.file.originalname : null;
  const receiptMime = req.file ? req.file.mimetype : null;

  const stmt = `
    INSERT INTO Expenses (
      id, title, category, amount, currency, date, entryDate, note,
      mgrStatus, acctStatus, paid,
      receiptPath, receiptName, receiptMime,
      createdAt, updatedAt, employeeId
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending', 'Pending', 0, ?, ?, ?, ?, ?, ?)
  `;

  db.run(
    stmt,
    [
      id, title, category, parseInt(amount, 10), currency, date, null, note || '',
      receiptPath, receiptName, receiptMime,
      now, now, req.user.sub
    ],
    function (err) {
      if (err) return res.status(500).json({ error: 'DB error' });
      db.get(`SELECT * FROM Expenses WHERE id = ?`, [id], (e2, row) => {
        if (e2) return res.status(500).json({ error: 'DB error' });
        res.status(201).json(row);
      });
    }
  );
});

// PATCH /api/expenses/:id/manager {status: 'Accepted'|'Declined'}
app.patch(
  '/api/expenses/:id/manager',
  auth,
  requireRole('manager'),
  (req, res) => {
    const { status } = req.body || {};
    if (!['Accepted', 'Declined', 'Pending'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    db.run(
      `UPDATE Expenses SET mgrStatus = ?, updatedAt = ? WHERE id = ?`,
      [status, new Date().toISOString(), req.params.id],
      function (err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        db.get(`SELECT * FROM Expenses WHERE id = ?`, [req.params.id], (e2, row) => {
          if (e2) return res.status(500).json({ error: 'DB error' });
          res.json(row || {});
        });
      }
    );
  }
);

// PATCH /api/expenses/:id/accountant {status: 'Approved'|'Declined'}
app.patch(
  '/api/expenses/:id/accountant',
  auth,
  requireRole('accountant'),
  (req, res) => {
    const { status } = req.body || {};
    if (!['Approved', 'Declined', 'Pending'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    db.run(
      `UPDATE Expenses SET acctStatus = ?, updatedAt = ? WHERE id = ?`,
      [status, new Date().toISOString(), req.params.id],
      function (err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        db.get(`SELECT * FROM Expenses WHERE id = ?`, [req.params.id], (e2, row) => {
          if (e2) return res.status(500).json({ error: 'DB error' });
          res.json(row || {});
        });
      }
    );
  }
);

/* -------------------------------------------------------
   OPTIONAL: EXPORT TO GOOGLE SHEETS
   Set SERVICE_ACCOUNT_JSON (base64 of JSON) and GOOGLE_SHEETS_ID
------------------------------------------------------- */
app.get('/api/export/sheets', auth, requireRole('admin'), async (req, res) => {
  try {
    const saB64 = process.env.SERVICE_ACCOUNT_JSON || '';
    const sheetId = process.env.GOOGLE_SHEETS_ID || '';
    if (!saB64 || !sheetId) {
      return res.status(400).json({ error: 'Sheets env missing' });
    }

    const { google } = require('googleapis');
    const sa = JSON.parse(Buffer.from(saB64, 'base64').toString('utf8'));

    const scopes = ['https://www.googleapis.com/auth/spreadsheets'];
    const authGoogle = new google.auth.JWT(sa.client_email, null, sa.private_key, scopes);
    await authGoogle.authorize();

    const sheets = google.sheets({ version: 'v4', auth: authGoogle });

    // Fetch all expenses
    db.all(
      `SELECT e.id, u.name as employee, e.title, e.category, e.amount, e.currency,
              e.date, e.mgrStatus, e.acctStatus, e.paid
         FROM Expenses e
         LEFT JOIN Users u ON u.id = e.employeeId
        ORDER BY datetime(e.createdAt) DESC`,
      [],
      async (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error' });

        const values = [
          ['ID', 'Employee', 'Title', 'Category', 'Amount', 'Currency', 'Date',
           'Mgr Status', 'Acct Status', 'Paid']
        ];
        rows.forEach(r => values.push([
          r.id, r.employee, r.title, r.category, r.amount, r.currency, r.date,
          r.mgrStatus, r.acctStatus, r.paid ? 'Yes' : 'No'
        ]));

        await sheets.spreadsheets.values.clear({
          spreadsheetId: sheetId,
          range: 'Sheet1!A1:Z9999'
        });

        await sheets.spreadsheets.values.update({
          spreadsheetId: sheetId,
          range: 'Sheet1!A1',
          valueInputOption: 'RAW',
          requestBody: { values }
        });

        res.json({ message: 'Exported to Google Sheets successfully' });
      }
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Sheets export failed' });
  }
});

/* -------------------------------------------------------
   HEALTH
------------------------------------------------------- */
app.get('/health', (req, res) => res.json({ ok: true }));

/* -------------------------------------------------------
   STATIC (serve uploaded files)
------------------------------------------------------- */
app.use('/uploads', express.static(UPLOAD_DIR));

/* -------------------------------------------------------
   START
------------------------------------------------------- */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () =>
  console.log(
    `Server started on http://localhost:${PORT}\n[CORS] Allowed origins: ${ORIGINS.join(', ')}`
  )
);
