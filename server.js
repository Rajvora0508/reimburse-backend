// server.js — Express + SQLite + Google Sheets export (with tightened CORS, helmet, upload limits)

require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const helmet = require('helmet');
const { Sequelize, DataTypes } = require('sequelize');

/* -----------------------------------------------------------
 * 0) GOOGLE CREDS: prefer GOOGLE_CREDENTIALS (stringified JSON)
 *    In prod, paste full JSON into env var and we write it to /tmp
 * --------------------------------------------------------- */
(function prepareGoogleKeyfile() {
  if (process.env.GOOGLE_CREDENTIALS) {
    const target = '/tmp/gsa.json';
    fs.writeFileSync(target, process.env.GOOGLE_CREDENTIALS, 'utf8');
    process.env.GOOGLE_KEYFILE = target; // rest of code uses GOOGLE_KEYFILE
  }
})();

/* -----------------------------------------------------------
 * 1) BASIC CONFIG
 * --------------------------------------------------------- */
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const DB_PATH = process.env.DB_PATH || path.resolve(process.cwd(), 'database.sqlite');
const UPLOAD_DIR = process.env.UPLOAD_DIR
  ? path.resolve(process.cwd(), process.env.UPLOAD_DIR)
  : path.resolve(process.cwd(), 'uploads');
const GOOGLE_SHEET_ID = process.env.GOOGLE_SHEET_ID || '';
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || `http://localhost:${PORT}`;

/* CORS via env: provide comma-separated list in ALLOWED_ORIGINS
   Examples:
   ALLOWED_ORIGINS=https://your-frontend.com,https://app.your-frontend.com,http://localhost:5500 */
const defaultAllowed = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173'
];
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
const ORIGINS = ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : defaultAllowed;

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* -----------------------------------------------------------
 * 2) DB: Sequelize + SQLite
 * --------------------------------------------------------- */
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: DB_PATH,
  logging: false
});

const User = sequelize.define('User', {
  name: { type: DataTypes.STRING, unique: true, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: true },
  role: { type: DataTypes.ENUM('admin', 'manager', 'accountant', 'employee'), allowNull: false },
  passwordHash: { type: DataTypes.STRING, allowNull: false }
}, { tableName: 'Users' });

const Expense = sequelize.define('Expense', {
  title: { type: DataTypes.STRING, allowNull: false },
  category: { type: DataTypes.STRING, allowNull: false },
  amount: { type: DataTypes.FLOAT, allowNull: false },
  currency: { type: DataTypes.STRING, allowNull: false, defaultValue: 'INR' },
  date: { type: DataTypes.DATEONLY, allowNull: false },
  entryDate: { type: DataTypes.DATE, allowNull: true, defaultValue: DataTypes.NOW },
  note: { type: DataTypes.TEXT, allowNull: true },

  mgrStatus: { type: DataTypes.ENUM('Pending', 'Accepted', 'Declined'), defaultValue: 'Pending' },
  acctStatus: { type: DataTypes.ENUM('Pending', 'Approved', 'Rejected'), defaultValue: 'Pending' },
  paid: { type: DataTypes.BOOLEAN, defaultValue: false },

  receiptPath: { type: DataTypes.STRING, allowNull: true },
  receiptName: { type: DataTypes.STRING, allowNull: true },
  receiptMime: { type: DataTypes.STRING, allowNull: true }
}, { tableName: 'Expenses' });

User.hasMany(Expense, { foreignKey: 'employeeId' });
Expense.belongsTo(User, { as: 'employee', foreignKey: 'employeeId' });

/* -----------------------------------------------------------
 * 3) APP & MIDDLEWARE
 * --------------------------------------------------------- */
const app = express();

// Security headers
app.use(helmet());

// Strict-ish CORS controlled by env
app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true); // allow curl/postman
    const ok = ORIGINS.includes(origin);
    return ok ? callback(null, true) : callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Authorization','Content-Type'],
  credentials: false
}));
app.options('*', cors());

// FRIENDLIER CORS ERROR → 403 JSON
app.use((err, req, res, next) => {
  if (err && String(err.message || '').startsWith('CORS blocked')) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  next(err);
});

app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR));
app.get('/health', (_, res) => res.json({ ok: true }));

/* -----------------------------------------------------------
 * 4) Multer (receipts) — size & type restricted
 * --------------------------------------------------------- */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/[^\w.\-]/g, '_');
    cb(null, `${Date.now()}_${safe}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 12 * 1024 * 1024 }, // 12 MB
  fileFilter: (req, file, cb) => {
    const allowed = ['image/png', 'image/jpeg', 'image/jpg', 'application/pdf'];
    if (!allowed.includes(file.mimetype)) return cb(new Error('Unsupported file type'), false);
    cb(null, true);
  }
});

/* -----------------------------------------------------------
 * 5) Auth helpers
 * --------------------------------------------------------- */
function signToken(user) {
  return jwt.sign(
    { id: user.id, name: user.name, role: user.role, email: user.email || null },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}
function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthenticated' });
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

/* -----------------------------------------------------------
 * 6) Auth routes
 * --------------------------------------------------------- */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { name, password } = req.body || {};
    if (!name || !password) return res.status(400).json({ error: 'name and password required' });

    const user = await User.findOne({ where: { name } });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    res.json({
      token: signToken(user),
      user: { id: user.id, name: user.name, role: user.role, email: user.email || null }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/me', authenticate, async (req, res) => {
  const u = await User.findByPk(req.user.id);
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json({ id: u.id, name: u.name, role: u.role, email: u.email || null });
});

/* -----------------------------------------------------------
 * 7) Expense routes
 * --------------------------------------------------------- */
// Create expense (employee)
app.post('/api/expenses', authenticate, upload.single('receipt'), async (req, res) => {
  try {
    const { title, category, amount, currency, date, note } = req.body || {};
    if (!title || !category || !amount || !date) {
      return res.status(400).json({ error: 'Missing fields' });
    }
    const payload = {
      title,
      category,
      amount: parseFloat(amount),
      currency: currency || 'INR',
      date,
      note: note || '',
      employeeId: req.user.id,
      entryDate: new Date(),
      mgrStatus: 'Pending',
      acctStatus: 'Pending',
      paid: false
    };
    if (req.file) {
      payload.receiptPath = `/uploads/${req.file.filename}`;
      payload.receiptName = req.file.originalname;
      payload.receiptMime = req.file.mimetype;
    }
    const exp = await Expense.create(payload);
    res.status(201).json(exp);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Create failed' });
  }
});

// List expenses
app.get('/api/expenses', authenticate, async (req, res) => {
  try {
    const where = req.user.role === 'employee' ? { employeeId: req.user.id } : {};
    const list = await Expense.findAll({
      where,
      order: [['createdAt', 'DESC']],
      include: [{ model: User, as: 'employee', attributes: ['id','name','email'] }]
    });
    res.json(list);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'List failed' });
  }
});

// Manager decision — manager is final; decline => red everywhere
app.patch('/api/expenses/:id/manager', authenticate, requireRole('manager','admin'), async (req, res) => {
  try {
    const { action } = req.body || {}; // 'Accept' | 'Decline'
    const exp = await Expense.findByPk(req.params.id);
    if (!exp) return res.status(404).json({ error: 'Not found' });

    if (action === 'Accept') {
      exp.mgrStatus = 'Accepted';
      // accountant remains Pending until they act
    } else if (action === 'Decline') {
      exp.mgrStatus = 'Declined';
      exp.acctStatus = 'Rejected'; // ensures final "red" everywhere
    } else {
      return res.status(400).json({ error: 'Invalid action' });
    }
    await exp.save();
    res.json(exp);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Manager action failed' });
  }
});

// Accountant decision — but if manager declined, it's final
app.patch('/api/expenses/:id/accountant', authenticate, requireRole('accountant','admin'), async (req, res) => {
  try {
    const { action } = req.body || {}; // 'Approve' | 'Decline'
    const exp = await Expense.findByPk(req.params.id);
    if (!exp) return res.status(404).json({ error: 'Not found' });

    if (exp.mgrStatus === 'Declined') {
      exp.acctStatus = 'Rejected'; // manager's decline is final
      await exp.save();
      return res.json(exp);
    }

    if (action === 'Approve') {
      exp.acctStatus = 'Approved';
    } else if (action === 'Decline') {
      exp.acctStatus = 'Rejected';
    } else {
      return res.status(400).json({ error: 'Invalid action' });
    }
    await exp.save();
    res.json(exp);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Accountant action failed' });
  }
});

/* -----------------------------------------------------------
 * 8) Admin: Export to Google Sheets
 * --------------------------------------------------------- */
app.get('/api/export/sheets', authenticate, requireRole('admin'), async (req, res) => {
  try {
    if (!GOOGLE_SHEET_ID) return res.status(400).json({ error: 'GOOGLE_SHEET_ID not set' });
    if (!process.env.GOOGLE_KEYFILE) return res.status(400).json({ error: 'GOOGLE_KEYFILE not set (or GOOGLE_CREDENTIALS missing)' });

    const { google } = require('googleapis');
    const auth = new google.auth.GoogleAuth({
      keyFile: process.env.GOOGLE_KEYFILE,
      scopes: ['https://www.googleapis.com/auth/spreadsheets']
    });
    const sheets = google.sheets({ version: 'v4', auth });

    const rows = await Expense.findAll({
      order: [['createdAt','DESC']],
      include: [{ model: User, as: 'employee', attributes: ['name','email'] }]
    });

    const values = [
      ['Title','Category','Amount','Currency','Date','Manager','Accountant','Paid','Employee','Email','Receipt URL']
    ];
    for (const e of rows) {
      const absoluteReceipt = e.receiptPath
        ? new URL(e.receiptPath, PUBLIC_BASE_URL).toString()
        : '';
      values.push([
        e.title,
        e.category,
        e.amount,
        e.currency,
        e.date,
        e.mgrStatus,
        e.acctStatus,
        e.paid ? 'Yes' : 'No',
        e.employee?.name || '',
        e.employee?.email || '',
        absoluteReceipt
      ]);
    }

    // Clear then write for a clean sheet
    await sheets.spreadsheets.values.clear({
      spreadsheetId: GOOGLE_SHEET_ID,
      range: 'Sheet1!A:Z'
    });
    await sheets.spreadsheets.values.update({
      spreadsheetId: GOOGLE_SHEET_ID,
      range: 'Sheet1!A1',
      valueInputOption: 'USER_ENTERED',
      requestBody: { values }
    });

    res.json({ message: 'Exported to Google Sheets successfully' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Export failed' });
  }
});

/* -----------------------------------------------------------
 * 9) Seed users (runs once on empty DB)
 * --------------------------------------------------------- */
async function seed() {
  await sequelize.sync();
  const count = await User.count();
  if (count === 0) {
    const pw = await bcrypt.hash('password123', 10);
    await User.bulkCreate([
      { name: 'admin', email: 'admin@company.local', role: 'admin', passwordHash: pw },
      { name: 'manager', email: 'manager@company.local', role: 'manager', passwordHash: pw },
      { name: 'accountant', email: 'accountant@company.local', role: 'accountant', passwordHash: pw },
      { name: 'alice', email: 'alice@company.local', role: 'employee', passwordHash: pw }
    ]);
    console.log('Seeded users: admin/manager/accountant/alice with password: password123');
  }
}

/* -----------------------------------------------------------
 * 10) START
 * --------------------------------------------------------- */
seed().then(() => {
  app.listen(PORT, () => {
    console.log(`Server started on http://localhost:${PORT}`);
  });
});
