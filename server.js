// server.js
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const QRCode = require('qrcode');
const xlsx = require('xlsx');

const app = express();
const DB_FILE = path.join(__dirname, 'database.sqlite');
const PUBLIC_DIR = path.join(__dirname, 'public');
const QR_DIR = path.join(PUBLIC_DIR, 'qrcodes');

if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
if (!fs.existsSync(QR_DIR)) fs.mkdirSync(QR_DIR, { recursive: true });

const db = new Database(DB_FILE);

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'change-this-secret', // change for production
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 3600 * 1000 }
}));
app.use(express.static(PUBLIC_DIR));
// Routes untuk halaman tanpa .html
app.get('/login', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'dashboard.html')));
app.get('/profile', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'profile.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));
app.get('/attendance', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'attendance.html')));

// Default root redirect ke attendance
app.get('/', (req, res) => res.redirect('/attendance'));

// DB init
db.exec(`
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  nama TEXT,
  alamat TEXT,
  no_hp TEXT,
  jabatan TEXT,
  qr_code TEXT
);
CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  status TEXT DEFAULT 'Hadir',
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

// Utility: generate QR image file for user id and save relative path in DB
function generateUserQR(id) {
  const qrData = String(id); // QR will contain just the user ID
  const filename = `${id}.png`;
  const fullpath = path.join(QR_DIR, filename);
  try {
    // generate PNG file (synchronous wrapper not offered -> use callback)
    QRCode.toFile(fullpath, qrData, { width: 300 }, (err) => {
      if (err) console.error('QR generation error', err);
    });
  } catch (e) {
    console.error('QR gen exception', e);
  }
  const rel = `/qrcodes/${filename}`;
  db.prepare('UPDATE users SET qr_code = ? WHERE id = ?').run(rel, id);
  return rel;
}

// Seed admin if missing
const admin = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!admin) {
  const hash = bcrypt.hashSync('admin123', 10);
  const info = db.prepare('INSERT INTO users (username,password,role,nama,jabatan) VALUES (?,?,?,?,?)')
    .run('admin', hash, 'admin', 'Administrator', 'Admin');
  generateUserQR(info.lastInsertRowid);
  console.log('✅ Default admin created: username=admin password=admin123');
}

// Auth helpers
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ success: false, message: 'Unauthorized' });
}
function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'admin') return next();
  return res.status(403).json({ success: false, message: 'Forbidden (admin only)' });
}
function refreshSessionUser(req) {
  if (!req.session || !req.session.user) return;
  const u = db.prepare('SELECT id,username,role,nama,alamat,no_hp,jabatan,qr_code FROM users WHERE id = ?').get(req.session.user.id);
  if (u) req.session.user = u;
}

// ---------- AUTH ----------
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ success: false, message: 'username & password required' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(400).json({ success: false, message: 'User not found' });
  if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ success: false, message: 'Wrong password' });
  // store minimal in session
  req.session.user = {
    id: user.id, username: user.username, role: user.role,
    nama: user.nama, alamat: user.alamat, no_hp: user.no_hp, jabatan: user.jabatan, qr_code: user.qr_code
  };
  res.json({ success: true, user: req.session.user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error('session destroy', err);
    res.json({ success: true });
  });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ success: false });
  res.json({ success: true, user: req.session.user });
});

// ---------- ADMIN: USERS ----------
app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.username, u.nama, u.alamat, u.no_hp, u.jabatan, u.role, u.qr_code,
      COUNT(a.id) AS total_absen
    FROM users u
    LEFT JOIN attendance a ON u.id = a.user_id
    GROUP BY u.id
    ORDER BY u.id ASC
  `).all();
  res.json({ success: true, users: rows });
});

app.post('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  const { username, password, role = 'user', nama = '', alamat = '', no_hp = '', jabatan = '' } = req.body || {};
  if (!username || !password) return res.status(400).json({ success: false, message: 'username & password required' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    const info = db.prepare('INSERT INTO users (username,password,role,nama,alamat,no_hp,jabatan) VALUES (?,?,?,?,?,?,?)')
      .run(username, hash, role, nama, alamat, no_hp, jabatan);
    const rel = generateUserQR(info.lastInsertRowid);
    return res.json({ success: true, id: info.lastInsertRowid, qr_code: rel });
  } catch (err) {
    console.error(err);
    return res.status(400).json({ success: false, message: 'Create failed (maybe username exists)' });
  }
});

app.put('/api/admin/users/:id', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { username, nama, alamat, no_hp, jabatan, role } = req.body || {};
  try {
    db.prepare(`UPDATE users SET username = COALESCE(?,username), nama = COALESCE(?,nama),
      alamat = COALESCE(?,alamat), no_hp = COALESCE(?,no_hp), jabatan = COALESCE(?,jabatan),
      role = COALESCE(?,role) WHERE id = ?`).run(username, nama, alamat, no_hp, jabatan, role, id);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  try {
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    // also delete QR file if exists
    const qfile = path.join(QR_DIR, `${id}.png`);
    if (fs.existsSync(qfile)) fs.unlinkSync(qfile);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Delete failed' });
  }
});

// regenerate QR
app.post('/api/admin/users/:id/regenerate-qr', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ success: false, message: 'User not found' });
  // remove old file
  const old = path.join(QR_DIR, `${id}.png`);
  try { if (fs.existsSync(old)) fs.unlinkSync(old); } catch(e){/*ignore*/ }
  const rel = generateUserQR(id);
  res.json({ success: true, qr_code: rel });
});

// admin change another user's password
app.post('/api/admin/change-password/:id', requireAuth, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { newPassword } = req.body || {};
  if (!newPassword) return res.status(400).json({ success: false, message: 'newPassword required' });
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, id);
  res.json({ success: true });
});

// ---------- USER PROFILE ----------
app.get('/api/user/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const me = req.session.user;
  if (me.role !== 'admin' && me.id !== id) return res.status(403).json({ success: false, message: 'Forbidden' });
  const row = db.prepare('SELECT id,username,nama,alamat,no_hp,jabatan,role,qr_code FROM users WHERE id = ?').get(id);
  res.json({ success: true, user: row });
});

app.put('/api/user/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const me = req.session.user;
  if (me.role !== 'admin' && me.id !== id) return res.status(403).json({ success: false, message: 'Forbidden' });
  const { nama, alamat, no_hp, jabatan, role } = req.body || {};
  if (me.role === 'admin') {
    db.prepare('UPDATE users SET nama = COALESCE(?,nama), alamat = COALESCE(?,alamat), no_hp = COALESCE(?,no_hp), jabatan = COALESCE(?,jabatan), role = COALESCE(?,role) WHERE id = ?')
      .run(nama, alamat, no_hp, jabatan, role, id);
  } else {
    db.prepare('UPDATE users SET nama = COALESCE(?,nama), alamat = COALESCE(?,alamat), no_hp = COALESCE(?,no_hp), jabatan = COALESCE(?,jabatan) WHERE id = ?')
      .run(nama, alamat, no_hp, jabatan, id);
  }
  if (me.id === id) refreshSessionUser(req);
  res.json({ success: true });
});

// change own password
app.post('/api/change-password', requireAuth, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ success: false, message: 'old & new required' });
  const me = req.session.user;
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(me.id);
  if (!bcrypt.compareSync(oldPassword, row.password)) return res.status(400).json({ success: false, message: 'Old password does not match' });
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hash, me.id);
  res.json({ success: true });
});

// ---------- ATTENDANCE ----------
app.post('/api/attendance', (req, res) => {
  const body = req.body || {};
  let user = null;
  if (body && body.code) {
    const code = String(body.code).trim();
    // first try id numeric
    const idNum = Number(code);
    if (!Number.isNaN(idNum) && idNum > 0) user = db.prepare('SELECT * FROM users WHERE id = ?').get(idNum);
    if (!user) user = db.prepare('SELECT * FROM users WHERE username = ?').get(code);
    if (!user) return res.status(400).json({ success: false, message: 'User not found for provided code' });
  } else if (req.session && req.session.user) {
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);
    if (!user) return res.status(400).json({ success: false, message: 'Session user not found' });
  } else {
    return res.status(401).json({ success: false, message: 'Need QR code or login to record attendance' });
  }

  // already absen today?
  const already = db.prepare(`SELECT 1 FROM attendance WHERE user_id = ? AND date(timestamp) = date('now','localtime')`).get(user.id);
  if (already) return res.json({ success: false, message: 'Sudah absen hari ini' });

  db.prepare('INSERT INTO attendance (user_id, status) VALUES (?, ?)').run(user.id, body.status || 'Hadir');
  res.json({ success: true, message: `Absensi tercatat untuk ${user.nama || user.username}` });
});

app.get('/api/attendance/me', requireAuth, (req, res) => {
  const me = req.session.user;
  const rows = db.prepare('SELECT id,timestamp,status FROM attendance WHERE user_id = ? ORDER BY timestamp DESC').all(me.id);
  res.json({ success: true, attendance: rows });
});

app.get('/api/attendance/all', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT a.id, a.timestamp, a.status, u.id as user_id, u.username, u.nama
    FROM attendance a JOIN users u ON a.user_id = u.id
    ORDER BY a.timestamp DESC
  `).all();
  res.json({ success: true, attendance: rows });
});

// ---------- EXPORT ----------
app.get('/api/admin/export/csv', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT a.id, u.username, u.nama, a.timestamp, a.status
    FROM attendance a JOIN users u ON a.user_id = u.id
    ORDER BY a.timestamp DESC
  `).all();
  let csv = 'id,username,nama,timestamp,status\n';
  for (const r of rows) {
    const name = (r.nama || '').replace(/"/g, '""');
    csv += `${r.id},${r.username},"${name}",${r.timestamp},${r.status}\n`;
  }
  res.setHeader('Content-Disposition', 'attachment; filename=laporan_absensi.csv');
  res.type('text/csv').send(csv);
});

app.get('/api/admin/export/excel', requireAuth, requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT a.id, u.username, u.nama, a.timestamp, a.status
    FROM attendance a JOIN users u ON a.user_id = u.id
    ORDER BY a.timestamp DESC
  `).all();
  const ws = xlsx.utils.json_to_sheet(rows);
  const wb = xlsx.utils.book_new();
  xlsx.utils.book_append_sheet(wb, ws, 'Absensi');
  const buffer = xlsx.write(wb, { bookType: 'xlsx', type: 'buffer' });
  res.setHeader('Content-Disposition', 'attachment; filename=laporan_absensi.xlsx');
  res.type('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet').send(buffer);
});

// Root
app.get('/', (req, res) => res.redirect('/attendance.html'));

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));