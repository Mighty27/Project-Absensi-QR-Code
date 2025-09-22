// server.js
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');
const QRCode = require('qrcode');
const xlsx = require('xlsx');

const app = express();
const PUBLIC_DIR = path.join(__dirname, 'public');
const QR_DIR = path.join(PUBLIC_DIR, 'qrcodes');

if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR, { recursive: true });
if (!fs.existsSync(QR_DIR)) fs.mkdirSync(QR_DIR, { recursive: true });

// ---------- DATABASE ----------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ---------- MIDDLEWARE ----------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 3600 * 1000 }
}));
app.use(express.static(PUBLIC_DIR));

// ---------- HTML ROUTES ----------
app.get('/login', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'dashboard.html')));
app.get('/profile', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'profile.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'admin.html')));
app.get('/attendance', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'attendance.html')));
app.get('/', (req, res) => res.redirect('/attendance'));

// ---------- HELPERS ----------
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ success: false, message: 'Unauthorized' });
}
function requireAdmin(req, res, next) {
  if (req.session?.user?.role === 'admin') return next();
  return res.status(403).json({ success: false, message: 'Forbidden (admin only)' });
}
async function refreshSessionUser(req) {
  if (!req.session?.user) return;
  const { rows } = await pool.query(
    'SELECT id,username,role,nama,alamat,no_hp,jabatan,qr_code FROM users WHERE id=$1',
    [req.session.user.id]
  );
  if (rows.length) req.session.user = rows[0];
}

// ---------- QR UTILS ----------
async function generateUserQR(id) {
  const filename = `${id}.png`;
  const fullpath = path.join(QR_DIR, filename);
  const qrData = String(id);

  await QRCode.toFile(fullpath, qrData, { width: 300 });
  const rel = `/qrcodes/${filename}`;
  await pool.query('UPDATE users SET qr_code=$1 WHERE id=$2', [rel, id]);
  return rel;
}

// ---------- INIT: create tables + seed admin ----------
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      nama TEXT,
      alamat TEXT,
      no_hp TEXT,
      jabatan TEXT,
      qr_code TEXT
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS attendance (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      status TEXT DEFAULT 'Hadir'
    );
  `);

  const { rows } = await pool.query('SELECT id FROM users WHERE username=$1', ['admin']);
  if (rows.length === 0) {
    const hash = bcrypt.hashSync('admin123', 10);
    const result = await pool.query(
      'INSERT INTO users (username,password,role,nama,jabatan) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      ['admin', hash, 'admin', 'Administrator', 'Admin']
    );
    await generateUserQR(result.rows[0].id);
    console.log('✅ Default admin created: username=admin password=admin123');
  }
})();

// ---------- AUTH ----------
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ success: false, message: 'username & password required' });

  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE username=$1', [username]);
    if (!rows.length) return res.status(400).json({ success: false, message: 'User not found' });

    const user = rows[0];
    if (!bcrypt.compareSync(password, user.password))
      return res.status(400).json({ success: false, message: 'Wrong password' });

    req.session.user = {
      id: user.id, username: user.username, role: user.role,
      nama: user.nama, alamat: user.alamat, no_hp: user.no_hp, jabatan: user.jabatan, qr_code: user.qr_code
    };
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'DB error' });
  }
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
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT u.*, COUNT(a.id) AS total_absen
    FROM users u
    LEFT JOIN attendance a ON u.id = a.user_id
    GROUP BY u.id
    ORDER BY u.id ASC
  `);
  res.json({ success: true, users: rows });
});

app.post('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const { username, password, role = 'user', nama = '', alamat = '', no_hp = '', jabatan = '' } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ success: false, message: 'username & password required' });

  const hash = bcrypt.hashSync(password, 10);
  try {
    const result = await pool.query(
      'INSERT INTO users (username,password,role,nama,alamat,no_hp,jabatan) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id',
      [username, hash, role, nama, alamat, no_hp, jabatan]
    );
    const rel = await generateUserQR(result.rows[0].id);
    res.json({ success: true, id: result.rows[0].id, qr_code: rel });
  } catch (err) {
    console.error(err);
    res.status(400).json({ success: false, message: 'Create failed (maybe username exists)' });
  }
});

app.put('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const { username, nama, alamat, no_hp, jabatan, role } = req.body || {};
  try {
    await pool.query(
      `UPDATE users SET
        username = COALESCE($1,username),
        nama = COALESCE($2,nama),
        alamat = COALESCE($3,alamat),
        no_hp = COALESCE($4,no_hp),
        jabatan = COALESCE($5,jabatan),
        role = COALESCE($6,role)
       WHERE id=$7`,
      [username, nama, alamat, no_hp, jabatan, role, id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Update failed' });
  }
});

app.delete('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  try {
    await pool.query('DELETE FROM users WHERE id=$1', [id]);
    const qfile = path.join(QR_DIR, `${id}.png`);
    if (fs.existsSync(qfile)) fs.unlinkSync(qfile);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Delete failed' });
  }
});

app.post('/api/admin/users/:id/regenerate-qr', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [id]);
  if (!rows.length) return res.status(404).json({ success: false, message: 'User not found' });

  const old = path.join(QR_DIR, `${id}.png`);
  if (fs.existsSync(old)) fs.unlinkSync(old);

  const rel = await generateUserQR(id);
  res.json({ success: true, qr_code: rel });
});

app.post('/api/admin/change-password/:id', requireAuth, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const { newPassword } = req.body || {};
  if (!newPassword) return res.status(400).json({ success: false, message: 'newPassword required' });
  const hash = bcrypt.hashSync(newPassword, 10);
  await pool.query('UPDATE users SET password=$1 WHERE id=$2', [hash, id]);
  res.json({ success: true });
});

// ---------- USER PROFILE ----------
app.get('/api/user/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const me = req.session.user;
  if (me.role !== 'admin' && me.id !== id)
    return res.status(403).json({ success: false, message: 'Forbidden' });

  const { rows } = await pool.query('SELECT id,username,nama,alamat,no_hp,jabatan,role,qr_code FROM users WHERE id=$1', [id]);
  res.json({ success: true, user: rows[0] });
});

app.put('/api/user/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const me = req.session.user;
  if (me.role !== 'admin' && me.id !== id)
    return res.status(403).json({ success: false, message: 'Forbidden' });

  const { nama, alamat, no_hp, jabatan, role } = req.body || {};
  if (me.role === 'admin') {
    await pool.query(
      'UPDATE users SET nama=COALESCE($1,nama),alamat=COALESCE($2,alamat),no_hp=COALESCE($3,no_hp),jabatan=COALESCE($4,jabatan),role=COALESCE($5,role) WHERE id=$6',
      [nama, alamat, no_hp, jabatan, role, id]
    );
  } else {
    await pool.query(
      'UPDATE users SET nama=COALESCE($1,nama),alamat=COALESCE($2,alamat),no_hp=COALESCE($3,no_hp),jabatan=COALESCE($4,jabatan) WHERE id=$5',
      [nama, alamat, no_hp, jabatan, id]
    );
  }
  if (me.id === id) await refreshSessionUser(req);
  res.json({ success: true });
});

app.post('/api/change-password', requireAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword)
    return res.status(400).json({ success: false, message: 'old & new required' });

  const me = req.session.user;
  const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [me.id]);
  if (!bcrypt.compareSync(oldPassword, rows[0].password))
    return res.status(400).json({ success: false, message: 'Old password does not match' });

  const hash = bcrypt.hashSync(newPassword, 10);
  await pool.query('UPDATE users SET password=$1 WHERE id=$2', [hash, me.id]);
  res.json({ success: true });
});

// ---------- ATTENDANCE ----------
app.post('/api/attendance', async (req, res) => {
  const body = req.body || {};
  let user = null;

  if (body.code) {
    const code = String(body.code).trim();
    const idNum = Number(code);
    if (!Number.isNaN(idNum) && idNum > 0) {
      const r = await pool.query('SELECT * FROM users WHERE id=$1', [idNum]);
      if (r.rows.length) user = r.rows[0];
    }
    if (!user) {
      const r = await pool.query('SELECT * FROM users WHERE username=$1', [code]);
      if (r.rows.length) user = r.rows[0];
    }
    if (!user) return res.status(400).json({ success: false, message: 'User not found for provided code' });
  } else if (req.session?.user) {
    const r = await pool.query('SELECT * FROM users WHERE id=$1', [req.session.user.id]);
    if (!r.rows.length) return res.status(400).json({ success: false, message: 'Session user not found' });
    user = r.rows[0];
  } else {
    return res.status(401).json({ success: false, message: 'Need QR code or login' });
  }

  const already = await pool.query(
    `SELECT 1 FROM attendance WHERE user_id=$1 AND DATE(timestamp)=CURRENT_DATE`,
    [user.id]
  );
  if (already.rows.length) return res.json({ success: false, message: 'Sudah absen hari ini' });

  await pool.query('INSERT INTO attendance (user_id,status) VALUES ($1,$2)', [user.id, body.status || 'Hadir']);
  res.json({ success: true, message: `Absensi tercatat untuk ${user.nama || user.username}` });
});

app.get('/api/attendance/me', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id,timestamp,status FROM attendance WHERE user_id=$1 ORDER BY timestamp DESC',
    [req.session.user.id]
  );
  res.json({ success: true, attendance: rows });
});

app.get('/api/attendance/all', requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT a.id, a.timestamp, a.status, u.id AS user_id, u.username, u.nama
    FROM attendance a JOIN users u ON a.user_id = u.id
    ORDER BY a.timestamp DESC
  `);
  res.json({ success: true, attendance: rows });
});

// ---------- EXPORT ----------
app.get('/api/admin/export/csv', requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT a.id, u.username, u.nama, a.timestamp, a.status
    FROM attendance a JOIN users u ON a.user_id = u.id
    ORDER BY a.timestamp DESC
  `);
  let csv = 'id,username,nama,timestamp,status\n';
  for (const r of rows) {
    const name = (r.nama || '').replace(/"/g, '""');
    csv += `${r.id},${r.username},"${name}",${r.timestamp},${r.status}\n`;
  }
  res.setHeader('Content-Disposition', 'attachment; filename=laporan_absensi.csv');
  res.type('text/csv').send(csv);
});

app.get('/api/admin/export/excel', requireAuth, requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT a.id, u.username, u.nama, a.timestamp, a.status
    FROM attendance a JOIN users u ON a.user_id = u.id
    ORDER BY a.timestamp DESC
  `);
  const ws = xlsx.utils.json_to_sheet(rows);
  const wb = xlsx.utils.book_new();
  xlsx.utils.book_append_sheet(wb, ws, 'Absensi');
  const buffer = xlsx.write(wb, { bookType: 'xlsx', type: 'buffer' });
  res.setHeader('Content-Disposition', 'attachment; filename=laporan_absensi.xlsx');
  res.type('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet').send(buffer);
});

// ---------- SERVER ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));