const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const QRCode = require('qrcode');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({ secret: 'mySecretKey', resave: false, saveUninitialized: true }));

// === قاعدة البيانات ===
const db = new sqlite3.Database('database.sqlite');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'client'
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS dynamic_qrs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    short_code TEXT UNIQUE,
    destination TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  // إنشاء أدمن افتراضي (admin / admin123)
  bcrypt.hash('admin123', 10, (err, hash) => {
    if (!err) {
      db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', ?, 'admin')`, [hash]);
    }
  });
});

// === دوال مساعدة ===
function isLoggedIn(req, res, next) {
  if (req.session.user) return next();
  res.status(401).json({ error: 'غير مسجل الدخول' });
}

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') return next();
  res.status(403).json({ error: 'غير مصرح' });
}

// === 1. تسجيل الدخول ===
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'بيانات غير صحيحة' });
    bcrypt.compare(password, user.password, (err, result) => {
      if (!result) return res.status(401).json({ error: 'بيانات غير صحيحة' });
      req.session.user = { id: user.id, username: user.username, role: user.role };
      res.json({ success: true, role: user.role });
    });
  });
});

// === 2. تسجيل الخروج ===
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// === 3. إضافة عميل (للأدمن فقط) ===
app.post('/api/admin/add-client', isAdmin, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبة' });
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).json({ error: 'خطأ في التشفير' });
    db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hash, 'client'], function(err) {
      if (err) return res.status(400).json({ error: 'اسم المستخدم موجود مسبقاً' });
      res.json({ success: true, id: this.lastID });
    });
  });
});

// === 4. جلب قائمة العملاء (للأدمن) ===
app.get('/api/admin/clients', isAdmin, (req, res) => {
  db.all('SELECT id, username, role FROM users WHERE role = "client"', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// === 5. إنشاء كود ديناميكي (للمستخدم العادي) ===
app.post('/api/dynamic/create', isLoggedIn, (req, res) => {
  const { destination } = req.body;
  if (!destination) return res.status(400).json({ error: 'الرابط الوجهة مطلوب' });
  const short_code = Math.random().toString(36).substring(2, 8);
  db.run('INSERT INTO dynamic_qrs (user_id, short_code, destination) VALUES (?, ?, ?)',
    [req.session.user.id, short_code, destination], async function(err) {
      if (err) return res.status(500).json({ error: err.message });
      const qrDataUrl = await QRCode.toDataURL(`${req.protocol}://${req.get('host')}/go/${short_code}`);
      res.json({ short_code, qrImage: qrDataUrl });
    });
});

// === 6. جلب كل الأكواد الديناميكية للمستخدم الحالي ===
app.get('/api/dynamic/list', isLoggedIn, (req, res) => {
  db.all('SELECT id, short_code, destination FROM dynamic_qrs WHERE user_id = ?', [req.session.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// === 7. تعديل وجهة كود ديناميكي ===
app.put('/api/dynamic/update/:id', isLoggedIn, (req, res) => {
  const { destination } = req.body;
  const id = req.params.id;
  db.run('UPDATE dynamic_qrs SET destination = ? WHERE id = ? AND user_id = ?',
    [destination, id, req.session.user.id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      if (this.changes === 0) return res.status(404).json({ error: 'غير موجود أو غير مصرح' });
      res.json({ success: true });
    });
});

// === 8. التوجيه الديناميكي (عند مسح QR) ===
app.get('/go/:short_code', (req, res) => {
  db.get('SELECT destination FROM dynamic_qrs WHERE short_code = ?', [req.params.short_code], (err, row) => {
    if (err || !row) return res.status(404).send('كود غير صالح');
    res.redirect(row.destination);
  });
});

// === 9. صفحة رئيسية ===
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));

app.listen(3000, () => console.log('✅ الخادم يعمل على http://localhost:3000'));

