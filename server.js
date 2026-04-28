// server.js
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

// تهيئة اتصال قاعدة البيانات
// سنستخدم متغير البيئة DATABASE_URL الذي سنضيفه لاحقاً
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // ضروري لـ Neon
});

// إدارة الجلسات (حل بسيط)
let sessions = {};

function getSessionUser(sessionId) { return sessions[sessionId]; }
function setSessionUser(sessionId, user) { sessions[sessionId] = user; }
function destroySession(sessionId) { delete sessions[sessionId]; }

// Middleware لمعرفة المستخدم من الـ sessionId
app.use((req, res, next) => {
    const sessionId = req.headers['x-session-id'];
    if (sessionId) {
        req.user = getSessionUser(sessionId);
    }
    next();
});

// دوال المساعدة للتحقق من الصلاحيات
function isLoggedIn(req, res, next) {
    if (req.user) return next();
    res.status(401).json({ error: 'غير مسجل الدخول' });
}

function isAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') return next();
    res.status(403).json({ error: 'غير مصرح' });
}

// --- واجهات برمجة التطبيقات (APIs) ---

// 1. تسجيل الدخول
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];
        if (!user) return res.status(401).json({ error: 'بيانات غير صحيحة' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'بيانات غير صحيحة' });

        const sessionId = Math.random().toString(36).substring(2);
        setSessionUser(sessionId, { id: user.id, username: user.username, role: user.role });
        res.json({ success: true, role: user.role, sessionId: sessionId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. إضافة عميل (للأدمن فقط)
app.post('/api/admin/add-client', isAdmin, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبة' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', [username, hashedPassword, 'client']);
        res.json({ success: true });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'اسم المستخدم موجود مسبقاً' });
        res.status(500).json({ error: err.message });
    }
});

// 3. جلب قائمة العملاء (للأدمن فقط)
app.get('/api/admin/clients', isAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, role FROM users WHERE role = $1', ['client']);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. إنشاء كود ديناميكي جديد
app.post('/api/dynamic/create', isLoggedIn, async (req, res) => {
    const { destination } = req.body;
    if (!destination) return res.status(400).json({ error: 'الرابط الوجهة مطلوب' });
    const short_code = Math.random().toString(36).substring(2, 8);
    try {
        await pool.query('INSERT INTO dynamic_qrs (user_id, short_code, destination) VALUES ($1, $2, $3)', [req.user.id, short_code, destination]);
        const qrDataUrl = await QRCode.toDataURL(`${req.protocol}://${req.get('host')}/go/${short_code}`);
        res.json({ short_code, qrImage: qrDataUrl });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 5. جلب قائمة الأكواد للمستخدم الحالي
app.get('/api/dynamic/list', isLoggedIn, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, short_code, destination FROM dynamic_qrs WHERE user_id = $1', [req.user.id]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 6. تعديل وجهة كود ديناميكي
app.put('/api/dynamic/update/:id', isLoggedIn, async (req, res) => {
    const { destination } = req.body;
    const { id } = req.params;
    try {
        await pool.query('UPDATE dynamic_qrs SET destination = $1 WHERE id = $2 AND user_id = $3', [destination, id, req.user.id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 7. التوجيه الديناميكي (عند مسح QR)
app.get('/go/:short_code', async (req, res) => {
    try {
        const result = await pool.query('SELECT destination FROM dynamic_qrs WHERE short_code = $1', [req.params.short_code]);
        if (result.rows.length === 0) return res.status(404).send('كود غير صالح');
        res.redirect(result.rows[0].destination);
    } catch (err) {
        res.status(404).send('كود غير صالح');
    }
});

// 8. تسجيل الخروج
app.post('/api/logout', (req, res) => {
    const sessionId = req.headers['x-session-id'];
    if (sessionId) destroySession(sessionId);
    res.json({ success: true });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 الخادم يعمل على http://localhost:${PORT}`));















