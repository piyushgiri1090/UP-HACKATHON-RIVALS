const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
let nodemailer;
try {
    nodemailer = require('nodemailer');
} catch (error) {
    nodemailer = null;
}

const app = express();
// Deployment platforms apna PORT khud dete hain, isliye process.env.PORT zaroori hai
const PORT = Number(process.env.PORT) || 5000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const otpStore = new Map();
const usersDb = new Map();
const adminSessions = new Map();
const dataDirectory = path.join(__dirname, 'data');
const dataFile = path.join(dataDirectory, 'submissions.json');
const adminEmail = (process.env.ADMIN_EMAIL || 'admin@uphackathonrivals.in').toLowerCase();
const adminUserId = process.env.ADMIN_USER_ID || 'admin';
const adminMobile = process.env.ADMIN_MOBILE || '';
const adminPassword = process.env.ADMIN_PASSWORD || 'UPRivals@2026';

if (!fs.existsSync(dataDirectory)) fs.mkdirSync(dataDirectory, { recursive: true });
if (!fs.existsSync(dataFile)) fs.writeFileSync(dataFile, JSON.stringify({ registrations: [], feedback: [] }, null, 2));

function readStoredData() {
    return JSON.parse(fs.readFileSync(dataFile, 'utf8'));
}

function writeStoredData(data) {
    fs.writeFileSync(dataFile, JSON.stringify(data, null, 2));
}

function createAdminToken() {
    const token = crypto.randomBytes(32).toString('hex');
    adminSessions.set(token, Date.now() + 8 * 60 * 60 * 1000);
    return token;
}

function requireAdmin(req, res, next) {
    const token = req.get('Authorization')?.replace('Bearer ', '');
    const expiresAt = token && adminSessions.get(token);
    if (!expiresAt || Date.now() > expiresAt) {
        if (token) adminSessions.delete(token);
        return res.status(401).json({ success: false, message: 'Admin login required.' });
    }
    req.adminToken = token;
    return next();
}

function generateOtp() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOtpEmail(email, otp, purpose) {
    if (!nodemailer || !process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASSWORD) {
        console.warn(`[AUTH] SMTP is not configured. Demo OTP for ${email}: ${otp}`);
        return false;
    }
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: process.env.SMTP_SECURE === 'true',
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD }
    });
    await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: email,
        subject: `UP Hackathon Rivals - ${purpose} OTP`,
        text: `Your OTP is ${otp}. It expires in 5 minutes.`
    });
    return true;
}

function storeOtp(key, otp) {
    otpStore.set(key, { otp, expiresAt: Date.now() + 5 * 60 * 1000 });
}

app.post('/api/auth/send-otp', async (req, res) => {
    const { email } = req.body;
    if (!email || !email.includes('@')) {
        return res.status(400).json({ success: false, message: 'Valid email zaroori hai.' });
    }

    const otp = generateOtp();
    try {
        const cleanEmail = email.toLowerCase();
        storeOtp(`user:${cleanEmail}`, otp);
        const delivered = await sendOtpEmail(cleanEmail, otp, 'User verification');
        return res.status(200).json({ success: true, message: delivered ? 'OTP email par bhej diya gaya hai.' : 'Local demo mode: SMTP configure nahi hai.', ...(delivered ? {} : { demoOtp: otp }) });
    } catch (error) {
        console.error('[AUTH] User OTP email failed:', error.message);
        return res.status(502).json({ success: false, message: 'OTP email send nahi ho saka.' });
    }
});

app.post('/api/auth/verify-otp', (req, res) => {
    const { email, otp, type, firstName, middleName, lastName, mobile, college, teamName } = req.body;
    if (!email || !otp) {
        return res.status(400).json({ success: false, message: 'Email aur OTP dono bharein.' });
    }
    if (type === 'register' && (!firstName || !lastName || !mobile)) {
        return res.status(400).json({ success: false, message: 'First name, last name aur mobile number zaroori hain.' });
    }

    const cleanEmail = email.toLowerCase();
    const record = otpStore.get(`user:${cleanEmail}`);

    if (!record) {
        return res.status(400).json({ success: false, message: 'OTP expire ho gaya ya generate nahi hua.' });
    }

    if (Date.now() > record.expiresAt) {
        otpStore.delete(`user:${cleanEmail}`);
        return res.status(400).json({ success: false, message: 'OTP expire ho chuka hai.' });
    }

    if (record.otp !== otp.trim()) {
        return res.status(400).json({ success: false, message: 'Galat OTP!' });
    }

    otpStore.delete(`user:${cleanEmail}`);

    if (type === 'register') {
        const profile = { email: cleanEmail, firstName, middleName, lastName, name: [firstName, middleName, lastName].filter(Boolean).join(' '), mobile, college, teamName, role: 'user' };
        usersDb.set(cleanEmail, profile);
        const storedData = readStoredData();
        storedData.registrations = storedData.registrations.filter((item) => item.email !== cleanEmail);
        storedData.registrations.push({ ...profile, createdAt: new Date().toISOString() });
        writeStoredData(storedData);
    }

    const userProfile = usersDb.get(cleanEmail) || { email: cleanEmail };

    return res.status(200).json({
        success: true,
        message: type === 'register' ? 'Registration complete!' : 'Login successful!',
        user: userProfile,
        token: `hack_token_${Date.now()}`
    });

});

app.post('/api/auth/admin-login', (req, res) => {
    const { identifier, password } = req.body;
    const cleanIdentifier = String(identifier || '').trim().toLowerCase();
    const validIdentifier = cleanIdentifier === adminEmail || cleanIdentifier === adminUserId.toLowerCase() || cleanIdentifier === adminMobile;
    if (!validIdentifier || password !== adminPassword) {
        return res.status(401).json({ success: false, message: 'Invalid admin credentials.' });
    }
    const otp = generateOtp();
    storeOtp(`admin:${adminEmail}`, otp);
    sendOtpEmail(adminEmail, otp, 'Admin login').catch((error) => console.error('[AUTH] Admin OTP email failed:', error.message));
    return res.json({ success: true, requiresOtp: true, email: adminEmail, message: 'Admin OTP email par bhej diya gaya hai.', ...(!process.env.SMTP_HOST ? { demoOtp: otp } : {}) });
});

app.post('/api/auth/admin-verify-otp', (req, res) => {
    const { otp } = req.body;
    const record = otpStore.get(`admin:${adminEmail}`);
    if (!record || Date.now() > record.expiresAt || record.otp !== String(otp || '').trim()) {
        return res.status(401).json({ success: false, message: 'Invalid or expired admin OTP.' });
    }
    otpStore.delete(`admin:${adminEmail}`);
    return res.json({ success: true, role: 'admin', token: createAdminToken() });
});

app.post('/api/feedback', (req, res) => {
    const message = String(req.body.message || '').trim();
    if (!message || message.length > 1000) {
        return res.status(400).json({ success: false, message: 'Feedback is required and must be under 1000 characters.' });
    }
    const storedData = readStoredData();
    storedData.feedback.push({ message, createdAt: new Date().toISOString() });
    writeStoredData(storedData);
    return res.status(201).json({ success: true, message: 'Feedback saved.' });
});

app.get('/api/admin/data', requireAdmin, (req, res) => {
    return res.json({ success: true, data: readStoredData() });
});

app.delete('/api/admin/users/:email', requireAdmin, (req, res) => {
    const email = decodeURIComponent(req.params.email).toLowerCase();
    const storedData = readStoredData();
    storedData.registrations = storedData.registrations.filter((item) => item.email !== email);
    usersDb.delete(email);
    writeStoredData(storedData);
    return res.json({ success: true });
});

app.post('/api/admin/users', requireAdmin, (req, res) => {
    const { firstName, middleName, lastName, email, mobile, college, teamName } = req.body;
    const cleanEmail = String(email || '').trim().toLowerCase();
    if (!firstName || !lastName || !cleanEmail.includes('@') || !mobile) {
        return res.status(400).json({ success: false, message: 'First name, last name, email and mobile are required.' });
    }
    const profile = { firstName, middleName, lastName, name: [firstName, middleName, lastName].filter(Boolean).join(' '), email: cleanEmail, mobile, college, teamName, role: 'user' };
    const storedData = readStoredData();
    storedData.registrations = storedData.registrations.filter((item) => item.email !== cleanEmail);
    storedData.registrations.push({ ...profile, createdAt: new Date().toISOString(), addedByAdmin: true });
    usersDb.set(cleanEmail, profile);
    writeStoredData(storedData);
    return res.status(201).json({ success: true });
});

app.post('/api/admin/notices', requireAdmin, (req, res) => {
    const title = String(req.body.title || '').trim();
    const message = String(req.body.message || '').trim();
    if (!title || !message || title.length > 120 || message.length > 1000) {
        return res.status(400).json({ success: false, message: 'Notice title and message are required.' });
    }
    const storedData = readStoredData();
    storedData.notices = storedData.notices || [];
    storedData.notices.push({ id: crypto.randomUUID(), title, message, createdAt: new Date().toISOString() });
    writeStoredData(storedData);
    return res.status(201).json({ success: true });
});

app.get('/api/notices', (req, res) => {
    const storedData = readStoredData();
    return res.json({ success: true, notices: (storedData.notices || []).slice(-10).reverse() });
});

app.post('/api/auth/admin-logout', requireAdmin, (req, res) => {
    adminSessions.delete(req.adminToken);
    return res.json({ success: true });
});

app.listen(PORT, () => {
    console.log(`Server live on port ${PORT}`);
});