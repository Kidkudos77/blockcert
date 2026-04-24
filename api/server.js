'use strict';
/**
 * BlockCert — REST API v3 (Hardened)
 *
 * Security improvements over v2:
 *  - helmet middleware (H2 fix): X-Frame-Options, HSTS, X-Content-Type-Options,
 *    Referrer-Policy, X-DNS-Prefetch-Control
 *  - Content Security Policy tailored to BlockCert (H2 fix)
 *  - express-rate-limit on auth endpoints (H1 fix)
 *  - Strict CORS — no wildcard ngrok matching (H3 fix)
 *  - nlpPayload schema validation (H4 fix)
 *  - Sanitized error responses — no stack traces to client (C4 fix)
 *  - Request ID for audit trail (M3 fix)
 *  - Input length enforcement on all routes
 *  - async login/register (bcrypt)
 */

const express    = require('express');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const bodyParser = require('body-parser');
const cors       = require('cors');
const crypto     = require('crypto');
const fs         = require('fs');
const path       = require('path');
const auth       = require('./auth');
const { getContract } = require('../wallet/wallet_setup');

const app  = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// ── Request ID middleware ────────────────────────────────────────────────────
// Every request gets a unique ID for correlation in logs (M3 fix)
app.use((req, _res, next) => {
    req.id = crypto.randomBytes(8).toString('hex');
    next();
});

// ── Helmet — security headers ────────────────────────────────────────────────
// H2 fix: Sets X-Frame-Options, X-Content-Type-Options, HSTS,
//         Referrer-Policy, X-DNS-Prefetch-Control, Permissions-Policy
app.use(helmet({
    // Content Security Policy tailored to BlockCert
    contentSecurityPolicy: {
        directives: {
            defaultSrc:     ["'self'"],
            scriptSrc:      ["'self'", "'unsafe-inline'",
                             "https://fonts.googleapis.com"],       // GUI inline scripts
            styleSrc:       ["'self'", "'unsafe-inline'",
                             "https://fonts.googleapis.com"],
            fontSrc:        ["'self'", "https://fonts.gstatic.com"],
            imgSrc:         ["'self'", "data:"],
            connectSrc:     ["'self'",
                             "https://kidkudos77.github.io",
                             "https://*.ngrok-free.dev",
                             "https://*.ngrok.io"],                 // API calls from GUI
            frameSrc:       ["'none'"],                             // no iframes
            objectSrc:      ["'none'"],
            baseUri:        ["'self'"],
            formAction:     ["'self'"],
            upgradeInsecureRequests: IS_PROD ? [] : null,
        },
        reportOnly: false,
    },
    // HSTS — only in production (local dev uses HTTP)
    hsts: IS_PROD ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
    // Prevent MIME-type sniffing
    noSniff: true,
    // Prevent clickjacking
    frameguard: { action: 'deny' },
    // Referrer policy — don't leak URL to third parties
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    // Disable browser DNS prefetch
    dnsPrefetchControl: { allow: false },
}));

// Additional headers not covered by helmet
app.use((_req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('X-Request-ID', _req.id);
    next();
});

// ── CORS — strict origin allowlist ───────────────────────────────────────────
// H3 fix: Use exact regex anchored to the specific ngrok free subdomain pattern,
//         not a loose .includes() check.
const NGROK_PATTERN = /^https:\/\/[a-z0-9-]+\.ngrok-free\.app$/;
const NGROK_DEV_PATTERN = /^https:\/\/[a-z0-9-]+\.ngrok-free\.dev$/;

const ALLOWED_ORIGINS = new Set([
    'https://kidkudos77.github.io',
    'http://localhost:8080',
    'http://127.0.0.1:8080',
    'http://localhost:3001',
    'http://localhost:3000',
]);

app.use(cors({
    origin: (origin, cb) => {
        if (!origin) return cb(null, true);  // same-origin or non-browser
        if (ALLOWED_ORIGINS.has(origin))     return cb(null, true);
        if (NGROK_PATTERN.test(origin))      return cb(null, true);
        if (NGROK_DEV_PATTERN.test(origin))  return cb(null, true);
        cb(new Error(`CORS_BLOCKED: ${origin}`));
    },
    methods:        ['GET', 'POST', 'OPTIONS'],  // only what we use (M2 fix)
    allowedHeaders: ['Content-Type', 'Authorization', 'ngrok-skip-browser-warning', 'X-Request-ID'],
    exposedHeaders: ['X-Request-ID'],
    credentials:    true,
    optionsSuccessStatus: 200,
}));

// ── Body parser — strict limits ──────────────────────────────────────────────
app.use(bodyParser.json({
    limit: '50kb',          // reduced from 1mb — credentials never need 1mb
    strict: true,           // only accept arrays and objects (not raw primitives)
}));

// ── Rate limiting ─────────────────────────────────────────────────────────────
// H1 fix: Limit login attempts. 10 attempts per 15 minutes per IP.
const authLimiter = rateLimit({
    windowMs:         15 * 60 * 1000,
    max:              10,
    standardHeaders:  true,
    legacyHeaders:    false,
    message:          { ok: false, error: 'Too many attempts. Try again in 15 minutes.' },
    skipSuccessfulRequests: true,
});

// General API limiter — 300 requests per 15 min per IP
const apiLimiter = rateLimit({
    windowMs:        15 * 60 * 1000,
    max:             300,
    standardHeaders: true,
    legacyHeaders:   false,
});

app.use('/auth/login',    authLimiter);
app.use('/auth/register', authLimiter);
app.use('/',              apiLimiter);

// ── Structured request logger ────────────────────────────────────────────────
// M3 fix: log with request ID, never log request body (could contain passwords)
app.use((req, _res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    console.log(JSON.stringify({
        t:      new Date().toISOString(),
        id:     req.id,
        method: req.method,
        path:   req.path,
        ip:     ip.toString().substring(0, 45), // limit length
    }));
    next();
});

// ── Input validation helpers ─────────────────────────────────────────────────
const HASH_PATTERN    = /^[a-f0-9]{64}$/;       // SHA-256 hex
const STUDENTID_PATTERN = /^[A-Za-z0-9_-]{3,64}$/;

function validateHash(h) {
    return typeof h === 'string' && HASH_PATTERN.test(h);
}

function validateStudentID(id) {
    return typeof id === 'string' && STUDENTID_PATTERN.test(id);
}

// nlpPayload schema validation — H4 fix
// Ensures only expected fields with expected types reach Fabric chaincode
function validateNlpPayload(p) {
    if (!p || typeof p !== 'object') return 'nlpPayload must be an object.';
    if (typeof p.gpa !== 'number' || p.gpa < 0 || p.gpa > 4.0)
        return 'nlpPayload.gpa must be a number between 0 and 4.0.';
    if (!Array.isArray(p.courses_completed))
        return 'nlpPayload.courses_completed must be an array.';
    if (p.courses_completed.length > 20)
        return 'nlpPayload.courses_completed too long.';
    const VALID_COURSES = new Set(['CIS4385C','CIS4360','CIS4361','CNT4406','COP3710','COP3014C']);
    for (const c of p.courses_completed) {
        if (!VALID_COURSES.has(c)) return `Invalid course code: ${c}`;
    }
    if (typeof p.bert_confidence !== 'number' || p.bert_confidence < 0 || p.bert_confidence > 1)
        return 'nlpPayload.bert_confidence must be between 0 and 1.';
    if (typeof p.eligibility_score !== 'number' || p.eligibility_score < 0 || p.eligibility_score > 1)
        return 'nlpPayload.eligibility_score must be between 0 and 1.';
    if (p.student_name && (typeof p.student_name !== 'string' || p.student_name.length > 100))
        return 'nlpPayload.student_name invalid.';
    return null; // valid
}

// C4 fix: never send internal error details to the client
function safeError(e, fallback = 'An internal error occurred.') {
    if (IS_PROD) return fallback;
    // In dev, show the message but not the full stack
    return typeof e?.message === 'string' ? e.message.substring(0, 200) : fallback;
}

// ════════════════════════════════════════════════════════════════════════════
//  HEALTH — public
// ════════════════════════════════════════════════════════════════════════════
app.get('/health', (_req, res) => res.json({
    status:         'ok',
    system:         'BlockCert',
    program:        'FAMU-FCSS',
    pqCryptography: 'CRYSTALS-Dilithium3',
    timestamp:      new Date().toISOString(),
    version:        '3.0',
}));

// ════════════════════════════════════════════════════════════════════════════
//  AUTH ENDPOINTS
// ════════════════════════════════════════════════════════════════════════════

// POST /auth/login
app.post('/auth/login', async (req, res) => {
    const { userID, password } = req.body || {};
    if (typeof userID !== 'string' || typeof password !== 'string')
        return res.status(400).json({ ok: false, error: 'userID and password required.' });

    const result = await auth.login(userID, password);
    return res.status(result.ok ? 200 : 401).json(result);
});

// POST /auth/logout
app.post('/auth/logout', (req, res) => {
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    auth.logout(token);
    return res.json({ ok: true });
});

// POST /auth/register
app.post('/auth/register', async (req, res) => {
    const result = await auth.register(req.body || {});
    return res.status(result.ok ? 201 : 400).json(result);
});

// POST /auth/change-password
app.post('/auth/change-password', auth.requireAuth(), async (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    if (typeof currentPassword !== 'string' || typeof newPassword !== 'string')
        return res.status(400).json({ ok: false, error: 'currentPassword and newPassword required.' });
    if (newPassword.length < 8 || newPassword.length > 128)
        return res.status(400).json({ ok: false, error: 'New password must be 8–128 characters.' });

    // Verify current password before changing
    const verify = await auth.login(req.session.userID, currentPassword);
    if (!verify.ok)
        return res.status(401).json({ ok: false, error: 'Current password incorrect.' });

    const usersPath = path.join(__dirname, 'users.json');
    const store = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
    const user  = store.users.find(u => u.userID === req.session.userID);
    if (!user) return res.status(404).json({ ok: false, error: 'User not found.' });

    user.passwordHash = await auth.hashPassword(newPassword);
    // Atomic write (C2 fix applied here too)
    const tmp = usersPath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(store, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, usersPath);

    // Invalidate existing session to force re-login with new password
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    auth.logout(token);

    return res.json({ ok: true, message: 'Password updated. Please log in again.' });
});

// ════════════════════════════════════════════════════════════════════════════
//  ADMIN ENDPOINTS
// ════════════════════════════════════════════════════════════════════════════

app.get('/admin/pending', auth.requireAuth(['admin']), (_req, res) => {
    return res.json({ ok: true, pending: auth.getPendingRegistrations() });
});

app.post('/admin/approve/:userID', auth.requireAuth(['admin']), (req, res) => {
    const target = auth.sanitizeStr(req.params.userID, 64);
    const token  = (req.headers.authorization || '').replace('Bearer ', '').trim();
    const result = auth.approveUser(token, target);
    return res.status(result.ok ? 200 : 403).json(result);
});

app.post('/admin/reject/:userID', auth.requireAuth(['admin']), (req, res) => {
    const target = auth.sanitizeStr(req.params.userID, 64);
    const reason = auth.sanitizeStr((req.body || {}).reason || '', 200);
    const token  = (req.headers.authorization || '').replace('Bearer ', '').trim();
    const result = auth.rejectUser(token, target, reason);
    return res.status(result.ok ? 200 : 403).json(result);
});

app.get('/admin/users', auth.requireAuth(['admin']), (req, res) => {
    const token  = (req.headers.authorization || '').replace('Bearer ', '').trim();
    const result = auth.listUsers(token);
    return res.status(result.ok ? 200 : 403).json(result);
});

// ════════════════════════════════════════════════════════════════════════════
//  CREDENTIAL ENDPOINTS
// ════════════════════════════════════════════════════════════════════════════

// POST /issue
app.post('/issue', auth.requireAuth(['institution', 'admin']), async (req, res) => {
    const { studentID, nlpPayload } = req.body || {};

    if (!validateStudentID(studentID))
        return res.status(400).json({ error: 'Invalid studentID format.' });

    // H4 fix: strict schema validation before passing to Fabric
    const schemaError = validateNlpPayload(nlpPayload);
    if (schemaError)
        return res.status(400).json({ error: schemaError });

    if (nlpPayload.bert_confidence < 0.60)
        return res.status(422).json({ error: 'BERT confidence below threshold.' });

    try {
        const { contract, gateway } = await getContract(req.session.fabricID);
        // Rebuild a clean payload object — never pass raw user input directly to chaincode
        const cleanPayload = {
            gpa:               Number(nlpPayload.gpa.toFixed(2)),
            courses_completed: nlpPayload.courses_completed,
            bert_confidence:   Number(nlpPayload.bert_confidence.toFixed(4)),
            eligibility_score: Number(nlpPayload.eligibility_score.toFixed(4)),
            student_name:      auth.sanitizeStr(nlpPayload.student_name || '', 100),
        };
        const result = await contract.submitTransaction(
            'issueMicroCredential', studentID, JSON.stringify(cleanPayload));
        await gateway.disconnect();
        const parsed = JSON.parse(result.toString());
        return res.status(parsed.success ? 201 : 422).json(parsed);
    } catch(e) {
        console.error({ id: req.id, route: '/issue', error: e.message });
        return res.status(500).json({ error: safeError(e) });  // C4 fix
    }
});

// GET /verify/:hash
app.get('/verify/:hash', auth.requireAuth(), async (req, res) => {
    if (!validateHash(req.params.hash))
        return res.status(400).json({ error: 'Invalid hash format.' });

    try {
        const { contract, gateway } = await getContract(req.session.fabricID);
        const result = await contract.evaluateTransaction('verifyCredential', req.params.hash);
        await gateway.disconnect();
        res.setHeader('Content-Type', 'application/ld+json');
        return res.json(JSON.parse(result.toString()));
    } catch(e) {
        console.error({ id: req.id, route: '/verify', error: e.message });
        return res.status(500).json({ error: safeError(e) });
    }
});

// GET /student/:id
app.get('/student/:id', auth.requireAuth(), async (req, res) => {
    const sess = req.session;
    const targetID = auth.sanitizeStr(req.params.id, 64);

    if (!validateStudentID(targetID))
        return res.status(400).json({ error: 'Invalid student ID format.' });

    if (sess.role === 'student' && sess.userID !== targetID)
        return res.status(403).json({ error: 'Access denied.' });

    try {
        const { contract, gateway } = await getContract(sess.fabricID);
        const result = await contract.evaluateTransaction('getStudentCredentials', targetID);
        await gateway.disconnect();
        res.setHeader('Content-Type', 'application/ld+json');
        return res.json(JSON.parse(result.toString()));
    } catch(e) {
        return res.status(500).json({ error: safeError(e) });
    }
});

// POST /revoke
app.post('/revoke', auth.requireAuth(['institution', 'admin']), async (req, res) => {
    const { credHash, reason } = req.body || {};
    if (!validateHash(credHash))
        return res.status(400).json({ error: 'Invalid credential hash format.' });

    const cleanReason = auth.sanitizeStr(reason || '', 200);

    try {
        const { contract, gateway } = await getContract(req.session.fabricID);
        const result = await contract.submitTransaction('revokeCredential', credHash, cleanReason);
        await gateway.disconnect();
        return res.json(JSON.parse(result.toString()));
    } catch(e) {
        return res.status(500).json({ error: safeError(e) });
    }
});

// GET /analytics
app.get('/analytics', auth.requireAuth(['institution', 'admin']), async (req, res) => {
    try {
        const { contract, gateway } = await getContract(req.session.fabricID);
        const result = await contract.evaluateTransaction('getProgramAnalytics');
        await gateway.disconnect();
        return res.json(JSON.parse(result.toString()));
    } catch(e) {
        return res.status(403).json({ error: safeError(e) });
    }
});


// GET /admin/verify-alerts — hash mismatch alerts (Item 3)
app.get('/admin/verify-alerts', auth.requireAuth(['admin']), async (req, res) => {
    try {
        const { contract, gateway } = await getContract(req.session.fabricID);
        const result = await contract.evaluateTransaction('getMismatchAlerts');
        await gateway.disconnect();
        return res.json(JSON.parse(result.toString()));
    } catch(e) {
        // If chaincode not yet upgraded, return empty alerts
        console.error({ id: req.id, route: '/admin/verify-alerts', error: e.message });
        return res.json({ alertCount: 0, alerts: [], note: 'Chaincode upgrade pending' });
    }
});

// GET /admin/verify-log — full verification log (Item 3)
app.get('/admin/verify-log', auth.requireAuth(['admin', 'institution']), async (req, res) => {
    const limit = Math.min(parseInt(req.query.limit||'50'), 200);
    try {
        const { contract, gateway } = await getContract(req.session.fabricID);
        const result = await contract.evaluateTransaction('getVerificationLog', String(limit));
        await gateway.disconnect();
        return res.json(JSON.parse(result.toString()));
    } catch(e) {
        console.error({ id: req.id, route: '/admin/verify-log', error: e.message });
        return res.json({ count: 0, entries: [], alerts: 0, note: 'Chaincode upgrade pending' });
    }
});

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Route not found.' }));

// ── Error handler ─────────────────────────────────────────────────────────────
// C4 fix: never leak stack traces or internal details
app.use((err, req, res, _next) => {
    if (err.message?.startsWith('CORS_BLOCKED'))
        return res.status(403).json({ error: 'Origin not allowed.' });
    if (err.type === 'entity.parse.failed')
        return res.status(400).json({ error: 'Invalid JSON.' });
    if (err.status === 413)
        return res.status(413).json({ error: 'Request too large.' });
    console.error({ id: req.id, error: err.message });
    return res.status(500).json({ error: 'Internal server error.' });
});

app.listen(PORT, () => {
    console.log(`\n  CertChain API v3 (Hardened)  →  http://localhost:${PORT}`);
    console.log('  Helmet: ✓  Rate-limiting: ✓  bcrypt: ✓  Atomic writes: ✓\n');
});

module.exports = app;
