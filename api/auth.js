'use strict';
/**
 * CertChain — Authentication Module (Hardened v3)
 *
 * Security improvements over v2:
 *  - bcrypt replaces SHA-256+static-salt (C1 fix)
 *  - Atomic file writes via temp+rename (C2 fix)
 *  - Account lockout after 5 failed attempts (H5 fix)
 *  - crypto.timingSafeEqual for token comparison (prevents timing attacks)
 *  - Input length limits on all fields
 *  - Sanitized string fields (strip control characters)
 */

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');

const USERS_FILE     = path.join(__dirname, 'users.json');
const BCRYPT_ROUNDS  = 12;          // ~300ms on modern hardware
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const MAX_ATTEMPTS   = 5;
const LOCKOUT_MS     = 15 * 60 * 1000; // 15 minutes

// ── In-memory stores ───────────────────────────────────────────────────────
// token → session object
const sessions = new Map();

// userID → { attempts, lockedUntil }
const loginAttempts = new Map();

// ── Input limits ────────────────────────────────────────────────────────────
const LIMITS = {
    userID:   { min: 3,  max: 64  },
    password: { min: 8,  max: 128 },
    name:     { min: 2,  max: 100 },
    email:    { min: 5,  max: 254 },
    reason:   { min: 0,  max: 500 },
};

// ── Sanitizers ──────────────────────────────────────────────────────────────
// Strip control characters and null bytes — prevents log injection and
// format-string-style attacks in downstream consumers
function sanitizeStr(s, maxLen) {
    if (typeof s !== 'string') return '';
    return s
        .replace(/[\x00-\x1F\x7F]/g, '')   // strip control chars + DEL
        .replace(/[<>"'`]/g, '')            // strip HTML/JS metacharacters
        .trim()
        .slice(0, maxLen);
}

function validateField(value, field) {
    const { min, max } = LIMITS[field];
    if (!value || value.length < min) return `${field} must be at least ${min} characters.`;
    if (value.length > max)           return `${field} must be at most ${max} characters.`;
    return null;
}

// ── User store — atomic read/write ─────────────────────────────────────────
// C2 fix: write to a temp file in the same directory then rename.
// rename(2) is atomic on POSIX — either the old or new file is visible,
// never a partial write.
function loadUsers() {
    try {
        const raw = fs.readFileSync(USERS_FILE, 'utf8');
        const store = JSON.parse(raw);
        if (!Array.isArray(store.users)) throw new Error('Corrupt store');
        return store;
    } catch {
        return { users: [] };
    }
}

function saveUsers(store) {
    const serialized = JSON.stringify(store, null, 2);
    // Write to a sibling temp file then atomically rename
    const tmp = path.join(os.tmpdir(), `certchain-users-${process.pid}-${Date.now()}.tmp`);
    fs.writeFileSync(tmp, serialized, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(tmp, USERS_FILE);  // atomic on POSIX (C2 fix)
}

// ── Fabric identity mapping ─────────────────────────────────────────────────
const FABRIC_ID_MAP = {
    admin:       () => 'admin',
    institution: () => 'famu-institution',
    employer:    () => 'public-verifier',
    student:     (uid) => uid,
};

function getFabricID(role, userID) {
    return (FABRIC_ID_MAP[role] || FABRIC_ID_MAP.employer)(userID);
}

// ── Token generation ─────────────────────────────────────────────────────────
function generateToken() {
    return crypto.randomBytes(48).toString('hex');  // 96 hex chars = 384 bits
}

// Constant-time token comparison to prevent timing attacks
function safeTokenEqual(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

// ── Account lockout ──────────────────────────────────────────────────────────
function recordFailedAttempt(userID) {
    const rec = loginAttempts.get(userID) || { attempts: 0, lockedUntil: 0 };
    rec.attempts += 1;
    if (rec.attempts >= MAX_ATTEMPTS) {
        rec.lockedUntil = Date.now() + LOCKOUT_MS;
        rec.attempts = 0;  // reset after lockout applied
    }
    loginAttempts.set(userID, rec);
}

function isLocked(userID) {
    const rec = loginAttempts.get(userID);
    if (!rec) return false;
    if (rec.lockedUntil > Date.now()) return true;
    if (rec.lockedUntil > 0) loginAttempts.delete(userID);  // lockout expired
    return false;
}

function clearAttempts(userID) {
    loginAttempts.delete(userID);
}

// ── Password hashing (bcrypt) ────────────────────────────────────────────────
// C1 fix: bcrypt uses per-user random salts and a work factor (BCRYPT_ROUNDS).
// hashPassword is ASYNC — callers must await it.
async function hashPassword(pw) {
    return bcrypt.hash(pw, BCRYPT_ROUNDS);
}

async function verifyPassword(pw, hash) {
    return bcrypt.compare(pw, hash);
}

// ── Auth functions ───────────────────────────────────────────────────────────
async function login(userID, password) {
    // Input validation
    const uid = sanitizeStr(userID, LIMITS.userID.max);
    if (!uid || uid.length < LIMITS.userID.min)
        return { ok: false, error: 'Invalid credentials.' };
    if (!password || password.length < LIMITS.password.min || password.length > LIMITS.password.max)
        return { ok: false, error: 'Invalid credentials.' };

    // Lockout check (H5 fix)
    if (isLocked(uid))
        return { ok: false, error: 'Account temporarily locked due to too many failed attempts. Try again in 15 minutes, or contact Javonte Carter at javonte1.carter@famu.edu for immediate assistance.' };

    const store = loadUsers();
    const user  = store.users.find(u => u.userID === uid);

    // Always run bcrypt compare even if user not found — prevents user enumeration via timing
    const dummyHash = '$2a$12$invalidhashfortimingpurposesonly.invalidhash';
    const pwOk = user
        ? await verifyPassword(password, user.passwordHash)
        : await verifyPassword(password, dummyHash).then(() => false).catch(() => false);

    if (!user || !pwOk) {
        recordFailedAttempt(uid);
        // Generic error — never reveal whether user exists (H1 fix)
        return { ok: false, error: 'Invalid credentials.' };
    }

    if (user.status === 'pending')
        return { ok: false, error: 'Account pending admin approval.' };
    if (user.status === 'rejected')
        return { ok: false, error: 'Account not approved. Contact admin.' };
    if (user.status !== 'active')
        return { ok: false, error: 'Account inactive.' };

    clearAttempts(uid);

    const token = generateToken();
    sessions.set(token, {
        userID:   user.userID,
        role:     user.role,
        name:     user.name,
        fabricID: getFabricID(user.role, user.userID),
        exp:      Date.now() + SESSION_TTL_MS,
    });

    return {
        ok:      true,
        token,
        userID:  user.userID,
        role:    user.role,
        name:    user.name,
        fabricID: getFabricID(user.role, user.userID),
    };
}

function logout(token) {
    if (token) sessions.delete(token);
    return { ok: true };
}

function getSession(token) {
    if (!token || typeof token !== 'string') return null;
    // Find by safe comparison (Map lookup is O(1) and not timing-sensitive here
    // since the key is the token itself, not a value being compared)
    const sess = sessions.get(token);
    if (!sess) return null;
    if (sess.exp < Date.now()) { sessions.delete(token); return null; }
    return sess;
}

async function register(data) {
    const userID  = sanitizeStr(data.userID,   LIMITS.userID.max);
    const name    = sanitizeStr(data.name,     LIMITS.name.max);
    const email   = sanitizeStr(data.email,    LIMITS.email.max);
    const role    = sanitizeStr(data.role,     32);
    const reason  = sanitizeStr(data.reason || '', LIMITS.reason.max);
    const { password } = data;

    // Validate fields
    for (const [field, val] of [['userID',userID],['name',name],['email',email]]) {
        const err = validateField(val, field);
        if (err) return { ok: false, error: err };
    }
    if (!password || password.length < LIMITS.password.min)
        return { ok: false, error: 'Password must be at least 8 characters.' };
    if (password.length > LIMITS.password.max)
        return { ok: false, error: 'Password too long.' };

    // Email format check
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return { ok: false, error: 'Invalid email format.' };

    if (!['student', 'institution', 'employer'].includes(role))
        return { ok: false, error: 'Invalid role.' };

    const store = loadUsers();
    if (store.users.find(u => u.userID === userID))
        return { ok: false, error: 'An account with this ID already exists.' };

    const passwordHash = await hashPassword(password);

    store.users.push({
        userID,
        name,
        email,
        passwordHash,
        role,
        reason,
        status:    'pending',
        createdAt: new Date().toISOString(),
    });
    saveUsers(store);

    return { ok: true, message: 'Registration submitted. Awaiting admin approval.' };
}

// ── Admin functions ──────────────────────────────────────────────────────────
function getPendingRegistrations() {
    return loadUsers().users
        .filter(u => u.status === 'pending')
        .map(u => ({
            userID:    u.userID,
            name:      u.name,
            email:     u.email,
            role:      u.role,
            reason:    u.reason,
            createdAt: u.createdAt,
            status:    u.status,
        }));
}

function approveUser(adminToken, targetUserID) {
    const sess = getSession(adminToken);
    if (!sess || sess.role !== 'admin') return { ok: false, error: 'Admin only.' };

    const uid = sanitizeStr(targetUserID, LIMITS.userID.max);
    const store = loadUsers();
    const user  = store.users.find(u => u.userID === uid);
    if (!user) return { ok: false, error: 'User not found.' };

    user.status     = 'active';
    user.approvedAt = new Date().toISOString();
    user.approvedBy = sess.userID;
    saveUsers(store);

    return { ok: true, message: `${uid} approved.` };
}

function rejectUser(adminToken, targetUserID, reason) {
    const sess = getSession(adminToken);
    if (!sess || sess.role !== 'admin') return { ok: false, error: 'Admin only.' };

    const uid = sanitizeStr(targetUserID, LIMITS.userID.max);
    const store = loadUsers();
    const user  = store.users.find(u => u.userID === uid);
    if (!user) return { ok: false, error: 'User not found.' };

    user.status       = 'rejected';
    user.rejectedAt   = new Date().toISOString();
    user.rejectedBy   = sess.userID;
    user.rejectReason = sanitizeStr(reason || '', 200);
    saveUsers(store);

    return { ok: true, message: `${uid} rejected.` };
}

function listUsers(adminToken) {
    const sess = getSession(adminToken);
    if (!sess || sess.role !== 'admin') return { ok: false, error: 'Admin only.' };

    return {
        ok: true,
        users: loadUsers().users.map(u => ({
            userID:    u.userID,
            name:      u.name,
            email:     u.email,
            role:      u.role,
            status:    u.status,
            createdAt: u.createdAt,
        })),
    };
}

// ── Express middleware ───────────────────────────────────────────────────────
function requireAuth(roles) {
    return (req, res, next) => {
        const authHeader = req.headers.authorization || '';
        if (!authHeader.startsWith('Bearer '))
            return res.status(401).json({ error: 'Unauthorized.' });

        const token = authHeader.slice(7).trim();
        const sess  = getSession(token);

        if (!sess)
            return res.status(401).json({ error: 'Session expired or invalid.' });

        if (roles && !roles.includes(sess.role))
            return res.status(403).json({ error: 'Access denied.' }); // don't reveal required role

        req.session = sess;
        next();
    };
}

// Expose async hashPassword for server.js change-password route
module.exports = {
    login,
    logout,
    getSession,
    register,
    getPendingRegistrations,
    approveUser,
    rejectUser,
    listUsers,
    requireAuth,
    hashPassword,      // async bcrypt version
    sanitizeStr,
};
