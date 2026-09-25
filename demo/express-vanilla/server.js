/**
 * awesome-node-auth live demo server
 *
 * A fully working Express application that uses awesome-node-auth with an
 * in-memory user store.  Run `npm start` — the server listens on port 3000
 * (or the PORT environment variable set by StackBlitz / the host).
 *
 * Routes
 *   POST  /auth/register
 *   POST  /auth/login
 *   POST  /auth/logout
 *   POST  /auth/refresh
 *   GET   /auth/me           (requires access-token cookie)
 *   GET   /auth/ui/login     (built-in login UI — SSR, themed)
 *   GET   /auth/ui/register  (built-in register UI)
 *   GET   /admin             (admin HTML UI — password: 1234)
 *   GET   /admin/api/users   (admin REST API)
 *   GET   /                  → serves public/index.html
 */

'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const os = require('os');
const { AuthConfigurator, createAdminRouter, buildUiRouter, PasswordService, MemoryTemplateStore } = require('@awesome-lang-auth/node');

const passwordService = new PasswordService();

// ── In-memory user store ──────────────────────────────────────────────────────

class InMemoryUserStore {
  constructor() {
    this._users = new Map();
    this._nextId = 1;
  }

  async findByEmail(email) {
    return [...this._users.values()].find(u => u.email === email) ?? null;
  }

  async findById(id) {
    return this._users.get(id) ?? null;
  }

  async create(data) {
    const id = String(this._nextId++);
    const user = { id, email: '', ...data };
    this._users.set(id, user);
    return user;
  }

  async updateRefreshToken(userId, token, expiry) {
    const u = this._users.get(userId);
    if (u) { u.refreshToken = token; u.refreshTokenExpiry = expiry; }
  }

  async updateLastLogin(userId) {
    const u = this._users.get(userId);
    if (u) u.lastLogin = new Date();
  }

  async updateResetToken(userId, token, expiry) {
    const u = this._users.get(userId);
    if (u) { u.resetToken = token; u.resetTokenExpiry = expiry; }
  }

  async updatePassword(userId, hashedPassword) {
    const u = this._users.get(userId);
    if (u) u.password = hashedPassword;
  }

  async updateTotpSecret(userId, secret) {
    const u = this._users.get(userId);
    if (u) { u.totpSecret = secret; u.isTotpEnabled = secret !== null; }
  }

  async updateMagicLinkToken(userId, token, expiry) {
    const u = this._users.get(userId);
    if (u) { u.magicLinkToken = token; u.magicLinkTokenExpiry = expiry; }
  }

  async updateSmsCode(userId, code, expiry) {
    const u = this._users.get(userId);
    if (u) { u.smsCode = code; u.smsCodeExpiry = expiry; }
  }

  async findByResetToken(token) {
    return [...this._users.values()].find(u => u.resetToken === token) ?? null;
  }

  async findByMagicLinkToken(token) {
    return [...this._users.values()].find(u => u.magicLinkToken === token) ?? null;
  }

  async updateEmailVerificationToken(userId, token, expiry) {
    const u = this._users.get(userId);
    if (u) { u.emailVerificationToken = token; u.emailVerificationTokenExpiry = expiry; }
  }

  async updateEmailVerified(userId, isVerified) {
    const u = this._users.get(userId);
    if (u) u.isEmailVerified = isVerified;
  }

  async findByEmailVerificationToken(token) {
    return [...this._users.values()].find(u => u.emailVerificationToken === token) ?? null;
  }

  async updateEmailChangeToken(userId, pendingEmail, token, expiry) {
    const u = this._users.get(userId);
    if (u) { u.pendingEmail = pendingEmail; u.emailChangeToken = token; u.emailChangeTokenExpiry = expiry; }
  }

  async updateEmail(userId, newEmail) {
    const u = this._users.get(userId);
    if (u) { u.email = newEmail; u.pendingEmail = null; u.emailChangeToken = null; u.emailChangeTokenExpiry = null; }
  }

  async findByEmailChangeToken(token) {
    return [...this._users.values()].find(u => u.emailChangeToken === token) ?? null;
  }

  async updateAccountLinkToken(userId, pendingEmail, pendingProvider, token, expiry) {
    const u = this._users.get(userId);
    if (u) {
      u.accountLinkPendingEmail = pendingEmail;
      u.accountLinkPendingProvider = pendingProvider;
      u.accountLinkToken = token;
      u.accountLinkTokenExpiry = expiry;
    }
  }

  async findByAccountLinkToken(token) {
    return [...this._users.values()].find(u => u.accountLinkToken === token) ?? null;
  }

  async findByProviderAccount(provider, providerAccountId) {
    return [...this._users.values()].find(
      u => u.loginProvider === provider && u.providerAccountId === providerAccountId
    ) ?? null;
  }

  async updateRequire2FA(userId, required) {
    const u = this._users.get(userId);
    if (u) u.require2FA = required;
  }

  async listUsers(limit, offset) {
    return [...this._users.values()].slice(offset, offset + limit);
  }

  async deleteUser(userId) {
    this._users.delete(userId);
  }
}

// ── App setup ─────────────────────────────────────────────────────────────────

// In-memory settings store — enables the Control tab in the admin panel,
// including the 🎨 UI Customization panel (colors, logo, site name, etc.).
// In production, persist this to your database instead.
let _settings = {
  ui: {
    siteName: 'Demo App',
    primaryColor: '#4a90d9',
    secondaryColor: '#6c757d',
  },
};
const settingsStore = {
  async getSettings() { return { ..._settings }; },
  async updateSettings(updates) { _settings = { ..._settings, ...updates }; },
};

// Upload directory — files uploaded via the admin UI Customization panel
// are stored here and served by the UI router at /auth/ui/assets/uploads/.
// Uses the system temp directory so this works in any environment (including StackBlitz).
const UPLOAD_DIR = path.join(os.tmpdir(), 'awesome-node-auth-demo-uploads');

// Template store — enables the 📧 Email & UI Templates tab in the admin panel.
// Use MemoryTemplateStore for development; swap for a DB-backed implementation in production.
// Wire to both AuthConfigurator (email template overrides) and createAdminRouter (admin editor).
const templateStore = new MemoryTemplateStore();

const app = express();

app.use(express.json());
app.use(cookieParser());

// Allow cross-origin requests from StackBlitz preview / the wiki iframe
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-CSRF-Token');
  if (req.method === 'OPTIONS') { res.sendStatus(204); return; }
  next();
});

// ── awesome-node-auth configuration ───────────────────────────────────────────────────

const userStore = new InMemoryUserStore();

/** @type {import('@awesome-lang-auth/node').AuthConfig} */
/**
 * SECURITY NOTE — These secrets are intentionally hardcoded for the demo only.
 * In production you MUST load them from environment variables and never commit
 * real secrets to source control.
 */
const authConfig = {
  accessTokenSecret:  process.env.ACCESS_TOKEN_SECRET  || 'demo-access-secret-change-in-production',
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET || 'demo-refresh-secret-change-in-production',
  accessTokenExpiresIn:  '15m',
  refreshTokenExpiresIn: '7d',
  cookieOptions: {
    secure:   process.env.NODE_ENV === 'production',   // HTTPS only in production
    sameSite: 'lax',
  },
  // Static UI defaults (overridden at runtime by the admin UI Customization panel)
  ui: {
    siteName: 'Demo App',
    primaryColor: '#4a90d9',
    secondaryColor: '#6c757d',
  },
};

const auth = new AuthConfigurator(
  { ...authConfig, templateStore },  // templateStore enables email template overrides
  userStore,
);

// Mount the auth router  →  POST /auth/register, POST /auth/login, GET /auth/me, …
// Pass onRegister so the POST /auth/register endpoint is enabled.
app.use('/auth', auth.router({
  onRegister: async (data) => {
    // Validate inputs
    const email    = typeof data.email    === 'string' ? data.email.trim()    : '';
    const password = typeof data.password === 'string' ? data.password.trim() : '';
    if (!email || !password) {
      const { AuthError } = require('@awesome-lang-auth/node');
      throw new AuthError('email and password are required', 'VALIDATION_ERROR', 400);
    }
    // Reject duplicate email
    const existing = await userStore.findByEmail(email);
    if (existing) {
      const { AuthError } = require('@awesome-lang-auth/node');
      throw new AuthError('Email already registered', 'EMAIL_EXISTS', 409);
    }
    const hash = await passwordService.hash(password);
    return userStore.create({ email, password: hash, role: 'user' });
  },
}));

// Mount the built-in UI router →  GET /auth/ui/login, GET /auth/ui/register, …
// Provides server-side rendered (SSR) HTML pages with:
//   • CSS variable injection (prevents FOUC)
//   • Loading splash-spinner overlay
//   • Runtime theme from settingsStore (admin UI Customization panel)
//   • Uploaded assets served at /auth/ui/assets/uploads/<filename>
app.use('/auth/ui', buildUiRouter({
  authConfig,
  routerOptions: {
    onRegister: async (data) => data,  // same handler as above, required for register page
  },
  settingsStore,          // runtime theme customization (colors, logo, etc.)
  templateStore,          // enables i18n injection into built-in UI pages
  uploadDir: UPLOAD_DIR,  // serve uploaded logo / background images
  apiPrefix: '/auth',
}));

// Mount the admin router →  GET /admin  (HTML UI + REST API)
//   Admin password: 1234
app.use('/admin', createAdminRouter(userStore, {
  jwtSecret: process.env.ACCESS_TOKEN_SECRET || 'dev-secret',
  accessPolicy: 'first-user',
  settingsStore,          // enables ⚙️ Control tab + 🎨 UI Customization panel
  templateStore,          // enables 📧 Email & UI Templates tab (live editor + preview)
  uploadDir: UPLOAD_DIR,  // enables file upload for logo and background image
  // Must match where buildUiRouter is mounted + '/assets/uploads':
  uploadBaseUrl: '/auth/ui/assets/uploads',
}));

// ── Static frontend ───────────────────────────────────────────────────────────
// express.static automatically serves public/index.html for GET /

app.use(express.static(path.join(__dirname, 'public')));

// ── Start ─────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  🔐  awesome-node-auth demo server\n`);
  console.log(`  http://localhost:${PORT}              → demo frontend`);
  console.log(`  http://localhost:${PORT}/auth/ui/login → built-in login UI (SSR + themed)`);
  console.log(`  http://localhost:${PORT}/admin         → admin panel (password: 1234)\n`);
});
