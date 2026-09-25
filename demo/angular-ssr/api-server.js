/**
 * Express API server — awesome-node-auth backend for the Angular SSR demo.
 *
 * In development (npm start), this runs on port 3000 alongside ng serve (port 4200).
 * Angular's proxy.conf.json routes /auth/* and /admin/* requests to this server.
 *
 * In production (npm run serve:ssr), this logic is embedded directly in server.ts
 * so a single process handles both Angular SSR and the auth API.
 */

'use strict';

try { require('dotenv').config(); } catch { /* dotenv is optional */ }

const express      = require('express');
const cookieParser = require('cookie-parser');
const path         = require('path');

const { AuthConfigurator, createAdminRouter, PasswordService, AuthError, MemoryTemplateStore } = require('@awesome-lang-auth/node');

const passwordService = new PasswordService();

// ── In-memory user store ──────────────────────────────────────────────────────

class InMemoryUserStore {
  constructor() { this._users = new Map(); this._nextId = 1; }

  async findByEmail(email) { return [...this._users.values()].find(u => u.email === email) ?? null; }
  async findById(id) { return this._users.get(id) ?? null; }
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
  async updateLastLogin(userId) { const u = this._users.get(userId); if (u) u.lastLogin = new Date(); }
  async updateResetToken(userId, token, expiry) {
    const u = this._users.get(userId);
    if (u) { u.resetToken = token; u.resetTokenExpiry = expiry; }
  }
  async updatePassword(userId, hash) { const u = this._users.get(userId); if (u) u.password = hash; }
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
  async findByResetToken(token) { return [...this._users.values()].find(u => u.resetToken === token) ?? null; }
  async findByMagicLinkToken(token) { return [...this._users.values()].find(u => u.magicLinkToken === token) ?? null; }
  async updateEmailVerificationToken(userId, token, expiry) {
    const u = this._users.get(userId);
    if (u) { u.emailVerificationToken = token; u.emailVerificationTokenExpiry = expiry; }
  }
  async updateEmailVerified(userId, v) { const u = this._users.get(userId); if (u) u.isEmailVerified = v; }
  async findByEmailVerificationToken(token) { return [...this._users.values()].find(u => u.emailVerificationToken === token) ?? null; }
  async updateEmailChangeToken(userId, pendingEmail, token, expiry) {
    const u = this._users.get(userId);
    if (u) { u.pendingEmail = pendingEmail; u.emailChangeToken = token; u.emailChangeTokenExpiry = expiry; }
  }
  async updateEmail(userId, newEmail) {
    const u = this._users.get(userId);
    if (u) { u.email = newEmail; u.pendingEmail = null; u.emailChangeToken = null; u.emailChangeTokenExpiry = null; }
  }
  async findByEmailChangeToken(token) { return [...this._users.values()].find(u => u.emailChangeToken === token) ?? null; }
  async updateAccountLinkToken(userId, pendingEmail, pendingProvider, token, expiry) {
    const u = this._users.get(userId);
    if (u) {
      u.accountLinkPendingEmail = pendingEmail;
      u.accountLinkPendingProvider = pendingProvider;
      u.accountLinkToken = token;
      u.accountLinkTokenExpiry = expiry;
    }
  }
  async findByAccountLinkToken(token) { return [...this._users.values()].find(u => u.accountLinkToken === token) ?? null; }
  async findByProviderAccount(provider, providerId) {
    return [...this._users.values()].find(u => u.loginProvider === provider && u.providerAccountId === providerId) ?? null;
  }
  async updateRequire2FA(userId, required) { const u = this._users.get(userId); if (u) u.require2FA = required; }
  async listUsers(limit, offset) { return [...this._users.values()].slice(offset, offset + limit); }
  async deleteUser(userId) { this._users.delete(userId); }
}

// ── App ───────────────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(cookieParser());

// CORS — allow Angular dev server origin
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-CSRF-Token');
  if (req.method === 'OPTIONS') { res.sendStatus(204); return; }
  next();
});

const userStore = new InMemoryUserStore();

// Template store — enables the 📧 Email & UI Templates tab in the admin panel.
const templateStore = new MemoryTemplateStore();

const authConfig = {
  accessTokenSecret:  process.env.ACCESS_TOKEN_SECRET  || 'demo-access-secret-change-in-production',
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET || 'demo-refresh-secret-change-in-production',
  accessTokenExpiresIn:  '15m',
  refreshTokenExpiresIn: '7d',
  cookieOptions: {
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  },
};

const auth = new AuthConfigurator(
  { ...authConfig, templateStore },  // templateStore enables email template overrides
  userStore,
);

app.use('/auth', auth.router({
  onRegister: async (data) => {
    const email    = typeof data.email    === 'string' ? data.email.trim()    : '';
    const password = typeof data.password === 'string' ? data.password.trim() : '';
    if (!email || !password) throw new AuthError('email and password are required', 'VALIDATION_ERROR', 400);
    const existing = await userStore.findByEmail(email);
    if (existing) throw new AuthError('Email already registered', 'EMAIL_EXISTS', 409);
    const hash = await passwordService.hash(password);
    return userStore.create({ email, password: hash, role: 'user' });
  },
}));

app.use('/admin', createAdminRouter(userStore, {
  jwtSecret: process.env.ACCESS_TOKEN_SECRET || 'dev-secret',
  accessPolicy: 'first-user',
  templateStore,  // enables 📧 Email & UI Templates tab (live editor + preview)
}));

const PORT = process.env.API_PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  🔐  awesome-node-auth API server (Angular SSR demo)`);
  console.log(`  http://localhost:${PORT}/auth  → auth endpoints`);
  console.log(`  http://localhost:${PORT}/admin → admin panel (auto-granted to first registered user)\n`);
});
