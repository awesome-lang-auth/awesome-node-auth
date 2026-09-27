/**
 * Angular SSR production server — Express with:
 *  - awesome-node-auth routes at /auth/* and /admin/*
 *  - Angular SSR engine for all other routes
 *
 * Build first:  npm run build
 * Then run:     npm run serve:ssr
 */

import 'zone.js/node';
import 'dotenv/config';

import { APP_BASE_HREF } from '@angular/common';
// In Angular 19+, CommonEngine is exported from @angular/ssr/node
import { CommonEngine } from '@angular/ssr/node';
import express from 'express';
import cookieParser from 'cookie-parser';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { AuthConfigurator, createAdminRouter, PasswordService, AuthError, type AuthConfig } from '@awesome-lang-auth/node';

// ── Inline in-memory store (same as api-server.js) ────────────────────────────
// In production replace with a real database store.

class InMemoryUserStore {
  private _users = new Map<string, any>();
  private _nextId = 1;

  async findByEmail(email: string) { return [...this._users.values()].find(u => u.email === email) ?? null; }
  async findById(id: string) { return this._users.get(id) ?? null; }
  async create(data: any) {
    const id = String(this._nextId++);
    const user = { id, email: '', ...data };
    this._users.set(id, user);
    return user;
  }
  async updateRefreshToken(userId: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u.refreshToken = token; u.refreshTokenExpiry = expiry; }
  }
  async updateLastLogin(userId: string) { const u = this._users.get(userId); if (u) u.lastLogin = new Date(); }
  async updateResetToken(userId: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId); if (u) { u.resetToken = token; u.resetTokenExpiry = expiry; }
  }
  async updatePassword(userId: string, hash: string) { const u = this._users.get(userId); if (u) u.password = hash; }
  async updateTotpSecret(userId: string, secret: string | null) {
    const u = this._users.get(userId); if (u) { u.totpSecret = secret; u.isTotpEnabled = secret !== null; }
  }
  async updateMagicLinkToken(userId: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId); if (u) { u.magicLinkToken = token; u.magicLinkTokenExpiry = expiry; }
  }
  async updateSmsCode(userId: string, code: string | null, expiry: Date | null) {
    const u = this._users.get(userId); if (u) { u.smsCode = code; u.smsCodeExpiry = expiry; }
  }
  async findByResetToken(token: string) { return [...this._users.values()].find(u => u.resetToken === token) ?? null; }
  async findByMagicLinkToken(token: string) { return [...this._users.values()].find(u => u.magicLinkToken === token) ?? null; }
  async updateEmailVerificationToken(userId: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId); if (u) { u.emailVerificationToken = token; u.emailVerificationTokenExpiry = expiry; }
  }
  async updateEmailVerified(userId: string, v: boolean) { const u = this._users.get(userId); if (u) u.isEmailVerified = v; }
  async findByEmailVerificationToken(token: string) { return [...this._users.values()].find(u => u.emailVerificationToken === token) ?? null; }
  async updateEmailChangeToken(userId: string, pendingEmail: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u.pendingEmail = pendingEmail; u.emailChangeToken = token; u.emailChangeTokenExpiry = expiry; }
  }
  async updateEmail(userId: string, newEmail: string) {
    const u = this._users.get(userId);
    if (u) { u.email = newEmail; u.pendingEmail = null; u.emailChangeToken = null; u.emailChangeTokenExpiry = null; }
  }
  async findByEmailChangeToken(token: string) { return [...this._users.values()].find(u => u.emailChangeToken === token) ?? null; }
  async updateAccountLinkToken(userId: string, pendingEmail: string, pendingProvider: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u.accountLinkPendingEmail = pendingEmail; u.accountLinkPendingProvider = pendingProvider; u.accountLinkToken = token; u.accountLinkTokenExpiry = expiry; }
  }
  async findByAccountLinkToken(token: string) { return [...this._users.values()].find(u => u.accountLinkToken === token) ?? null; }
  async findByProviderAccount(provider: string, providerId: string) {
    return [...this._users.values()].find(u => u.loginProvider === provider && u.providerAccountId === providerId) ?? null;
  }
  async updateRequire2FA(userId: string, required: boolean) { const u = this._users.get(userId); if (u) u.require2FA = required; }
  async listUsers(limit: number, offset: number) { return [...this._users.values()].slice(offset, offset + limit); }
  async deleteUser(userId: string) { this._users.delete(userId); }
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

const userStore = new InMemoryUserStore();
const passwordService = new PasswordService();

const authConfig: AuthConfig = {
  accessTokenSecret:  process.env['ACCESS_TOKEN_SECRET']  ?? 'demo-access-secret-change-in-production',
  refreshTokenSecret: process.env['REFRESH_TOKEN_SECRET'] ?? 'demo-refresh-secret-change-in-production',
  accessTokenExpiresIn:  '15m',
  refreshTokenExpiresIn: '7d',
  cookieOptions: {
    secure:   process.env['NODE_ENV'] === 'production',
    sameSite: 'lax',
  },
};

const authConfigurator = new AuthConfigurator(authConfig, userStore);
const adminRouter      = createAdminRouter(userStore, { jwtSecret: process.env['ACCESS_TOKEN_SECRET'] ?? 'dev-secret', accessPolicy: 'first-user' });

export function app(): express.Express {
  const server  = express();
  const __dir   = dirname(fileURLToPath(import.meta.url));
  const browser = resolve(__dir, '../browser');

  server.use(cookieParser());
  server.use(express.json());

  // ── awesome-node-auth API routes ───────────────────────────────────────────────────

  server.use('/auth', authConfigurator.router({
    onRegister: async (data: any) => {
      const email    = typeof data.email    === 'string' ? data.email.trim()    : '';
      const password = typeof data.password === 'string' ? data.password.trim() : '';
      if (!email || !password) throw new AuthError('email and password are required', 'VALIDATION_ERROR', 400);
      const existing = await userStore.findByEmail(email);
      if (existing) throw new AuthError('Email already registered', 'EMAIL_EXISTS', 409);
      const hash = await passwordService.hash(password);
      return userStore.create({ email, password: hash, role: 'user' });
    },
  }) as any);

  server.use('/admin', adminRouter as any);

  // ── Angular static assets ─────────────────────────────────────────────────

  server.set('view engine', 'html');
  server.set('views', browser);
  server.use(express.static(browser, { maxAge: '1y', index: false }));

  // ── Angular SSR engine ────────────────────────────────────────────────────

  const engine = new CommonEngine();

  server.get('**', (req, res, next) => {
    engine.render({
      bootstrap: () => import('./src/main.server').then(m => m.default),
      documentFilePath: join(browser, 'index.html'),
      url: req.originalUrl,
      publicPath: browser,
      providers: [
        { provide: APP_BASE_HREF, useValue: req.baseUrl },
        { provide: 'REQUEST',  useValue: req },
        { provide: 'RESPONSE', useValue: res },
      ],
    })
      .then(html => res.send(html))
      .catch(next);
  });

  return server;
}

function run() {
  const port = process.env['PORT'] || 4000;
  const server = app();
  server.listen(port, () => {
    console.log(`\n  🔐  awesome-node-auth Angular SSR demo`);
    console.log(`  http://localhost:${port}         → Angular SSR app`);
    console.log(`  http://localhost:${port}/admin   → admin panel\n`);
  });
}

run();
