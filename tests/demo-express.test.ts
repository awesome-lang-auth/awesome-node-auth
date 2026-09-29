/**
 * Integration tests for the Express demo server pattern.
 *
 * Mirrors the setup in demo/express-vanilla/server.js — same InMemoryUserStore, same
 * AuthConfig, same route layout — but imports from local source so the
 * tests run inside the main vitest suite without needing a separate npm
 * install.
 *
 * Coverage:
 *   POST  /auth/register  — public, creates a user
 *   POST  /auth/login     — public, issues JWT cookies
 *   GET   /auth/me        — protected (requires valid accessToken cookie)
 *   POST  /auth/refresh   — public, renews the access token
 *   POST  /auth/logout    — public, clears JWT cookies
 *   GET   /admin          — protected (Bearer token: adminSecret)
 *   GET   /admin/api/users— admin REST endpoint
 */

import { describe, it, expect, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';

import { AuthConfigurator, createAdminRouter, PasswordService, AuthError } from '../src/index';
import type { AuthConfig, IUserStore, BaseUser } from '../src/index';

// ── In-memory user store (identical to demo/express-vanilla/server.js) ──────────

class InMemoryUserStore implements IUserStore {
  private _users = new Map<string, BaseUser & Record<string, unknown>>();
  private _nextId = 1;

  async findByEmail(email: string) {
    return [...this._users.values()].find(u => u.email === email) ?? null;
  }
  async findById(id: string) {
    return this._users.get(id) ?? null;
  }
  async create(data: Partial<BaseUser>) {
    const id = String(this._nextId++);
    const user = { id, email: '', ...data } as BaseUser & Record<string, unknown>;
    this._users.set(id, user);
    return user;
  }
  async updateRefreshToken(userId: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u['refreshToken'] = token; u['refreshTokenExpiry'] = expiry; }
  }
  async updateLastLogin(userId: string) {
    const u = this._users.get(userId);
    if (u) u['lastLogin'] = new Date();
  }
  async updateResetToken(userId: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u['resetToken'] = token; u['resetTokenExpiry'] = expiry; }
  }
  async updatePassword(userId: string, hash: string) {
    const u = this._users.get(userId);
    if (u) u.password = hash;
  }
  async updateTotpSecret(userId: string, secret: string | null) {
    const u = this._users.get(userId);
    if (u) { u['totpSecret'] = secret; u['isTotpEnabled'] = secret !== null; }
  }
  async updateMagicLinkToken(userId: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u['magicLinkToken'] = token; u['magicLinkTokenExpiry'] = expiry; }
  }
  async updateSmsCode(userId: string, code: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u['smsCode'] = code; u['smsCodeExpiry'] = expiry; }
  }
  async findByResetToken(token: string) {
    return [...this._users.values()].find(u => u['resetToken'] === token) ?? null;
  }
  async findByMagicLinkToken(token: string) {
    return [...this._users.values()].find(u => u['magicLinkToken'] === token) ?? null;
  }
  async updateEmailVerificationToken(userId: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u['emailVerificationToken'] = token; u['emailVerificationTokenExpiry'] = expiry; }
  }
  async updateEmailVerified(userId: string, isVerified: boolean) {
    const u = this._users.get(userId);
    if (u) u['isEmailVerified'] = isVerified;
  }
  async findByEmailVerificationToken(token: string) {
    return [...this._users.values()].find(u => u['emailVerificationToken'] === token) ?? null;
  }
  async updateEmailChangeToken(userId: string, pendingEmail: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u['pendingEmail'] = pendingEmail; u['emailChangeToken'] = token; u['emailChangeTokenExpiry'] = expiry; }
  }
  async updateEmail(userId: string, newEmail: string) {
    const u = this._users.get(userId);
    if (u) { u.email = newEmail; u['pendingEmail'] = null; u['emailChangeToken'] = null; }
  }
  async findByEmailChangeToken(token: string) {
    return [...this._users.values()].find(u => u['emailChangeToken'] === token) ?? null;
  }
  async updateAccountLinkToken(userId: string, pendingEmail: string, pendingProvider: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) {
      u['accountLinkPendingEmail'] = pendingEmail;
      u['accountLinkPendingProvider'] = pendingProvider;
      u['accountLinkToken'] = token;
      u['accountLinkTokenExpiry'] = expiry;
    }
  }
  async findByAccountLinkToken(token: string) {
    return [...this._users.values()].find(u => u['accountLinkToken'] === token) ?? null;
  }
  async findByProviderAccount(provider: string, providerAccountId: string) {
    return [...this._users.values()].find(
      u => u['loginProvider'] === provider && u['providerAccountId'] === providerAccountId,
    ) ?? null;
  }
  async updateRequire2FA(userId: string, required: boolean) {
    const u = this._users.get(userId);
    if (u) u['require2FA'] = required;
  }
  async listUsers(limit: number, offset: number) {
    return [...this._users.values()].slice(offset, offset + limit);
  }
  async deleteUser(userId: string) {
    this._users.delete(userId);
  }
}

// ── App factory (mirrors demo/express-vanilla/server.js exactly) ────────────────

const DEMO_ADMIN_SECRET = '1234';

function createDemoApp() {
  const app = express();
  const passwordService = new PasswordService();
  const userStore = new InMemoryUserStore();

  const authConfig: AuthConfig = {
    accessTokenSecret:     'demo-access-secret-change-in-production',
    refreshTokenSecret:    'demo-refresh-secret-change-in-production',
    accessTokenExpiresIn:  '15m',
    refreshTokenExpiresIn: '7d',
    cookieOptions: { secure: false, sameSite: 'lax' },
  };

  const auth = new AuthConfigurator(authConfig, userStore);

  app.use(express.json());

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

  app.use('/admin', createAdminRouter(userStore, { adminSecret: DEMO_ADMIN_SECRET }));

  return { app, userStore };
}

// ── Helper: register + login, return auth cookies ────────────────────────────

async function registerAndLogin(app: express.Application, email = 'alice@example.com', password = 'secret123') {
  await request(await listen(app)).post('/auth/register').send({ email, password });
  const res = await request(await listen(app)).post('/auth/login').send({ email, password });
  // supertest returns Set-Cookie as an array of strings
  const cookies: string[] = (res.headers['set-cookie'] as string[] | string | undefined) ?? [];
  return { cookies: Array.isArray(cookies) ? cookies : [cookies] };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Demo Express Server', () => {
  let app: express.Application;

  beforeEach(() => {
    ({ app } = createDemoApp());
  });

  // ── Registration ───────────────────────────────────────────────────────────

  describe('POST /auth/register', () => {
    it('creates a new user and returns 201', async () => {
      const res = await request(await listen(app))
        .post('/auth/register')
        .send({ email: 'alice@example.com', password: 'secret123' });
      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
    });

    it('returns 409 when email is already registered', async () => {
      await request(await listen(app)).post('/auth/register').send({ email: 'alice@example.com', password: 'secret123' });
      const res = await request(await listen(app))
        .post('/auth/register')
        .send({ email: 'alice@example.com', password: 'other123' });
      expect(res.status).toBe(409);
    });

    it('returns 400 when email is missing', async () => {
      const res = await request(await listen(app)).post('/auth/register').send({ password: 'secret123' });
      expect(res.status).toBe(400);
    });

    it('returns 400 when password is missing', async () => {
      const res = await request(await listen(app)).post('/auth/register').send({ email: 'alice@example.com' });
      expect(res.status).toBe(400);
    });
  });

  // ── Login ─────────────────────────────────────────────────────────────────

  describe('POST /auth/login', () => {
    it('logs in and sets HttpOnly JWT cookies', async () => {
      await request(await listen(app)).post('/auth/register').send({ email: 'alice@example.com', password: 'secret123' });
      const res = await request(await listen(app))
        .post('/auth/login')
        .send({ email: 'alice@example.com', password: 'secret123' });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      const cookies = res.headers['set-cookie'] as string[];
      expect(cookies).toBeDefined();
      // accessToken and refreshToken cookies must be set
      expect(cookies.some((c: string) => c.startsWith('accessToken='))).toBe(true);
      expect(cookies.some((c: string) => c.startsWith('refreshToken='))).toBe(true);
      // They must be HttpOnly
      expect(cookies.some((c: string) => c.includes('HttpOnly'))).toBe(true);
    });

    it('returns 401 for wrong password', async () => {
      await request(await listen(app)).post('/auth/register').send({ email: 'alice@example.com', password: 'secret123' });
      const res = await request(await listen(app))
        .post('/auth/login')
        .send({ email: 'alice@example.com', password: 'wrong' });
      expect(res.status).toBe(401);
    });

    it('returns 401 for unknown email', async () => {
      const res = await request(await listen(app))
        .post('/auth/login')
        .send({ email: 'nobody@example.com', password: 'secret123' });
      expect(res.status).toBe(401);
    });
  });

  // ── Protected route: GET /auth/me ─────────────────────────────────────────

  describe('GET /auth/me (protected)', () => {
    it('returns 403 with no token', async () => {
      const res = await request(await listen(app)).get('/auth/me');
      expect(res.status).toBe(403);
    });

    it('returns the authenticated user when token cookie is present', async () => {
      const { cookies } = await registerAndLogin(app);
      const res = await request(await listen(app))
        .get('/auth/me')
        .set('Cookie', cookies);
      expect(res.status).toBe(200);
      expect(res.body.email).toBe('alice@example.com');
    });

    it('returns 403 with a tampered token', async () => {
      const res = await request(await listen(app))
        .get('/auth/me')
        .set('Cookie', ['accessToken=invalid.token.here']);
      expect(res.status).toBe(403);
    });
  });

  // ── Token refresh ─────────────────────────────────────────────────────────

  describe('POST /auth/refresh', () => {
    it('issues a new access token when refreshToken cookie is valid', async () => {
      const { cookies } = await registerAndLogin(app);
      const res = await request(await listen(app))
        .post('/auth/refresh')
        .set('Cookie', cookies);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      const newCookies = res.headers['set-cookie'] as string[];
      expect(newCookies.some((c: string) => c.startsWith('accessToken='))).toBe(true);
    });

    it('returns 401 with no refresh token', async () => {
      const res = await request(await listen(app)).post('/auth/refresh');
      expect(res.status).toBe(401);
    });
  });

  // ── Logout ────────────────────────────────────────────────────────────────

  describe('POST /auth/logout', () => {
    it('clears auth cookies on logout', async () => {
      const { cookies } = await registerAndLogin(app);
      const res = await request(await listen(app))
        .post('/auth/logout')
        .set('Cookie', cookies);
      expect(res.status).toBe(200);
      const cleared = res.headers['set-cookie'] as string[];
      // accessToken cookie should be cleared (Max-Age=0 or Expires in the past)
      expect(cleared.some((c: string) => c.startsWith('accessToken=') && (c.includes('Max-Age=0') || c.includes('Expires=')))).toBe(true);
    });

    it('GET /auth/me returns 403 after logout', async () => {
      const { cookies } = await registerAndLogin(app);
      const logoutRes = await request(await listen(app)).post('/auth/logout').set('Cookie', cookies);
      const loggedOutCookies = logoutRes.headers['set-cookie'] as string[];
      const res = await request(await listen(app))
        .get('/auth/me')
        .set('Cookie', loggedOutCookies);
      expect(res.status).toBe(403);
    });
  });

  // ── Admin panel ───────────────────────────────────────────────────────────

  describe('Admin panel', () => {
    it('GET /admin redirects or returns HTML without auth', async () => {
      const res = await request(await listen(app)).get('/admin');
      expect([401, 302, 200]).toContain(res.status);
    });

    it('GET /admin/api/users returns 401 without admin credentials', async () => {
      const res = await request(await listen(app)).get('/admin/api/users');
      expect(res.status).toBe(401);
    });

    it('GET /admin/api/users lists users with valid admin credentials', async () => {
      await request(await listen(app)).post('/auth/register').send({ email: 'bob@example.com', password: 'pass123' });
      const res = await request(await listen(app))
        .get('/admin/api/users')
        .set('Authorization', `Bearer ${DEMO_ADMIN_SECRET}`);
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.users ?? res.body)).toBe(true);
    });

    it('GET /admin/api/users with wrong admin secret returns 403', async () => {
      const res = await request(await listen(app))
        .get('/admin/api/users')
        .set('Authorization', 'Bearer wrongsecret');
      expect(res.status).toBe(403);
    });
  });

  // ── Full register → login → me → logout flow ─────────────────────────────

  describe('Full auth flow', () => {
    it('register → login → GET /auth/me → logout → GET /auth/me returns 403', async () => {
      // 1. Register
      const regRes = await request(await listen(app))
        .post('/auth/register')
        .send({ email: 'carol@example.com', password: 'pass123' });
      expect(regRes.status).toBe(201);

      // 2. Login
      const loginRes = await request(await listen(app))
        .post('/auth/login')
        .send({ email: 'carol@example.com', password: 'pass123' });
      expect(loginRes.status).toBe(200);
      const cookies = loginRes.headers['set-cookie'] as string[];

      // 3. Access protected route
      const meRes = await request(await listen(app)).get('/auth/me').set('Cookie', cookies);
      expect(meRes.status).toBe(200);
      expect(meRes.body.email).toBe('carol@example.com');

      // 4. Logout
      const logoutRes = await request(await listen(app)).post('/auth/logout').set('Cookie', cookies);
      expect(logoutRes.status).toBe(200);

      // 5. Protected route now returns 403
      const afterLogout = await request(await listen(app))
        .get('/auth/me')
        .set('Cookie', logoutRes.headers['set-cookie'] as string[]);
      expect(afterLogout.status).toBe(403);
    });
  });
});
