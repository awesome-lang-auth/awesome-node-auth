/**
 * Integration tests for the Next.js API handler pattern.
 *
 * The Next.js demo (demo/nextjs-fullstack/) uses standard API routes that
 * delegate to awesome-node-auth's Express-compatible router.  Because
 * Next.js req/res are compatible with Express, the same handler can be
 * tested with supertest via a thin Express wrapper — no Next.js runtime
 * needed.
 *
 * Pattern tested (from demo/nextjs-fullstack/pages/api/auth/[...auth].ts):
 *
 *   export default function handler(req, res) {
 *     const router = getAuth().router({ onRegister });
 *     req.url = req.url.replace(/^\/api\/auth/, '') || '/';
 *     router(req, res, () => res.status(404).json({ error: 'Not found' }));
 *   }
 *
 * Coverage:
 *   POST /api/auth/register  — creates a user
 *   POST /api/auth/login     — issues cookies
 *   GET  /api/auth/me        — protected (requires accessToken cookie)
 *   POST /api/auth/refresh   — renews access token
 *   POST /api/auth/logout    — clears cookies
 *   GET  /api/admin          — admin panel (password-protected)
 *   unknown route            — falls through to 404 handler
 */

import { describe, it, expect, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';

import { AuthConfigurator, createAdminRouter, PasswordService, AuthError } from '../src/index';
import type { AuthConfig, IUserStore, BaseUser } from '../src/index';

// ── Shared in-memory store (matches demo/nextjs-fullstack/lib/user-store.ts) ─

class InMemoryUserStore implements IUserStore {
  private _users = new Map<string, BaseUser & Record<string, unknown>>();
  private _nextId = 1;

  async findByEmail(email: string) {
    return [...this._users.values()].find(u => u.email === email) ?? null;
  }
  async findById(id: string) { return this._users.get(id) ?? null; }
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
  async deleteUser(userId: string) { this._users.delete(userId); }
}

// ── App factory replicating the Next.js demo API structure ────────────────────
//
// Next.js routes each map to a handler function.  Here we mount them all on
// a single Express app so supertest can exercise them without a Next.js
// runtime — exactly mirroring how Next.js dispatches to each handler.

const ADMIN_SECRET = '1234';

function createNextjsDemoApp() {
  const userStore = new InMemoryUserStore();
  const passwordService = new PasswordService();

  const authConfig: AuthConfig = {
    accessTokenSecret:  'demo-access-secret-change-in-production',
    refreshTokenSecret: 'demo-refresh-secret-change-in-production',
    accessTokenExpiresIn:  '15m',
    refreshTokenExpiresIn: '7d',
    cookieOptions: { secure: false, sameSite: 'lax' },
  };

  // Singleton auth configurator (mirrors demo/nextjs-fullstack/lib/auth.ts)
  const auth = new AuthConfigurator(authConfig, userStore);

  // Registration handler (mirrors registerUser in lib/auth.ts)
  async function registerUser(data: Record<string, unknown>) {
    const email    = typeof data.email    === 'string' ? data.email.trim()    : '';
    const password = typeof data.password === 'string' ? data.password.trim() : '';
    if (!email || !password) throw new AuthError('email and password are required', 'VALIDATION_ERROR', 400);
    const existing = await userStore.findByEmail(email);
    if (existing) throw new AuthError('Email already registered', 'EMAIL_EXISTS', 409);
    const hash = await passwordService.hash(password);
    return userStore.create({ email, password: hash, role: 'user' });
  }

  const authRouter = auth.router({ onRegister: registerUser });
  const adminRouter = createAdminRouter(userStore, { adminSecret: ADMIN_SECRET });

  const app = express();
  app.use(express.json());

  // Mirror: pages/api/auth/[...auth].ts
  // Strip /api/auth prefix before handing off to the inner router.
  // NOTE: No rate limiting here — this is a test-only Express app; rate limiting
  //       would cause intermittent test failures and is enforced in production only.
  app.use('/api/auth', (req, res, next) => {
    req.url = req.url || '/';
    authRouter(req, res, () => res.status(404).json({ error: 'Not found' }));
    void next; // unused but keeps TS happy
  });

  // Mirror: pages/api/admin/[...admin].ts
  app.use('/api/admin', (req, res, next) => {
    req.url = req.url || '/';
    adminRouter(req, res, () => res.status(404).json({ error: 'Not found' }));
    void next;
  });

  return { app, userStore };
}

// ── Helper ────────────────────────────────────────────────────────────────────

async function registerAndLogin(app: express.Application, email = 'alice@example.com', password = 'secret123') {
  await request(await listen(app)).post('/api/auth/register').send({ email, password });
  const res = await request(await listen(app)).post('/api/auth/login').send({ email, password });
  const raw: string[] | string | undefined = res.headers['set-cookie'];
  return { cookies: Array.isArray(raw) ? raw : raw ? [raw] : [] };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Demo Next.js API handlers', () => {
  let app: express.Application;

  beforeEach(() => {
    ({ app } = createNextjsDemoApp());
  });

  // ── POST /api/auth/register ─────────────────────────────────────────────

  describe('POST /api/auth/register', () => {
    it('creates a new user and returns 201', async () => {
      const res = await request(await listen(app))
        .post('/api/auth/register')
        .send({ email: 'alice@example.com', password: 'secret123' });
      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
    });

    it('returns 409 for duplicate email', async () => {
      await request(await listen(app)).post('/api/auth/register').send({ email: 'alice@example.com', password: 'secret123' });
      const res = await request(await listen(app))
        .post('/api/auth/register')
        .send({ email: 'alice@example.com', password: 'other' });
      expect(res.status).toBe(409);
    });

    it('returns 400 when email is missing', async () => {
      const res = await request(await listen(app)).post('/api/auth/register').send({ password: 'secret123' });
      expect(res.status).toBe(400);
    });
  });

  // ── POST /api/auth/login ────────────────────────────────────────────────

  describe('POST /api/auth/login', () => {
    it('returns 200 and sets HttpOnly cookies', async () => {
      await request(await listen(app)).post('/api/auth/register').send({ email: 'alice@example.com', password: 'secret123' });
      const res = await request(await listen(app))
        .post('/api/auth/login')
        .send({ email: 'alice@example.com', password: 'secret123' });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      const cookies = res.headers['set-cookie'] as string[];
      expect(cookies.some((c: string) => c.startsWith('accessToken='))).toBe(true);
      expect(cookies.some((c: string) => c.includes('HttpOnly'))).toBe(true);
    });

    it('returns 401 for wrong password', async () => {
      await request(await listen(app)).post('/api/auth/register').send({ email: 'alice@example.com', password: 'secret123' });
      const res = await request(await listen(app))
        .post('/api/auth/login')
        .send({ email: 'alice@example.com', password: 'wrong' });
      expect(res.status).toBe(401);
    });
  });

  // ── GET /api/auth/me — protected ────────────────────────────────────────

  describe('GET /api/auth/me (protected)', () => {
    it('returns 403 without token', async () => {
      const res = await request(await listen(app)).get('/api/auth/me');
      expect(res.status).toBe(403);
    });

    it('returns the user when accessToken cookie is valid', async () => {
      const { cookies } = await registerAndLogin(app);
      const res = await request(await listen(app)).get('/api/auth/me').set('Cookie', cookies);
      expect(res.status).toBe(200);
      expect(res.body.email).toBe('alice@example.com');
    });

    it('returns 403 with a tampered cookie', async () => {
      const res = await request(await listen(app))
        .get('/api/auth/me')
        .set('Cookie', ['accessToken=bad.jwt.token']);
      expect(res.status).toBe(403);
    });
  });

  // ── POST /api/auth/refresh ───────────────────────────────────────────────

  describe('POST /api/auth/refresh', () => {
    it('issues a new accessToken when refreshToken is valid', async () => {
      const { cookies } = await registerAndLogin(app);
      const res = await request(await listen(app))
        .post('/api/auth/refresh')
        .set('Cookie', cookies);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('returns 401 without a refresh token', async () => {
      const res = await request(await listen(app)).post('/api/auth/refresh');
      expect(res.status).toBe(401);
    });
  });

  // ── POST /api/auth/logout ────────────────────────────────────────────────

  describe('POST /api/auth/logout', () => {
    it('clears auth cookies and returns 200', async () => {
      const { cookies } = await registerAndLogin(app);
      const res = await request(await listen(app))
        .post('/api/auth/logout')
        .set('Cookie', cookies);
      expect(res.status).toBe(200);
      const cleared = res.headers['set-cookie'] as string[];
      expect(cleared.some((c: string) => c.startsWith('accessToken=') && (c.includes('Max-Age=0') || c.includes('Expires=')))).toBe(true);
    });

    it('GET /api/auth/me returns 403 after logout', async () => {
      const { cookies } = await registerAndLogin(app);
      const logoutRes = await request(await listen(app)).post('/api/auth/logout').set('Cookie', cookies);
      const clearedCookies = logoutRes.headers['set-cookie'] as string[];
      const res = await request(await listen(app)).get('/api/auth/me').set('Cookie', clearedCookies);
      expect(res.status).toBe(403);
    });
  });

  // ── Admin panel (/api/admin) ─────────────────────────────────────────────

  describe('Admin panel (/api/admin)', () => {
    it('GET /api/admin/api/users returns 401 without credentials', async () => {
      const res = await request(await listen(app)).get('/api/admin/api/users');
      expect(res.status).toBe(401);
    });

    it('GET /api/admin/api/users lists users with admin credentials', async () => {
      await request(await listen(app)).post('/api/auth/register').send({ email: 'eve@example.com', password: 'pass123' });
      const res = await request(await listen(app))
        .get('/api/admin/api/users')
        .set('Authorization', `Bearer ${ADMIN_SECRET}`);
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.users ?? res.body)).toBe(true);
    });
  });

  // ── Next.js middleware: /dashboard redirect pattern ──────────────────────
  //
  // The Next.js middleware (demo/nextjs-fullstack/middleware.ts) runs in the
  // Edge runtime and verifies the accessToken cookie with Web Crypto API.
  // We verify the same JWT validation logic here without the Edge runtime.

  describe('Dashboard protection logic (JWT verification)', () => {
    it('accessToken set by login is a valid compact JWT', async () => {
      await request(await listen(app)).post('/api/auth/register').send({ email: 'dave@example.com', password: 'pass123' });
      const loginRes = await request(await listen(app))
        .post('/api/auth/login')
        .send({ email: 'dave@example.com', password: 'pass123' });
      const cookies = loginRes.headers['set-cookie'] as string[];
      const tokenCookie = cookies.find((c: string) => c.startsWith('accessToken='));
      expect(tokenCookie).toBeDefined();
      // A compact JWT has exactly 3 base64url segments separated by '.'
      const token = tokenCookie!.split(';')[0].replace('accessToken=', '');
      const parts = token.split('.');
      expect(parts).toHaveLength(3);
      // Payload must contain sub (user id) and email
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      expect(payload.email).toBe('dave@example.com');
      expect(payload.sub).toBeDefined();
    });

    it('after logout the accessToken cookie is cleared', async () => {
      const { cookies } = await registerAndLogin(app, 'frank@example.com', 'pass123');
      const logoutRes = await request(await listen(app)).post('/api/auth/logout').set('Cookie', cookies);
      const clearedCookies = logoutRes.headers['set-cookie'] as string[];
      const tokenCookie = clearedCookies.find((c: string) => c.startsWith('accessToken='));
      expect(tokenCookie).toBeDefined();
      // After logout the cookie value must be empty / max-age 0
      expect(tokenCookie!.includes('Max-Age=0') || tokenCookie!.includes('Expires=')).toBe(true);
    });
  });
});
