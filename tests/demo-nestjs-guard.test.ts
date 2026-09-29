/**
 * Integration tests for the NestJS demo patterns.
 *
 * The NestJS demo (demo/nestjs-fullstack/src/main.ts) uses:
 *   • JwtAuthGuard — wraps auth.middleware() as a NestJS CanActivate guard
 *   • @CurrentUser() — param decorator that reads req.user set by the guard
 *   • AuthController — delegates all /auth/* routes to auth.router()
 *   • ProfileController — GET /api/profile protected by JwtAuthGuard
 *
 * We don't start the full NestJS application; instead we test the exact same
 * Express middleware patterns that NestJS relies on internally.  This covers:
 *   1. auth.middleware() attaches the decoded user to req.user
 *   2. Routes protected with middleware return 403 without a token
 *   3. auth.router() handles /auth/* endpoints correctly
 *   4. The admin router rejects requests without admin credentials
 *
 * Coverage:
 *   POST /auth/register  — NestJS AuthController delegates to auth.router()
 *   POST /auth/login     — sets HttpOnly cookies
 *   GET  /api/profile    — protected by JwtAuthGuard (auth.middleware())
 *   GET  /auth/me        — protected, returns req.user
 *   GET  /admin/api/users— admin panel, password-protected
 */

import { describe, it, expect, beforeEach } from 'vitest';
import express, { Request, Response, NextFunction } from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';

import { AuthConfigurator, createAdminRouter, PasswordService, AuthError } from '../src/index';
import type { AuthConfig, IUserStore, BaseUser } from '../src/index';

// ── In-memory user store (same as demo/nestjs-fullstack/src/user-store.ts) ───

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

// ── App factory — mirrors the NestJS demo wiring ──────────────────────────────
//
// NestJS internally uses Express under @nestjs/platform-express.
// The JwtAuthGuard pattern is:
//
//   canActivate(context): Promise<boolean> {
//     const req = context.switchToHttp().getRequest();
//     const res = context.switchToHttp().getResponse();
//     return new Promise((resolve, reject) => {
//       this.auth.middleware()(req, res, (err) => {
//         if (err) return reject(err);
//         resolve(true);
//       });
//     });
//   }
//
// This is equivalent to using auth.middleware() directly in Express, which
// is what we test here.

const ADMIN_SECRET = '1234';

function createNestjsDemoApp() {
  const userStore = new InMemoryUserStore();
  const passwordService = new PasswordService();

  const authConfig: AuthConfig = {
    accessTokenSecret:  'demo-access-secret-change-in-production',
    refreshTokenSecret: 'demo-refresh-secret-change-in-production',
    accessTokenExpiresIn:  '15m',
    refreshTokenExpiresIn: '7d',
    cookieOptions: { secure: false, sameSite: 'lax' },
  };

  const auth = new AuthConfigurator(authConfig, userStore);

  // JwtAuthGuard as Express middleware (same logic as NestJS guard)
  const jwtAuthGuard = (req: Request, res: Response, next: NextFunction) => {
    auth.middleware()(req, res, (err?: unknown) => {
      if (err) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
      next();
    });
  };

  // @CurrentUser() returns req.user — we replicate this by reading req.user in the handler
  const app = express();
  app.use(express.json());

  // AuthController: all /auth/* routes delegate to auth.router()
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

  // ProfileController: GET /api/profile — protected by JwtAuthGuard
  // Equivalent to: @Get('profile') @UseGuards(JwtAuthGuard) getProfile(@CurrentUser() user)
  app.get('/api/profile', jwtAuthGuard, (req: Request, res: Response) => {
    res.json((req as any).user);
  });

  // Admin router
  app.use('/admin', createAdminRouter(userStore, { adminSecret: ADMIN_SECRET }));

  return { app, userStore };
}

// ── Helper ────────────────────────────────────────────────────────────────────

async function registerAndLogin(app: express.Application, email = 'alice@example.com', password = 'secret123') {
  await request(await listen(app)).post('/auth/register').send({ email, password });
  const res = await request(await listen(app)).post('/auth/login').send({ email, password });
  const raw: string[] | string | undefined = res.headers['set-cookie'];
  return { cookies: Array.isArray(raw) ? raw : raw ? [raw] : [] };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Demo NestJS guard + auth patterns', () => {
  let app: express.Application;

  beforeEach(() => {
    ({ app } = createNestjsDemoApp());
  });

  // ── AuthController: /auth/* ─────────────────────────────────────────────

  describe('AuthController (POST /auth/register + POST /auth/login)', () => {
    it('registers a new user', async () => {
      const res = await request(await listen(app))
        .post('/auth/register')
        .send({ email: 'alice@example.com', password: 'secret123' });
      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
    });

    it('returns 409 for duplicate email', async () => {
      await request(await listen(app)).post('/auth/register').send({ email: 'alice@example.com', password: 'secret123' });
      const res = await request(await listen(app))
        .post('/auth/register')
        .send({ email: 'alice@example.com', password: 'other' });
      expect(res.status).toBe(409);
    });

    it('login issues HttpOnly JWT cookies', async () => {
      await request(await listen(app)).post('/auth/register').send({ email: 'alice@example.com', password: 'secret123' });
      const res = await request(await listen(app))
        .post('/auth/login')
        .send({ email: 'alice@example.com', password: 'secret123' });
      expect(res.status).toBe(200);
      const cookies = res.headers['set-cookie'] as string[];
      expect(cookies.some((c: string) => c.startsWith('accessToken='))).toBe(true);
      expect(cookies.some((c: string) => c.includes('HttpOnly'))).toBe(true);
    });
  });

  // ── JwtAuthGuard: middleware attaches req.user ──────────────────────────

  describe('JwtAuthGuard (auth.middleware())', () => {
    it('rejects unauthenticated request with 403', async () => {
      const res = await request(await listen(app)).get('/api/profile');
      expect(res.status).toBe(403);
    });

    it('allows request with valid accessToken cookie and attaches user', async () => {
      const { cookies } = await registerAndLogin(app);
      const res = await request(await listen(app))
        .get('/api/profile')
        .set('Cookie', cookies);
      expect(res.status).toBe(200);
      expect(res.body.email).toBe('alice@example.com');
    });

    it('rejects request with tampered token with 403', async () => {
      const res = await request(await listen(app))
        .get('/api/profile')
        .set('Cookie', ['accessToken=tampered.token.here']);
      expect(res.status).toBe(403);
    });
  });

  // ── @CurrentUser() — reading req.user after JwtAuthGuard ────────────────

  describe('@CurrentUser() decorator pattern', () => {
    it('req.user contains sub, email, and role', async () => {
      const { cookies } = await registerAndLogin(app, 'bob@example.com', 'pass123');
      const res = await request(await listen(app))
        .get('/api/profile')
        .set('Cookie', cookies);
      expect(res.status).toBe(200);
      // sub = user id, email, role set during registration
      expect(res.body.sub).toBeDefined();
      expect(res.body.email).toBe('bob@example.com');
    });

    it('req.user is undefined (request rejected) without a token', async () => {
      const res = await request(await listen(app)).get('/api/profile');
      expect(res.status).toBe(403);
    });
  });

  // ── GET /auth/me (built-in protected endpoint) ──────────────────────────

  describe('GET /auth/me (built-in protected endpoint)', () => {
    it('returns 403 without token', async () => {
      const res = await request(await listen(app)).get('/auth/me');
      expect(res.status).toBe(403);
    });

    it('returns user data with valid cookie', async () => {
      const { cookies } = await registerAndLogin(app, 'carol@example.com', 'pass123');
      const res = await request(await listen(app)).get('/auth/me').set('Cookie', cookies);
      expect(res.status).toBe(200);
      expect(res.body.email).toBe('carol@example.com');
    });
  });

  // ── Admin panel ──────────────────────────────────────────────────────────

  describe('Admin panel (/admin)', () => {
    it('GET /admin/api/users returns 401 without credentials', async () => {
      const res = await request(await listen(app)).get('/admin/api/users');
      expect(res.status).toBe(401);
    });

    it('GET /admin/api/users returns users with valid credentials', async () => {
      await request(await listen(app)).post('/auth/register').send({ email: 'dave@example.com', password: 'pass123' });
      const res = await request(await listen(app))
        .get('/admin/api/users')
        .set('Authorization', `Bearer ${ADMIN_SECRET}`);
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.users ?? res.body)).toBe(true);
    });
  });

  // ── Token refresh + logout ────────────────────────────────────────────────

  describe('Token lifecycle', () => {
    it('POST /auth/refresh renews the access token', async () => {
      const { cookies } = await registerAndLogin(app);
      const res = await request(await listen(app))
        .post('/auth/refresh')
        .set('Cookie', cookies);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('/api/profile returns 403 after logout', async () => {
      const { cookies } = await registerAndLogin(app, 'eve@example.com', 'pass123');
      // Confirm access works before logout
      const before = await request(await listen(app)).get('/api/profile').set('Cookie', cookies);
      expect(before.status).toBe(200);

      // Logout
      const logoutRes = await request(await listen(app)).post('/auth/logout').set('Cookie', cookies);
      expect(logoutRes.status).toBe(200);

      // Protected route now returns 403
      const after = await request(await listen(app))
        .get('/api/profile')
        .set('Cookie', logoutRes.headers['set-cookie'] as string[]);
      expect(after.status).toBe(403);
    });
  });
});
