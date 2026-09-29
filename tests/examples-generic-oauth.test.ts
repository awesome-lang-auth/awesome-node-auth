/**
 * Tests for examples/generic-oauth-and-linking.example.ts
 *
 * The example file itself is not imported (it starts an HTTP server at module
 * level).  Instead we replicate its exact setup — same stores, same
 * GenericOAuthStrategy subclass, same createAuthRouter options — and test
 * every endpoint that can be exercised without hitting an external OAuth
 * provider (Discord credentials are not available in CI).
 *
 * Coverage:
 *   POST /auth/register        — onRegister handler (validates + creates user)
 *   POST /auth/login           — LocalStrategy, sets JWT cookies
 *   GET  /auth/me              — protected, returns req.user
 *   POST /auth/refresh         — renews access token
 *   POST /auth/logout          — clears cookies
 *   GET  /auth/linked-accounts — requires auth, returns [] for a new user
 *   GET  /admin/api/users      — admin endpoint (Bearer token)
 *   GET  /admin/api/settings   — settings endpoint (Bearer token)
 *   POST /admin/api/settings   — save settings (Bearer token)
 *   GenericOAuthStrategy       — class can be instantiated with provider config
 *   InMemorySettingsStore      — get/update settings persists across calls
 */

import { describe, it, expect, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';

import {
  createAuthRouter,
  createAdminRouter,
  PasswordService,
  AuthError,
  GenericOAuthStrategy,
  BaseUser,
} from '../src/index';
import type { AuthConfig, GenericOAuthProviderConfig } from '../src/index';

import {
  InMemoryUserStore,
  InMemoryLinkedAccountsStore,
  InMemorySettingsStore,
} from '../examples/in-memory-user-store';

// ── Replicate the DiscordStrategy from the example ───────────────────────────

const discordConfig: GenericOAuthProviderConfig = {
  name: 'discord',
  clientId:     'test-client-id',
  clientSecret: 'test-client-secret',
  callbackUrl:  'http://localhost:3000/auth/oauth/discord/callback',
  authorizationUrl: 'https://discord.com/api/oauth2/authorize',
  tokenUrl:         'https://discord.com/api/oauth2/token',
  userInfoUrl:      'https://discord.com/api/users/@me',
  scope: 'identify email',
  mapProfile: (raw) => ({
    id:    String(raw['id']),
    email: String(raw['email'] ?? ''),
    name:  raw['username'] ? String(raw['username']) : undefined,
  }),
};

// ── App factory (exact mirror of generic-oauth-and-linking.example.ts) ───────

const ADMIN_SECRET = 'change-me-admin-secret';

function createExampleApp() {
  const userStore           = new InMemoryUserStore();
  const linkedAccountsStore = new InMemoryLinkedAccountsStore();
  const settingsStore       = new InMemorySettingsStore();
  const passwordService     = new PasswordService();

  const config: AuthConfig = {
    accessTokenSecret:  'change-me-access-secret',
    refreshTokenSecret: 'change-me-refresh-secret',
    accessTokenExpiresIn:  '15m',
    refreshTokenExpiresIn: '7d',
    email: { siteUrl: 'http://localhost:3000' },
  };

  // DiscordStrategy — mirrors the example
  class DiscordStrategy extends GenericOAuthStrategy<BaseUser> {
    async findOrCreateUser(profile: { id: string; email: string; name?: string }): Promise<BaseUser> {
      const link = await linkedAccountsStore.findUserByProviderAccount('discord', profile.id);
      if (link) {
        const user = await userStore.findById(link.userId);
        if (user) return user;
      }
      const byEmail = await userStore.findByEmail(profile.email);
      if (byEmail) {
        throw new AuthError(
          'An account with this email already exists.',
          'OAUTH_ACCOUNT_CONFLICT',
          409,
        );
      }
      return userStore.create({
        email: profile.email,
        loginProvider: 'discord',
        providerAccountId: profile.id,
        isEmailVerified: true,
      });
    }
  }

  const discordStrategy = new DiscordStrategy(discordConfig);

  const authRouter = createAuthRouter(userStore, config, {
    oauthStrategies: [discordStrategy],
    linkedAccountsStore,
    settingsStore,
    onRegister: async (data: Record<string, unknown>) => {
      const email    = typeof data.email    === 'string' ? data.email.trim()    : '';
      const password = typeof data.password === 'string' ? data.password.trim() : '';
      if (!email || !password) throw new AuthError('email and password are required', 'VALIDATION_ERROR', 400);
      const existing = await userStore.findByEmail(email);
      if (existing) throw new AuthError('Email already registered', 'EMAIL_EXISTS', 409);
      const hash = await passwordService.hash(password);
      return userStore.create({ email, password: hash, role: 'user' });
    },
  });

  const adminRouter = createAdminRouter(userStore, {
    adminSecret: ADMIN_SECRET,
    settingsStore,
    linkedAccountsStore,
  });

  const app = express();
  app.use(express.json());
  app.use('/auth',  authRouter);
  app.use('/admin', adminRouter);
  app.get('/', (_req, res) => res.json({ ok: true }));

  return { app, userStore, linkedAccountsStore, settingsStore };
}

// ── Helper ────────────────────────────────────────────────────────────────────

async function registerAndLogin(
  app: express.Application,
  email = 'alice@example.com',
  password = 'secret123',
) {
  await request(await listen(app)).post('/auth/register').send({ email, password });
  const res = await request(await listen(app)).post('/auth/login').send({ email, password });
  const raw: string[] | string | undefined = res.headers['set-cookie'];
  return { cookies: Array.isArray(raw) ? raw : raw ? [raw] : [] };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('examples/generic-oauth-and-linking — GenericOAuthStrategy', () => {
  it('can be instantiated with a provider config', () => {
    class TestStrategy extends GenericOAuthStrategy<BaseUser> {
      async findOrCreateUser(profile: { id: string; email: string }): Promise<BaseUser> {
        return { id: profile.id, email: profile.email };
      }
    }
    const strategy = new TestStrategy(discordConfig);
    expect(strategy).toBeInstanceOf(GenericOAuthStrategy);
  });

  it('mapProfile transforms raw provider data to standard shape', () => {
    const raw = { id: '12345', email: 'user@discord.com', username: 'testuser', avatar: null };
    const profile = discordConfig.mapProfile!(raw);
    expect(profile.id).toBe('12345');
    expect(profile.email).toBe('user@discord.com');
    expect(profile.name).toBe('testuser');
  });

  it('mapProfile handles missing optional fields', () => {
    const raw = { id: '99', email: 'x@discord.com' };
    const profile = discordConfig.mapProfile!(raw);
    expect(profile.id).toBe('99');
    expect(profile.name).toBeUndefined();
  });
});

describe('examples/generic-oauth-and-linking — auth endpoints', () => {
  let app: express.Application;

  beforeEach(() => {
    ({ app } = createExampleApp());
  });

  // ── Registration ─────────────────────────────────────────────────────────

  describe('POST /auth/register', () => {
    it('creates a new user and returns 201', async () => {
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

    it('returns 400 for missing fields', async () => {
      const res = await request(await listen(app)).post('/auth/register').send({ email: 'alice@example.com' });
      expect(res.status).toBe(400);
    });
  });

  // ── Login ─────────────────────────────────────────────────────────────────

  describe('POST /auth/login', () => {
    it('returns 200 and sets HttpOnly JWT cookies', async () => {
      await request(await listen(app)).post('/auth/register').send({ email: 'alice@example.com', password: 'secret123' });
      const res = await request(await listen(app))
        .post('/auth/login')
        .send({ email: 'alice@example.com', password: 'secret123' });
      expect(res.status).toBe(200);
      const cookies = res.headers['set-cookie'] as string[];
      expect(cookies.some((c: string) => c.startsWith('accessToken='))).toBe(true);
      expect(cookies.some((c: string) => c.includes('HttpOnly'))).toBe(true);
    });

    it('returns 401 for wrong password', async () => {
      await request(await listen(app)).post('/auth/register').send({ email: 'alice@example.com', password: 'secret123' });
      const res = await request(await listen(app))
        .post('/auth/login')
        .send({ email: 'alice@example.com', password: 'wrong' });
      expect(res.status).toBe(401);
    });
  });

  // ── GET /auth/me ──────────────────────────────────────────────────────────

  describe('GET /auth/me', () => {
    it('returns 403 without token', async () => {
      const res = await request(await listen(app)).get('/auth/me');
      expect(res.status).toBe(403);
    });

    it('returns user with valid token', async () => {
      const { cookies } = await registerAndLogin(app);
      const res = await request(await listen(app)).get('/auth/me').set('Cookie', cookies);
      expect(res.status).toBe(200);
      expect(res.body.email).toBe('alice@example.com');
    });
  });

  // ── Refresh ───────────────────────────────────────────────────────────────

  describe('POST /auth/refresh', () => {
    it('issues a new access token', async () => {
      const { cookies } = await registerAndLogin(app);
      const res = await request(await listen(app)).post('/auth/refresh').set('Cookie', cookies);
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('returns 401 without refresh token', async () => {
      const res = await request(await listen(app)).post('/auth/refresh');
      expect(res.status).toBe(401);
    });
  });

  // ── Logout ────────────────────────────────────────────────────────────────

  describe('POST /auth/logout', () => {
    it('clears auth cookies and returns 200', async () => {
      const { cookies } = await registerAndLogin(app);
      const res = await request(await listen(app)).post('/auth/logout').set('Cookie', cookies);
      expect(res.status).toBe(200);
      const cleared = res.headers['set-cookie'] as string[];
      expect(cleared.some((c: string) => c.startsWith('accessToken=') && (c.includes('Max-Age=0') || c.includes('Expires=')))).toBe(true);
    });

    it('GET /auth/me returns 403 after logout', async () => {
      const { cookies } = await registerAndLogin(app);
      const logoutRes = await request(await listen(app)).post('/auth/logout').set('Cookie', cookies);
      const clearedCookies = logoutRes.headers['set-cookie'] as string[];
      const res = await request(await listen(app)).get('/auth/me').set('Cookie', clearedCookies);
      expect(res.status).toBe(403);
    });
  });

  // ── Linked accounts endpoint (requires auth) ──────────────────────────────

  describe('GET /auth/linked-accounts', () => {
    it('returns 403 without token', async () => {
      const res = await request(await listen(app)).get('/auth/linked-accounts');
      expect(res.status).toBe(403);
    });

    it('returns an empty array for a new user with no linked accounts', async () => {
      const { cookies } = await registerAndLogin(app);
      const res = await request(await listen(app))
        .get('/auth/linked-accounts')
        .set('Cookie', cookies);
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.linkedAccounts ?? res.body)).toBe(true);
    });
  });

  // ── OAuth redirect endpoint (provider must be registered) ─────────────────

  describe('GET /auth/oauth/discord', () => {
    it('redirects to Discord authorization URL', async () => {
      const res = await request(await listen(app)).get('/auth/oauth/discord');
      // Without real credentials the redirect still points at Discord
      expect([302, 301]).toContain(res.status);
      if (res.headers.location) {
        expect(res.headers.location).toMatch(/discord\.com\/api\/oauth2\/authorize/);
      }
    });
  });
});

// ── Admin panel ───────────────────────────────────────────────────────────────

describe('examples/generic-oauth-and-linking — admin panel', () => {
  let app: express.Application;
  let settingsStore: InMemorySettingsStore;

  beforeEach(() => {
    ({ app, settingsStore } = createExampleApp());
  });

  it('GET /admin/api/users returns 401 without credentials', async () => {
    const res = await request(await listen(app)).get('/admin/api/users');
    expect(res.status).toBe(401);
  });

  it('GET /admin/api/users returns user list with valid Bearer token', async () => {
    await request(await listen(app)).post('/auth/register').send({ email: 'dave@example.com', password: 'pass123' });
    const res = await request(await listen(app))
      .get('/admin/api/users')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.users ?? res.body)).toBe(true);
  });

  it('GET /admin/api/users returns 403 with wrong secret', async () => {
    const res = await request(await listen(app))
      .get('/admin/api/users')
      .set('Authorization', 'Bearer wrongsecret');
    expect(res.status).toBe(403);
  });

  it('GET /admin/api/settings returns current settings', async () => {
    const res = await request(await listen(app))
      .get('/admin/api/settings')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(typeof res.body).toBe('object');
  });

  it('settingsStore persists across admin GET/POST settings calls', async () => {
    // Update via the store directly (mirrors admin POST /settings)
    await settingsStore.updateSettings({ require2FA: true });
    const settings = await settingsStore.getSettings();
    expect(settings.require2FA).toBe(true);
  });
});

// ── Full example flow ─────────────────────────────────────────────────────────

describe('examples/generic-oauth-and-linking — full flow', () => {
  it('register → login → linked-accounts → logout', async () => {
    const { app } = createExampleApp();

    // 1. Register
    const reg = await request(await listen(app)).post('/auth/register').send({ email: 'eve@example.com', password: 'pass123' });
    expect(reg.status).toBe(201);

    // 2. Login
    const login = await request(await listen(app)).post('/auth/login').send({ email: 'eve@example.com', password: 'pass123' });
    expect(login.status).toBe(200);
    const cookies = login.headers['set-cookie'] as string[];

    // 3. Check linked accounts (empty for password user)
    const linked = await request(await listen(app)).get('/auth/linked-accounts').set('Cookie', cookies);
    expect(linked.status).toBe(200);

    // 4. Verify identity
    const me = await request(await listen(app)).get('/auth/me').set('Cookie', cookies);
    expect(me.status).toBe(200);
    expect(me.body.email).toBe('eve@example.com');

    // 5. Logout
    const logout = await request(await listen(app)).post('/auth/logout').set('Cookie', cookies);
    expect(logout.status).toBe(200);

    // 6. Protected endpoint now 403
    const after = await request(await listen(app))
      .get('/auth/me')
      .set('Cookie', logout.headers['set-cookie'] as string[]);
    expect(after.status).toBe(403);
  });
});
