/**
 * Tests for examples/in-memory-user-store.ts
 *
 * Verifies that the three in-memory stores shipped as a copy-paste reference
 * in the examples/ folder satisfy their respective interfaces and work
 * correctly with the auth router.
 *
 * Coverage:
 *
 * InMemoryUserStore:
 *   - create / findByEmail / findById
 *   - updateRefreshToken / updateLastLogin / updatePassword / updateResetToken
 *   - updateTotpSecret / updateMagicLinkToken / updateSmsCode
 *   - updateEmailVerificationToken / updateEmailVerified / findByEmailVerificationToken
 *   - updateEmailChangeToken / updateEmail / findByEmailChangeToken
 *   - updateAccountLinkToken / findByAccountLinkToken
 *   - findByProviderAccount / updateRequire2FA
 *   - listUsers / deleteUser
 *   - Integration: full register → login → GET /auth/me → logout flow
 *
 * InMemoryLinkedAccountsStore:
 *   - linkAccount / getLinkedAccounts / unlinkAccount / findUserByProviderAccount
 *
 * InMemorySettingsStore:
 *   - getSettings / updateSettings
 */

import { describe, it, expect, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';

import { AuthConfigurator, createAdminRouter, PasswordService, AuthError } from '../src/index';
import type { AuthConfig } from '../src/index';

// Import the example stores directly — they use '../src/index' (local source)
import {
  InMemoryUserStore,
  InMemoryLinkedAccountsStore,
  InMemorySettingsStore,
} from '../examples/in-memory-user-store';

// ── Unit tests: InMemoryUserStore ─────────────────────────────────────────────

describe('examples/in-memory-user-store — InMemoryUserStore', () => {
  let store: InMemoryUserStore;

  beforeEach(() => {
    store = new InMemoryUserStore();
  });

  // ── CRUD ─────────────────────────────────────────────────────────────────

  it('create assigns an id and stores the user', async () => {
    const user = await store.create({ email: 'alice@example.com', password: 'hash' });
    expect(user.id).toBeDefined();
    expect(user.email).toBe('alice@example.com');
  });

  it('findByEmail returns the user', async () => {
    await store.create({ email: 'alice@example.com' });
    const found = await store.findByEmail('alice@example.com');
    expect(found).not.toBeNull();
    expect(found!.email).toBe('alice@example.com');
  });

  it('findByEmail returns null for unknown email', async () => {
    const found = await store.findByEmail('nobody@example.com');
    expect(found).toBeNull();
  });

  it('findById returns the user', async () => {
    const created = await store.create({ email: 'bob@example.com' });
    const found = await store.findById(created.id);
    expect(found).not.toBeNull();
    expect(found!.id).toBe(created.id);
  });

  it('findById returns null for unknown id', async () => {
    const found = await store.findById('nonexistent');
    expect(found).toBeNull();
  });

  it('increments ids across multiple creates', async () => {
    const u1 = await store.create({ email: 'a@example.com' });
    const u2 = await store.create({ email: 'b@example.com' });
    expect(u1.id).not.toBe(u2.id);
  });

  // ── Token updates ─────────────────────────────────────────────────────────

  it('updateRefreshToken sets refreshToken and expiry', async () => {
    const user = await store.create({ email: 'a@example.com' });
    const expiry = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7);
    await store.updateRefreshToken(user.id, 'some-refresh-token', expiry);
    const updated = await store.findById(user.id);
    expect(updated!.refreshToken).toBe('some-refresh-token');
    expect(updated!.refreshTokenExpiry).toEqual(expiry);
  });

  it('updateRefreshToken can clear token by setting null', async () => {
    const user = await store.create({ email: 'a@example.com' });
    await store.updateRefreshToken(user.id, 'token', new Date());
    await store.updateRefreshToken(user.id, null, null);
    const updated = await store.findById(user.id);
    expect(updated!.refreshToken).toBeNull();
  });

  it('updateLastLogin sets lastLogin', async () => {
    const user = await store.create({ email: 'a@example.com' });
    await store.updateLastLogin(user.id);
    const updated = await store.findById(user.id);
    expect(updated!.lastLogin).toBeInstanceOf(Date);
  });

  it('updatePassword sets the hashed password', async () => {
    const user = await store.create({ email: 'a@example.com', password: 'old-hash' });
    await store.updatePassword(user.id, 'new-hash');
    const updated = await store.findById(user.id);
    expect(updated!.password).toBe('new-hash');
  });

  it('updateResetToken stores token and findByResetToken returns it', async () => {
    const user = await store.create({ email: 'a@example.com' });
    const expiry = new Date(Date.now() + 3600000);
    await store.updateResetToken(user.id, 'reset-token-abc', expiry);
    const found = await store.findByResetToken('reset-token-abc');
    expect(found).not.toBeNull();
    expect(found!.id).toBe(user.id);
  });

  it('findByResetToken returns null for unknown token', async () => {
    const found = await store.findByResetToken('nonexistent');
    expect(found).toBeNull();
  });

  it('updateTotpSecret sets totpSecret and isTotpEnabled', async () => {
    const user = await store.create({ email: 'a@example.com' });
    await store.updateTotpSecret(user.id, 'JBSWY3DPEHPK3PXP');
    const updated = await store.findById(user.id);
    expect(updated!.totpSecret).toBe('JBSWY3DPEHPK3PXP');
    expect(updated!.isTotpEnabled).toBe(true);
  });

  it('updateTotpSecret with null disables TOTP', async () => {
    const user = await store.create({ email: 'a@example.com' });
    await store.updateTotpSecret(user.id, 'secret');
    await store.updateTotpSecret(user.id, null);
    const updated = await store.findById(user.id);
    expect(updated!.totpSecret).toBeNull();
    expect(updated!.isTotpEnabled).toBe(false);
  });

  it('updateMagicLinkToken stores token and findByMagicLinkToken returns it', async () => {
    const user = await store.create({ email: 'a@example.com' });
    const expiry = new Date(Date.now() + 900000);
    await store.updateMagicLinkToken(user.id, 'magic-abc', expiry);
    const found = await store.findByMagicLinkToken('magic-abc');
    expect(found!.id).toBe(user.id);
  });

  it('updateSmsCode stores the SMS code', async () => {
    const user = await store.create({ email: 'a@example.com' });
    const expiry = new Date(Date.now() + 300000);
    await store.updateSmsCode(user.id, '123456', expiry);
    const updated = await store.findById(user.id);
    expect(updated!.smsCode).toBe('123456');
    expect(updated!.smsCodeExpiry).toEqual(expiry);
  });

  // ── Email verification ─────────────────────────────────────────────────────

  it('updateEmailVerificationToken + findByEmailVerificationToken', async () => {
    const user = await store.create({ email: 'a@example.com' });
    const expiry = new Date(Date.now() + 86400000);
    await store.updateEmailVerificationToken(user.id, 'verify-tok', expiry);
    const found = await store.findByEmailVerificationToken('verify-tok');
    expect(found!.id).toBe(user.id);
  });

  it('updateEmailVerified sets isEmailVerified', async () => {
    const user = await store.create({ email: 'a@example.com' });
    await store.updateEmailVerified(user.id, true);
    const updated = await store.findById(user.id);
    expect(updated!.isEmailVerified).toBe(true);
  });

  // ── Email change ──────────────────────────────────────────────────────────

  it('updateEmailChangeToken + findByEmailChangeToken + updateEmail', async () => {
    const user = await store.create({ email: 'old@example.com' });
    const expiry = new Date(Date.now() + 86400000);
    await store.updateEmailChangeToken(user.id, 'new@example.com', 'change-tok', expiry);
    const found = await store.findByEmailChangeToken('change-tok');
    expect(found!.pendingEmail).toBe('new@example.com');
    await store.updateEmail(user.id, 'new@example.com');
    const updated = await store.findById(user.id);
    expect(updated!.email).toBe('new@example.com');
    expect(updated!.emailChangeToken).toBeNull();
  });

  // ── Account linking ───────────────────────────────────────────────────────

  it('updateAccountLinkToken + findByAccountLinkToken', async () => {
    const user = await store.create({ email: 'a@example.com' });
    const expiry = new Date(Date.now() + 86400000);
    await store.updateAccountLinkToken(user.id, 'second@example.com', 'google', 'link-tok', expiry);
    const found = await store.findByAccountLinkToken('link-tok');
    expect(found!.id).toBe(user.id);
    expect(found!.accountLinkPendingEmail).toBe('second@example.com');
    expect(found!.accountLinkPendingProvider).toBe('google');
  });

  it('findByProviderAccount returns user by provider + id', async () => {
    const user = await store.create({ email: 'a@example.com', loginProvider: 'github', providerAccountId: 'gh-42' });
    const found = await store.findByProviderAccount('github', 'gh-42');
    expect(found!.id).toBe(user.id);
  });

  it('findByProviderAccount returns null for unknown provider account', async () => {
    const found = await store.findByProviderAccount('google', 'nonexistent');
    expect(found).toBeNull();
  });

  // ── 2FA policy ────────────────────────────────────────────────────────────

  it('updateRequire2FA sets require2FA flag', async () => {
    const user = await store.create({ email: 'a@example.com' });
    await store.updateRequire2FA(user.id, true);
    const updated = await store.findById(user.id);
    expect(updated!.require2FA).toBe(true);
  });

  // ── Admin ops ─────────────────────────────────────────────────────────────

  it('listUsers returns a paginated slice', async () => {
    for (let i = 0; i < 5; i++) {
      await store.create({ email: `user${i}@example.com` });
    }
    const page1 = await store.listUsers(3, 0);
    expect(page1).toHaveLength(3);
    const page2 = await store.listUsers(3, 3);
    expect(page2).toHaveLength(2);
  });

  it('deleteUser removes the user', async () => {
    const user = await store.create({ email: 'a@example.com' });
    await store.deleteUser(user.id);
    const found = await store.findById(user.id);
    expect(found).toBeNull();
  });
});

// ── Unit tests: InMemoryLinkedAccountsStore ───────────────────────────────────

describe('examples/in-memory-user-store — InMemoryLinkedAccountsStore', () => {
  let store: InMemoryLinkedAccountsStore;

  beforeEach(() => {
    store = new InMemoryLinkedAccountsStore();
  });

  it('getLinkedAccounts returns empty array for new user', async () => {
    const accounts = await store.getLinkedAccounts('user-1');
    expect(accounts).toEqual([]);
  });

  it('linkAccount adds a linked account', async () => {
    await store.linkAccount('user-1', { provider: 'google', providerAccountId: 'g-123', email: 'a@example.com' });
    const accounts = await store.getLinkedAccounts('user-1');
    expect(accounts).toHaveLength(1);
    expect(accounts[0].provider).toBe('google');
    expect(accounts[0].providerAccountId).toBe('g-123');
  });

  it('linkAccount is idempotent for same provider + providerAccountId', async () => {
    const account = { provider: 'google', providerAccountId: 'g-123', email: 'a@example.com' };
    await store.linkAccount('user-1', account);
    await store.linkAccount('user-1', { ...account, email: 'updated@example.com' });
    const accounts = await store.getLinkedAccounts('user-1');
    expect(accounts).toHaveLength(1);
    expect(accounts[0].email).toBe('updated@example.com');
  });

  it('linkAccount supports multiple providers per user', async () => {
    await store.linkAccount('user-1', { provider: 'google', providerAccountId: 'g-1', email: 'a@g.com' });
    await store.linkAccount('user-1', { provider: 'github', providerAccountId: 'gh-1', email: 'a@gh.com' });
    const accounts = await store.getLinkedAccounts('user-1');
    expect(accounts).toHaveLength(2);
  });

  it('unlinkAccount removes the specified account', async () => {
    await store.linkAccount('user-1', { provider: 'google', providerAccountId: 'g-1', email: 'a@g.com' });
    await store.linkAccount('user-1', { provider: 'github', providerAccountId: 'gh-1', email: 'a@gh.com' });
    await store.unlinkAccount('user-1', 'google', 'g-1');
    const accounts = await store.getLinkedAccounts('user-1');
    expect(accounts).toHaveLength(1);
    expect(accounts[0].provider).toBe('github');
  });

  it('findUserByProviderAccount returns the userId', async () => {
    await store.linkAccount('user-42', { provider: 'discord', providerAccountId: 'd-99', email: 'x@d.com' });
    const result = await store.findUserByProviderAccount('discord', 'd-99');
    expect(result).not.toBeNull();
    expect(result!.userId).toBe('user-42');
  });

  it('findUserByProviderAccount returns null for unknown provider account', async () => {
    const result = await store.findUserByProviderAccount('github', 'nonexistent');
    expect(result).toBeNull();
  });
});

// ── Unit tests: InMemorySettingsStore ─────────────────────────────────────────

describe('examples/in-memory-user-store — InMemorySettingsStore', () => {
  let store: InMemorySettingsStore;

  beforeEach(() => {
    store = new InMemorySettingsStore();
  });

  it('getSettings returns empty object by default', async () => {
    const settings = await store.getSettings();
    expect(settings).toEqual({});
  });

  it('updateSettings merges into the current settings', async () => {
    await store.updateSettings({ emailVerificationMode: 'strict' });
    const settings = await store.getSettings();
    expect(settings.emailVerificationMode).toBe('strict');
  });

  it('updateSettings is additive (does not replace existing keys)', async () => {
    await store.updateSettings({ emailVerificationMode: 'strict' });
    await store.updateSettings({ require2FA: true });
    const settings = await store.getSettings();
    expect(settings.emailVerificationMode).toBe('strict');
    expect(settings.require2FA).toBe(true);
  });

  it('getSettings returns a copy (mutations do not affect stored state)', async () => {
    await store.updateSettings({ emailVerificationMode: 'lazy' });
    const s = await store.getSettings();
    (s as any).emailVerificationMode = 'strict';
    const s2 = await store.getSettings();
    expect(s2.emailVerificationMode).toBe('lazy');
  });
});

// ── Integration: InMemoryUserStore works with the auth router ────────────────

describe('examples/in-memory-user-store — Integration with AuthConfigurator', () => {
  let app: express.Application;
  const ADMIN_SECRET = 'test-admin-secret';

  beforeEach(() => {
    const userStore = new InMemoryUserStore();
    const passwordService = new PasswordService();
    const authConfig: AuthConfig = {
      accessTokenSecret:  'test-access-secret-very-long-and-secure',
      refreshTokenSecret: 'test-refresh-secret-very-long-and-secure',
      accessTokenExpiresIn:  '15m',
      refreshTokenExpiresIn: '7d',
      cookieOptions: { secure: false, sameSite: 'lax' },
    };

    const auth = new AuthConfigurator(authConfig, userStore);

    app = express();
    app.use(express.json());
    app.use('/auth', auth.router({
      onRegister: async (data) => {
        const email    = typeof data.email    === 'string' ? data.email.trim()    : '';
        const password = typeof data.password === 'string' ? data.password.trim() : '';
        if (!email || !password) throw new AuthError('email and password required', 'VALIDATION_ERROR', 400);
        const existing = await userStore.findByEmail(email);
        if (existing) throw new AuthError('Email already registered', 'EMAIL_EXISTS', 409);
        const hash = await passwordService.hash(password);
        return userStore.create({ email, password: hash, role: 'user' });
      },
    }));
    app.use('/admin', createAdminRouter(userStore, { adminSecret: ADMIN_SECRET }));
  });

  it('full flow: register → login → GET /auth/me → logout → GET /auth/me returns 403', async () => {
    // Register
    const reg = await request(await listen(app)).post('/auth/register').send({ email: 'alice@example.com', password: 'secret123' });
    expect(reg.status).toBe(201);

    // Login
    const login = await request(await listen(app)).post('/auth/login').send({ email: 'alice@example.com', password: 'secret123' });
    expect(login.status).toBe(200);
    const cookies = login.headers['set-cookie'] as string[];
    expect(cookies.some((c: string) => c.startsWith('accessToken='))).toBe(true);

    // GET /auth/me (protected) — succeeds
    const me = await request(await listen(app)).get('/auth/me').set('Cookie', cookies);
    expect(me.status).toBe(200);
    expect(me.body.email).toBe('alice@example.com');

    // Logout
    const logout = await request(await listen(app)).post('/auth/logout').set('Cookie', cookies);
    expect(logout.status).toBe(200);

    // GET /auth/me after logout — 403
    const afterLogout = await request(await listen(app))
      .get('/auth/me')
      .set('Cookie', logout.headers['set-cookie'] as string[]);
    expect(afterLogout.status).toBe(403);
  });

  it('admin GET /api/users lists registered users', async () => {
    await request(await listen(app)).post('/auth/register').send({ email: 'bob@example.com', password: 'pass123' });
    const res = await request(await listen(app))
      .get('/admin/api/users')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.users ?? res.body)).toBe(true);
  });

  it('refresh token renews access token', async () => {
    await request(await listen(app)).post('/auth/register').send({ email: 'carol@example.com', password: 'pass123' });
    const login = await request(await listen(app)).post('/auth/login').send({ email: 'carol@example.com', password: 'pass123' });
    const cookies = login.headers['set-cookie'] as string[];
    const refresh = await request(await listen(app)).post('/auth/refresh').set('Cookie', cookies);
    expect(refresh.status).toBe(200);
    expect(refresh.body.success).toBe(true);
  });
});
