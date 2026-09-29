import { describe, it, expect, vi, beforeEach } from 'vitest';
import express, { Express } from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';
import { AuthConfigurator } from '../src/auth-configurator';
import { createAdminRouter } from '../src/router/admin.router';
import { createAuthRouter, performSendVerificationEmail } from '../src/router/auth.router';
import { IUserStore } from '../src/interfaces/user-store.interface';
import { AuthConfig } from '../src/models/auth-config.model';
import { AuthError } from '../src/models/errors';
import { BaseUser } from '../src/models/user.model';

class MockUserStore implements IUserStore {
  users: Map<string, BaseUser> = new Map();
  verificationTokens: Map<string, { token: string; expires: Date }> = new Map();

  async findById(id: string): Promise<BaseUser | null> {
    return this.users.get(id) || null;
  }
  async findByEmail(email: string): Promise<BaseUser | null> {
    for (const u of this.users.values()) {
      if (u.email === email) return u;
    }
    return null;
  }
  async create(user: Omit<BaseUser, 'id'>): Promise<BaseUser> {
    const id = `u_${Date.now()}_${Math.random()}`;
    const newUser: BaseUser = { ...user, id };
    this.users.set(id, newUser);
    return newUser;
  }
  async updateEmailVerificationToken(id: string, token: string | null, expires: Date | null): Promise<void> {
    if (token && expires) {
      this.verificationTokens.set(id, { token, expires });
    } else {
      this.verificationTokens.delete(id);
    }
  }
  async updateEmailVerified(id: string, verified: boolean): Promise<void> {
    const user = this.users.get(id);
    if (user) user.isEmailVerified = verified;
  }
  async deleteUser(id: string): Promise<void> {
    this.users.delete(id);
  }
}

describe('Issue #26 Acceptance Criteria Verification', () => {
  let userStore: MockUserStore;
  let authConfig: AuthConfig;

  beforeEach(() => {
    userStore = new MockUserStore();
    authConfig = {
      accessTokenSecret: 'test-secret-at-least-32-chars-long-12345',
      refreshTokenSecret: 'test-refresh-at-least-32-chars-long-12345',
      email: {
        siteUrl: 'https://example.com',
      },
    };
  });

  // ---------------------------------------------------------------------------
  // 1. Admin delete: unknown id -> 404 without calling hook; AuthError status propagated
  // ---------------------------------------------------------------------------
  describe('Admin delete user edge cases (Points 7 & 8)', () => {
    it('returns 404 for unknown user id and DOES NOT invoke onBeforeDeleteUser hook', async () => {
      const hook = vi.fn();
      const adminRouter = createAdminRouter(userStore, {
        accessPolicy: 'open',
        jwtSecret: authConfig.accessTokenSecret,
        onBeforeDeleteUser: hook,
      });

      const app = express();
      app.use('/admin', adminRouter);

      const res = await request(await listen(app)).delete('/admin/api/users/non-existent-user-id');

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('User not found');
      expect(hook).not.toHaveBeenCalled();
    });

    it('propagates AuthError statusCode (e.g. 409) when hook throws AuthError', async () => {
      const existingUser = await userStore.create({
        email: 'victim@example.com',
        passwordHash: 'hash',
        role: 'user',
        isEmailVerified: true,
      });

      const hook = vi.fn().mockImplementation(() => {
        throw new AuthError('Cannot delete user with active billing subscription', 409, 'BILLING_ACTIVE');
      });

      const adminRouter = createAdminRouter(userStore, {
        accessPolicy: 'open',
        jwtSecret: authConfig.accessTokenSecret,
        onBeforeDeleteUser: hook,
      });

      const app = express();
      app.use('/admin', adminRouter);

      const res = await request(await listen(app)).delete(`/admin/api/users/${existingUser.id}`);

      expect(res.status).toBe(409);
      expect(res.body.error).toBe('Cannot delete user with active billing subscription');
      expect(res.body.code).toBe('BILLING_ACTIVE');
      expect(hook).toHaveBeenCalledWith(existingUser.id, expect.objectContaining({ source: 'admin' }));
      // User must still exist
      expect(await userStore.findById(existingUser.id)).not.toBeNull();
    });

    it('returns 500 when hook throws a generic Error', async () => {
      const existingUser = await userStore.create({
        email: 'generic-err@example.com',
        passwordHash: 'hash',
        role: 'user',
        isEmailVerified: true,
      });

      const hook = vi.fn().mockImplementation(() => {
        throw new Error('Database connection failed');
      });

      const adminRouter = createAdminRouter(userStore, {
        accessPolicy: 'open',
        jwtSecret: authConfig.accessTokenSecret,
        onBeforeDeleteUser: hook,
      });

      const app = express();
      app.use('/admin', adminRouter);

      const res = await request(await listen(app)).delete(`/admin/api/users/${existingUser.id}`);

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('Internal server error');
      expect(await userStore.findById(existingUser.id)).not.toBeNull();
    });

    it('deletes user and answers 200 on success (including alias /users/:id)', async () => {
      const u1 = await userStore.create({ email: 'u1@example.com', passwordHash: 'hash', role: 'user' });
      const u2 = await userStore.create({ email: 'u2@example.com', passwordHash: 'hash', role: 'user' });

      const adminRouter = createAdminRouter(userStore, {
        accessPolicy: 'open',
        jwtSecret: authConfig.accessTokenSecret,
      });

      const app = express();
      app.use('/admin', adminRouter);

      // DELETE /api/users/:id
      const res1 = await request(await listen(app)).delete(`/admin/api/users/${u1.id}`);
      expect(res1.status).toBe(200);
      expect(res1.body.success).toBe(true);
      expect(await userStore.findById(u1.id)).toBeNull();

      // DELETE /users/:id (alias)
      const res2 = await request(await listen(app)).delete(`/admin/users/${u2.id}`);
      expect(res2.status).toBe(200);
      expect(res2.body.success).toBe(true);
      expect(await userStore.findById(u2.id)).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Verification link prefix defaults from router options (Point 9)
  // ---------------------------------------------------------------------------
  describe('Verification link prefix defaults (Point 9)', () => {
    it('AuthConfigurator.sendVerificationEmail uses configurator router options prefix (/api/auth)', async () => {
      let sentLink = '';
      const config: AuthConfig = {
        ...authConfig,
        email: {
          siteUrl: 'https://example.com',
          sendVerificationEmail: async (_email, _token, link) => {
            sentLink = link;
          },
        },
      };

      const configurator = new AuthConfigurator(config, userStore);
      // Mount router with apiPrefix: '/api/auth'
      configurator.router({ apiPrefix: '/api/auth' });

      const user = await userStore.create({
        email: 'test-prefix@example.com',
        passwordHash: 'hash',
        role: 'user',
        isEmailVerified: false,
      });

      const result = await configurator.sendVerificationEmail(user.id);
      expect(result.sent).toBe(true);
      expect(sentLink).toContain('https://example.com/api/auth/verify-email?token=');
      expect(sentLink).not.toContain('https://example.com/auth/verify-email');
    });

    it('createAdminRouter uses apiPrefix option for verification link if routerOptions not explicitly passed', async () => {
      let sentLink = '';
      const config: AuthConfig = {
        ...authConfig,
        email: {
          siteUrl: 'https://example.com',
          sendVerificationEmail: async (_email, _token, link) => {
            sentLink = link;
          },
        },
      };

      const adminRouter = createAdminRouter(userStore, {
        accessPolicy: 'open',
        jwtSecret: config.accessTokenSecret,
        authConfig: config,
        apiPrefix: '/api/auth', // Standalone admin router with apiPrefix
      });

      const app = express();
      app.use('/admin', adminRouter);

      const user = await userStore.create({
        email: 'admin-prefix@example.com',
        passwordHash: 'hash',
        role: 'user',
        isEmailVerified: false,
      });

      const res = await request(await listen(app)).post(`/admin/api/users/${user.id}/send-verification-email`);
      expect(res.status).toBe(200);
      expect(sentLink).toContain('https://example.com/api/auth/verify-email?token=');
    });
  });

  // ---------------------------------------------------------------------------
  // 3. sendVerificationEmail reason codes and unconfigured mailer (Points 10 & 11)
  // ---------------------------------------------------------------------------
  describe('sendVerificationEmail reason codes (Points 10 & 11)', () => {
    it('returns { sent: false, reason: "no_mailer" } when no mailer or sendVerificationEmail is configured', async () => {
      const configWithoutMailer: AuthConfig = {
        ...authConfig,
        email: {
          siteUrl: 'https://example.com',
          // Neither sendVerificationEmail nor mailer configured
        },
      };

      const user = await userStore.create({
        email: 'nomailer@example.com',
        passwordHash: 'hash',
        role: 'user',
        isEmailVerified: false,
      });

      const result = await performSendVerificationEmail(userStore, configWithoutMailer, user.id);

      expect(result.sent).toBe(false);
      expect(result.reason).toBe('no_mailer');
      // Token must NOT have been generated or stored
      expect(userStore.verificationTokens.has(user.id)).toBe(false);
    });

    it('returns 501 on admin send-verification-email when no mailer is configured', async () => {
      const configWithoutMailer: AuthConfig = {
        ...authConfig,
        email: {
          siteUrl: 'https://example.com',
        },
      };

      const adminRouter = createAdminRouter(userStore, {
        accessPolicy: 'open',
        jwtSecret: configWithoutMailer.accessTokenSecret,
        authConfig: configWithoutMailer,
      });

      const app = express();
      app.use('/admin', adminRouter);

      const user = await userStore.create({
        email: 'nomailer-admin@example.com',
        passwordHash: 'hash',
        role: 'user',
        isEmailVerified: false,
      });

      const res = await request(await listen(app)).post(`/admin/api/users/${user.id}/send-verification-email`);
      expect(res.status).toBe(501);
      expect(res.body.error).toBe('Email verification mailer is not configured');
    });

    it('returns { sent: false, reason: "unsupported_store" } instead of throwing when store lacks verification methods', async () => {
      const unsupportedStore: IUserStore = {
        findById: async () => null,
        findByEmail: async () => null,
        create: async () => ({ id: '1', email: 'a@b.c' } as BaseUser),
        // updateEmailVerificationToken and updateEmailVerified missing!
      };

      const result = await performSendVerificationEmail(unsupportedStore, authConfig, 'any-id');

      expect(result.sent).toBe(false);
      expect(result.reason).toBe('unsupported_store');
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Admin send-verification-email accepts user ID or email (Point 12)
  // ---------------------------------------------------------------------------
  describe('Admin send-verification-email accepts user ID or email (Point 12)', () => {
    it('accepts URL-encoded email in :id path parameter', async () => {
      let sentTo = '';
      const config: AuthConfig = {
        ...authConfig,
        email: {
          siteUrl: 'https://example.com',
          sendVerificationEmail: async (email) => {
            sentTo = email;
          },
        },
      };

      const adminRouter = createAdminRouter(userStore, {
        accessPolicy: 'open',
        jwtSecret: config.accessTokenSecret,
        authConfig: config,
      });

      const app = express();
      app.use('/admin', adminRouter);

      await userStore.create({
        email: 'alice@example.com',
        passwordHash: 'hash',
        role: 'user',
        isEmailVerified: false,
      });

      const res = await request(await listen(app)).post('/admin/api/users/alice%40example.com/send-verification-email');

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(sentTo).toBe('alice@example.com');
    });
  });
});
