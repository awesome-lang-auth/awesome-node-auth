import { describe, it, expect, beforeEach } from 'vitest';
import express, { Express } from 'express';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { AuthConfigurator } from '../src/auth-configurator';
import { createAdminRouter } from '../src/router/admin.router';
import { createAuthRouter } from '../src/router/auth.router';
import { IUserStore } from '../src/interfaces/user-store.interface';
import { AuthConfig } from '../src/models/auth-config.model';
import { AuthError } from '../src/models/errors';
import { BaseUser } from '../src/models/user.model';

const secret = 'test-secret-issue-29-at-least-32-chars-long';

class MockUserStore implements IUserStore {
  users: Map<string, BaseUser> = new Map();
  verificationTokens: Map<string, { token: string; expires: Date }> = new Map();

  add(user: BaseUser): BaseUser {
    this.users.set(user.id, user);
    return user;
  }
  async findById(id: string): Promise<BaseUser | null> {
    return this.users.get(id) || null;
  }
  async findByEmail(email: string): Promise<BaseUser | null> {
    for (const u of this.users.values()) {
      if (u.email === email) return u;
    }
    return null;
  }
  async create(user: Partial<BaseUser>): Promise<BaseUser> {
    const id = `u_${this.users.size + 1}`;
    return this.add({ ...user, id } as BaseUser);
  }
  async updateRefreshToken(): Promise<void> {}
  async updateResetToken(): Promise<void> {}
  async updatePassword(): Promise<void> {}
  async updateTotpSecret(): Promise<void> {}
  async updateMagicLinkToken(): Promise<void> {}
  async updateSmsCode(): Promise<void> {}
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

/** Same store without the email-verification methods. */
function withoutVerification(store: MockUserStore): MockUserStore {
  const s = store as unknown as Record<string, unknown>;
  s['updateEmailVerificationToken'] = undefined;
  s['updateEmailVerified'] = undefined;
  return store;
}

function userToken(user: BaseUser): string {
  return jwt.sign({ sub: user.id, email: user.email, role: 'user' }, secret, { expiresIn: '1h' });
}

describe('Issue #29', () => {
  let userStore: MockUserStore;
  let sentTo: string[];
  let sentLinks: string[];
  let config: AuthConfig;

  beforeEach(() => {
    userStore = new MockUserStore();
    sentTo = [];
    sentLinks = [];
    config = {
      accessTokenSecret: secret,
      refreshTokenSecret: secret,
      email: {
        siteUrl: 'https://example.com',
        sendVerificationEmail: async (email, _token, link) => {
          sentTo.push(email);
          sentLinks.push(link);
        },
      },
    };
  });

  function adminApp(cfg: AuthConfig = config, extra: Record<string, unknown> = {}): Express {
    const app = express();
    app.use('/admin', createAdminRouter(userStore, {
      accessPolicy: 'open',
      jwtSecret: secret,
      authConfig: cfg,
      ...extra,
    }));
    return app;
  }

  // ---------------------------------------------------------------------------
  // 1. Admin :id decoded once
  // ---------------------------------------------------------------------------
  describe('admin send-verification-email decodes :id once', () => {
    it('an id containing "%" (sent as %25) reaches the user with that id', async () => {
      userStore.add({ id: 'a%b', email: 'percent@example.com', isEmailVerified: false } as BaseUser);

      const res = await request(adminApp()).post('/admin/api/users/a%25b/send-verification-email');

      expect(res.status).toBe(200);
      expect(sentTo).toEqual(['percent@example.com']);
    });

    it('an email encoded once (%40) is found; the alias /users/:id behaves the same', async () => {
      userStore.add({ id: 'u1', email: 'alice@example.com', isEmailVerified: false } as BaseUser);

      const res1 = await request(adminApp()).post('/admin/api/users/alice%40example.com/send-verification-email');
      const res2 = await request(adminApp()).post('/admin/users/alice%40example.com/send-verification-email');

      expect(res1.status).toBe(200);
      expect(res2.status).toBe(200);
      expect(sentTo).toEqual(['alice@example.com', 'alice@example.com']);
    });

    it('a double-encoded email (%2540) is not decoded twice: 404, the user is not reached', async () => {
      userStore.add({ id: 'u1', email: 'a@b.c', isEmailVerified: false } as BaseUser);

      const res = await request(adminApp()).post('/admin/api/users/a%2540b.c/send-verification-email');

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('User not found');
      expect(sentTo).toEqual([]);
      expect(userStore.verificationTokens.size).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. unsupported_store -> 501 on both routes
  // ---------------------------------------------------------------------------
  describe('unsupported_store answers 501 on both routes', () => {
    it('POST /auth/send-verification-email answers 501', async () => {
      const user = userStore.add({ id: 'u1', email: 'self@example.com', isEmailVerified: false } as BaseUser);
      withoutVerification(userStore);
      const app = express();
      app.use('/auth', createAuthRouter(userStore, config));

      const res = await request(app)
        .post('/auth/send-verification-email')
        .set('Authorization', `Bearer ${userToken(user)}`);

      expect(res.status).toBe(501);
      expect(res.body.error).toBe('UserStore does not implement email verification');
      expect(sentTo).toEqual([]);
    });

    it('POST /admin/api/users/:id/send-verification-email answers 501', async () => {
      userStore.add({ id: 'u1', email: 'admin-target@example.com', isEmailVerified: false } as BaseUser);
      withoutVerification(userStore);

      const res = await request(adminApp()).post('/admin/api/users/u1/send-verification-email');

      expect(res.status).toBe(501);
      expect(res.body.error).toBe('UserStore does not implement email verification');
      expect(sentTo).toEqual([]);
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Link prefix
  // ---------------------------------------------------------------------------
  describe('AuthConfigurator.sendVerificationEmail link prefix', () => {
    it('uses the configurator apiPrefix option before any router has been built', async () => {
      userStore.add({ id: 'u1', email: 'early@example.com', isEmailVerified: false } as BaseUser);
      const auth = new AuthConfigurator(config, userStore, { apiPrefix: '/api/auth' });

      const result = await auth.sendVerificationEmail('u1');

      expect(result).toEqual({ sent: true });
      expect(sentLinks[0]).toMatch(/^https:\/\/example\.com\/api\/auth\/verify-email\?token=/);
    });

    it('uses config.apiPrefix before any router has been built', async () => {
      userStore.add({ id: 'u1', email: 'early2@example.com', isEmailVerified: false } as BaseUser);
      const auth = new AuthConfigurator({ ...config, apiPrefix: '/v1/auth' }, userStore);

      await auth.sendVerificationEmail('u1');

      expect(sentLinks[0]).toMatch(/^https:\/\/example\.com\/v1\/auth\/verify-email\?token=/);
    });

    it('an explicit routerOptions: undefined does not override the default prefix', async () => {
      userStore.add({ id: 'u1', email: 'undef@example.com', isEmailVerified: false } as BaseUser);
      const auth = new AuthConfigurator(config, userStore);
      auth.router({ apiPrefix: '/api/auth' });

      await auth.sendVerificationEmail('u1', { routerOptions: undefined });

      expect(sentLinks[0]).toMatch(/^https:\/\/example\.com\/api\/auth\/verify-email\?token=/);
    });

    it('router options without apiPrefix do not hide the configurator/config prefix', async () => {
      userStore.add({ id: 'u1', email: 'noprefix@example.com', isEmailVerified: false } as BaseUser);
      const auth = new AuthConfigurator(config, userStore, { apiPrefix: '/api/auth' });
      auth.router({});

      await auth.sendVerificationEmail('u1', { routerOptions: {} });

      expect(sentLinks[0]).toMatch(/^https:\/\/example\.com\/api\/auth\/verify-email\?token=/);
    });

    it('after buildAllRouters() the link prefix equals the prefix the auth router is mounted on', async () => {
      const user = userStore.add({ id: 'u1', email: 'built@example.com', isEmailVerified: false } as BaseUser);
      const auth = new AuthConfigurator(config, userStore, { apiPrefix: '/api/auth' });
      const app = express();
      app.use(auth.buildAllRouters({ admin: { accessPolicy: 'open' } }));

      // The auth router is mounted on /api/auth ...
      const viaRoute = await request(app)
        .post('/api/auth/send-verification-email')
        .set('Authorization', `Bearer ${userToken(user)}`);
      expect(viaRoute.status).toBe(200);
      // ... the admin router on /api/auth/admin ...
      const viaAdmin = await request(app).post('/api/auth/admin/api/users/u1/send-verification-email');
      expect(viaAdmin.status).toBe(200);
      // ... and the configurator helper links there as well.
      await auth.sendVerificationEmail('u1');

      expect(sentLinks).toHaveLength(3);
      for (const link of sentLinks) {
        expect(link).toMatch(/^https:\/\/example\.com\/api\/auth\/verify-email\?token=/);
      }
    });
  });

  describe('standalone admin router link prefix', () => {
    it('with only authConfig uses authConfig.apiPrefix', async () => {
      userStore.add({ id: 'u1', email: 'standalone@example.com', isEmailVerified: false } as BaseUser);

      const res = await request(adminApp({ ...config, apiPrefix: '/api/auth' }))
        .post('/admin/api/users/u1/send-verification-email');

      expect(res.status).toBe(200);
      expect(sentLinks[0]).toMatch(/^https:\/\/example\.com\/api\/auth\/verify-email\?token=/);
    });

    it('routerOptions without apiPrefix do not hide the apiPrefix option', async () => {
      userStore.add({ id: 'u1', email: 'standalone2@example.com', isEmailVerified: false } as BaseUser);

      const res = await request(adminApp(config, { apiPrefix: '/api/auth', routerOptions: {} }))
        .post('/admin/api/users/u1/send-verification-email');

      expect(res.status).toBe(200);
      expect(sentLinks[0]).toMatch(/^https:\/\/example\.com\/api\/auth\/verify-email\?token=/);
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Hook errors never map to 401 unless the status is explicit
  // ---------------------------------------------------------------------------
  describe('onBeforeDeleteUser AuthError status', () => {
    function selfApp(hook: () => void): Express {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, config, { onBeforeDeleteUser: hook }));
      return app;
    }

    it('AuthError without status: self route answers 500 with message and code, user kept', async () => {
      const user = userStore.add({ id: 'u1', email: 'self-500@example.com' } as BaseUser);
      const app = selfApp(() => { throw new AuthError('Billing still active', 'BILLING_ACTIVE'); });

      const res = await request(app).delete('/auth/account').set('Authorization', `Bearer ${userToken(user)}`);

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'Billing still active', code: 'BILLING_ACTIVE' });
      expect(await userStore.findById('u1')).not.toBeNull();
    });

    it('AuthError without status: admin route answers 500 with message and code, user kept', async () => {
      userStore.add({ id: 'u1', email: 'admin-500@example.com' } as BaseUser);
      const app = adminApp(config, {
        onBeforeDeleteUser: () => { throw new AuthError('Billing still active'); },
      });

      const res = await request(app).delete('/admin/api/users/u1');

      expect(res.status).toBe(500);
      expect(res.body).toEqual({ error: 'Billing still active', code: 'AUTH_ERROR' });
      expect(await userStore.findById('u1')).not.toBeNull();
    });

    it('AuthError with explicit 409: self route answers 409', async () => {
      const user = userStore.add({ id: 'u1', email: 'self-409@example.com' } as BaseUser);
      const app = selfApp(() => { throw new AuthError('Billing still active', 409, 'BILLING_ACTIVE'); });

      const res = await request(app).delete('/auth/account').set('Authorization', `Bearer ${userToken(user)}`);

      expect(res.status).toBe(409);
      expect(res.body).toEqual({ error: 'Billing still active', code: 'BILLING_ACTIVE' });
      expect(await userStore.findById('u1')).not.toBeNull();
    });

    it('AuthError with explicit 409 (code-first signature): admin route answers 409', async () => {
      userStore.add({ id: 'u1', email: 'admin-409@example.com' } as BaseUser);
      const app = adminApp(config, {
        onBeforeDeleteUser: () => { throw new AuthError('Billing still active', 'BILLING_ACTIVE', 409); },
      });

      const res = await request(app).delete('/admin/api/users/u1');

      expect(res.status).toBe(409);
      expect(res.body).toEqual({ error: 'Billing still active', code: 'BILLING_ACTIVE' });
      expect(await userStore.findById('u1')).not.toBeNull();
    });

    it('AuthError keeps its 401 default outside hooks and records whether the status was explicit', () => {
      expect(new AuthError('x').statusCode).toBe(401);
      expect(new AuthError('x').hasExplicitStatus).toBe(false);
      expect(new AuthError('x', 'CODE').hasExplicitStatus).toBe(false);
      expect(new AuthError('x', 'CODE', 401).hasExplicitStatus).toBe(true);
      expect(new AuthError('x', 409).hasExplicitStatus).toBe(true);
    });
  });
});
