import { describe, it, expect, vi, beforeEach } from 'vitest';
import express, { Request, Response } from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';
import jwt from 'jsonwebtoken';
import { createAuthRouter, performSendVerificationEmail } from '../src/router/auth.router';
import { createAdminRouter } from '../src/router/admin.router';
import { createToolsRouter } from '../src/router/tools.router';
import { AuthConfigurator } from '../src/auth-configurator';
import { AuthConfig } from '../src/models/auth-config.model';
import { InMemoryUserStore } from '../examples/in-memory-user-store';
import { AuthTools } from '../src/tools/auth-tools';
import { AuthEventBus } from '../src/events/auth-event-bus';

const jwtSecret = 'test-jwt-secret-issues-20-21-24-long-enough';

const config: AuthConfig = {
  accessTokenSecret: jwtSecret,
  refreshTokenSecret: jwtSecret,
  email: {
    siteUrl: 'https://example.com',
    sendVerificationEmail: vi.fn().mockResolvedValue(undefined),
    sendPasswordReset: vi.fn().mockResolvedValue(undefined),
  },
  sms: {
    provider: 'twilio',
    accountSid: 'AC123',
    authToken: 'token123',
    fromNumber: '+1234567890',
  },
};

describe('Issues #20, #21, #24 Tests', () => {
  let userStore: InMemoryUserStore;
  let testUser: any;
  let userToken: string;
  let adminUser: any;
  let adminToken: string;

  beforeEach(async () => {
    userStore = new InMemoryUserStore();
    testUser = await userStore.create({
      email: 'user@example.com',
      password: 'hashed-password-123',
      isEmailVerified: false,
    });
    userToken = jwt.sign(
      { sub: testUser.id, email: testUser.email, role: 'user' },
      jwtSecret,
      { expiresIn: '1h' },
    );

    adminUser = await userStore.create({
      email: 'admin@example.com',
      isAdmin: true,
      roles: ['admin'],
    });
    adminToken = jwt.sign(
      { sub: adminUser.id, email: adminUser.email, role: 'admin', roles: ['admin'], isAdmin: true },
      jwtSecret,
      { expiresIn: '1h' },
    );
  });

  // =========================================================================
  // Issue #21: 500 on body-less POST to user auth routes
  // =========================================================================
  describe('Issue #21: Safe fallback on body-less POST/PATCH requests', () => {
    function setupAuthApp(options = {}) {
      const app = express();
      // Notice: NO express.json() middleware!
      // This guarantees req.body is undefined when a body-less request or a request without Content-Type: application/json arrives.
      app.use('/auth', createAuthRouter(userStore, config, {
        defaultRegister: true,
        ...options,
      }));
      return app;
    }

    it('POST /send-verification-email with no body succeeds with 200', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app))
        .post('/auth/send-verification-email')
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true });
    });

    it('PATCH /profile with no body succeeds with 200', async () => {
      userStore.updateProfile = vi.fn().mockResolvedValue(undefined);
      const app = setupAuthApp();
      const res = await request(await listen(app))
        .patch('/auth/profile')
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true });
    });

    it('POST /logout with no body succeeds with 200', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app))
        .post('/auth/logout')
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true });
    });

    it('POST /login with no body returns 400 (not 500)', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app)).post('/auth/login');
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Email and password are required');
    });

    it('POST /register with no body returns 400 (not 500)', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app)).post('/auth/register');
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Email and password are required');
    });

    it('POST /forgot-password with no body returns 400 (not 500)', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app)).post('/auth/forgot-password');
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Email is required');
    });

    it('POST /reset-password with no body returns 400 (not 500)', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app)).post('/auth/reset-password');
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Token and password are required');
    });

    it('POST /add-phone with no body returns 400 (not 500)', async () => {
      userStore.updatePhoneNumber = vi.fn().mockResolvedValue(undefined);
      const app = setupAuthApp();
      const res = await request(await listen(app))
        .post('/auth/add-phone')
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('phoneNumber is required');
    });

    it('POST /change-password with no body returns 400 (not 500)', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app))
        .post('/auth/change-password')
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('New password is required');
    });

    it('POST /change-email/request with no body returns 400 (not 500)', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app))
        .post('/auth/change-email/request')
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('newEmail is required');
    });

    it('POST /change-email/confirm with no body returns 400 (not 500)', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app)).post('/auth/change-email/confirm');
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('token is required');
    });

    it('POST /2fa/verify-setup with no body returns 400 (not 500)', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app))
        .post('/auth/2fa/verify-setup')
        .set('Authorization', `Bearer ${userToken}`);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Token and secret are required');
    });

    it('POST /2fa/verify with no body returns 400 (not 500)', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app)).post('/auth/2fa/verify');
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Temp token and TOTP code are required');
    });

    it('POST /magic-link/send with no body returns 400 (not 500)', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app)).post('/auth/magic-link/send');
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('email is required');
    });

    it('POST /magic-link/verify with no body returns 400 (not 500)', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app)).post('/auth/magic-link/verify');
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('token is required');
    });

    it('POST /sms/send with no body returns 400 (not 500)', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app)).post('/auth/sms/send');
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('userId or email is required');
    });

    it('POST /sms/verify with no body returns 400 (not 500)', async () => {
      const app = setupAuthApp();
      const res = await request(await listen(app)).post('/auth/sms/verify');
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('code is required');
    });

    it('POST /link-request with no body returns 400 (not 500)', async () => {
      const mockLinkedAccountsStore = {
        getLinkedAccounts: vi.fn().mockResolvedValue([]),
        unlinkAccount: vi.fn().mockResolvedValue(undefined),
        linkAccount: vi.fn().mockResolvedValue(undefined),
      };
      const app = setupAuthApp({ linkedAccountsStore: mockLinkedAccountsStore });
      const res = await request(await listen(app)).post('/auth/link-request');
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('email is required');
    });

    it('POST /link-verify with no body returns 400 (not 500)', async () => {
      const mockLinkedAccountsStore = {
        getLinkedAccounts: vi.fn().mockResolvedValue([]),
        unlinkAccount: vi.fn().mockResolvedValue(undefined),
        linkAccount: vi.fn().mockResolvedValue(undefined),
      };
      const app = setupAuthApp({ linkedAccountsStore: mockLinkedAccountsStore });
      const res = await request(await listen(app)).post('/auth/link-verify');
      expect(res.status).toBe(400);
      expect(res.body.error).toBe('token is required');
    });

    it('tools router routes do not crash on body-less requests', async () => {
      const app = express();
      const eventBus = new AuthEventBus();
      const tools = new AuthTools(eventBus, { sse: true });
      app.use('/tools', createToolsRouter(tools, { telemetry: true, notify: true }));

      const trackRes = await request(await listen(app)).post('/tools/track/user.signup');
      expect(trackRes.status).toBe(202);

      const notifyRes = await request(await listen(app)).post('/tools/notify/slack');
      expect(notifyRes.status).toBe(202);
    });

    it('admin routes do not crash on body-less requests', async () => {
      const app = express();
      const mockUserMetadataStore = {
        getMetadata: vi.fn().mockResolvedValue({}),
        updateMetadata: vi.fn().mockResolvedValue(undefined),
        clearMetadata: vi.fn().mockResolvedValue(undefined),
      };
      const mockSettingsStore = {
        getSettings: vi.fn().mockResolvedValue({}),
        updateSettings: vi.fn().mockResolvedValue(undefined),
      };
      const mockWebhookStore = {
        listAll: vi.fn().mockResolvedValue([]),
        update: vi.fn().mockResolvedValue(undefined),
      };

      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        silent: true,
        userMetadataStore: mockUserMetadataStore,
        settingsStore: mockSettingsStore,
        webhookStore: mockWebhookStore as any,
      }));

      const putMetaRes = await request(await listen(app))
        .put(`/admin/api/users/${testUser.id}/metadata`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(putMetaRes.status).toBe(200);

      const putSettingsRes = await request(await listen(app))
        .put('/admin/api/settings')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(putSettingsRes.status).toBe(200);

      const patchUiRes = await request(await listen(app))
        .patch('/admin/api/settings/ui')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(patchUiRes.status).toBe(200);

      const patchWebhookRes = await request(await listen(app))
        .patch('/admin/api/webhooks/wh-123')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(patchWebhookRes.status).toBe(200);
    });
  });

  // =========================================================================
  // Issue #20: Awaited hook before account deletion (self and admin)
  // =========================================================================
  describe('Issue #20: onBeforeDeleteUser hook', () => {
    it('calls onBeforeDeleteUser hook on self deletion (DELETE /auth/account) with source=self', async () => {
      const hookCalls: any[] = [];
      const onBeforeDeleteUser = vi.fn().mockImplementation(async (userId: string, ctx: any) => {
        hookCalls.push({ userId, source: ctx.source });
      });

      const app = express();
      app.use('/auth', createAuthRouter(userStore, config, { onBeforeDeleteUser }));

      const res = await request(await listen(app))
        .delete('/auth/account')
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true });
      expect(onBeforeDeleteUser).toHaveBeenCalledTimes(1);
      expect(hookCalls).toEqual([{ userId: testUser.id, source: 'self' }]);

      // User record should be deleted
      const found = await userStore.findById(testUser.id);
      expect(found).toBeNull();
    });

    it('aborts self deletion if onBeforeDeleteUser throws, returns 500, and preserves user', async () => {
      const onBeforeDeleteUser = vi.fn().mockImplementation(async () => {
        throw new Error('External service cleanup failed');
      });

      const app = express();
      app.use('/auth', createAuthRouter(userStore, config, { onBeforeDeleteUser }));

      const res = await request(await listen(app))
        .delete('/auth/account')
        .set('Authorization', `Bearer ${userToken}`);

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('Internal server error');

      // User record must still exist
      const found = await userStore.findById(testUser.id);
      expect(found).not.toBeNull();
      expect(found?.id).toBe(testUser.id);
    });

    it('calls onBeforeDeleteUser hook on admin deletion (DELETE /admin/api/users/:id) with source=admin', async () => {
      const hookCalls: any[] = [];
      const onBeforeDeleteUser = vi.fn().mockImplementation(async (userId: string, ctx: any) => {
        hookCalls.push({ userId, source: ctx.source });
      });

      const app = express();
      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        silent: true,
        onBeforeDeleteUser,
      }));

      const res = await request(await listen(app))
        .delete(`/admin/api/users/${testUser.id}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true });
      expect(onBeforeDeleteUser).toHaveBeenCalledTimes(1);
      expect(hookCalls).toEqual([{ userId: testUser.id, source: 'admin' }]);

      // User record should be deleted
      const found = await userStore.findById(testUser.id);
      expect(found).toBeNull();
    });

    it('aborts admin deletion if onBeforeDeleteUser throws, returns 500, and preserves user', async () => {
      const onBeforeDeleteUser = vi.fn().mockImplementation(async () => {
        throw new Error('External order anonymization failed');
      });

      const app = express();
      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        silent: true,
        onBeforeDeleteUser,
      }));

      const res = await request(await listen(app))
        .delete(`/admin/api/users/${testUser.id}`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('Internal server error');

      // User record must still exist
      const found = await userStore.findById(testUser.id);
      expect(found).not.toBeNull();
      expect(found?.id).toBe(testUser.id);
    });

    it('propagates onBeforeDeleteUser from AuthConfiguratorOptions to buildAllRouters', async () => {
      const hookCalls: any[] = [];
      const onBeforeDeleteUser = vi.fn().mockImplementation(async (userId: string, ctx: any) => {
        hookCalls.push({ userId, source: ctx.source });
      });

      const configurator = new AuthConfigurator(config, userStore, { onBeforeDeleteUser });
      const compositeApp = express();
      compositeApp.use(configurator.buildAllRouters({
        admin: {
          accessPolicy: 'is-admin-flag',
        },
      }));

      // Test self deletion through composite router
      const selfRes = await request(await listen(compositeApp))
        .delete('/auth/account')
        .set('Authorization', `Bearer ${userToken}`);
      expect(selfRes.status).toBe(200);
      expect(hookCalls).toContainEqual({ userId: testUser.id, source: 'self' });

      // Create another user to test admin deletion
      const user2 = await userStore.create({ email: 'user2@example.com' });
      const adminRes = await request(await listen(compositeApp))
        .delete(`/auth/admin/api/users/${user2.id}`)
        .set('Authorization', `Bearer ${adminToken}`);
      expect(adminRes.status).toBe(200);
      expect(hookCalls).toContainEqual({ userId: user2.id, source: 'admin' });
    });
  });

  // =========================================================================
  // Issue #24: Send verification email for a given user from server code / admin
  // =========================================================================
  describe('Issue #24: sendVerificationEmail server API and admin endpoint', () => {
    it('AuthConfigurator.sendVerificationEmail sends email for unverified user by ID', async () => {
      const sendVerificationEmailMock = vi.fn().mockResolvedValue(undefined);
      const customConfig: AuthConfig = {
        ...config,
        email: {
          ...config.email,
          sendVerificationEmail: sendVerificationEmailMock,
        },
      };

      const configurator = new AuthConfigurator(customConfig, userStore);
      const result = await configurator.sendVerificationEmail(testUser.id, { emailLang: 'it' });

      expect(result).toEqual({ sent: true });
      expect(sendVerificationEmailMock).toHaveBeenCalledTimes(1);
      const [email, token, link, lang] = sendVerificationEmailMock.mock.calls[0];
      expect(email).toBe(testUser.email);
      expect(token).toBeDefined();
      expect(link).toContain(`/verify-email?token=${token}`);
      expect(lang).toBe('it');

      // Check token and 24h expiry stored on user
      const updatedUser = await userStore.findById(testUser.id);
      expect(updatedUser?.emailVerificationToken).toBe(token);
      expect(updatedUser?.emailVerificationTokenExpiry).toBeDefined();
      const expiry = updatedUser!.emailVerificationTokenExpiry!.getTime();
      const now = Date.now();
      expect(expiry - now).toBeGreaterThan(23 * 60 * 60 * 1000);
      expect(expiry - now).toBeLessThanOrEqual(24 * 60 * 60 * 1000 + 1000);
    });

    it('AuthConfigurator.sendVerificationEmail finds user by email address', async () => {
      const configurator = new AuthConfigurator(config, userStore);
      const result = await configurator.sendVerificationEmail('user@example.com');
      expect(result).toEqual({ sent: true });
    });

    it('AuthConfigurator.sendVerificationEmail returns already_verified if user is verified', async () => {
      await userStore.updateEmailVerified(testUser.id, true);
      const configurator = new AuthConfigurator(config, userStore);
      const result = await configurator.sendVerificationEmail(testUser.id);

      expect(result).toEqual({ sent: false, reason: 'already_verified' });
    });

    it('AuthConfigurator.sendVerificationEmail returns not_found if user does not exist', async () => {
      const configurator = new AuthConfigurator(config, userStore);
      const result = await configurator.sendVerificationEmail('non-existent-user-id');

      expect(result).toEqual({ sent: false, reason: 'not_found' });
    });

    it('Admin endpoint POST /admin/api/users/:id/send-verification-email sends email and returns 200', async () => {
      const sendVerificationEmailMock = vi.fn().mockResolvedValue(undefined);
      const customConfig: AuthConfig = {
        ...config,
        email: {
          ...config.email,
          sendVerificationEmail: sendVerificationEmailMock,
        },
      };

      const app = express();
      app.use(express.json());
      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        silent: true,
        authConfig: customConfig,
      }));

      const res = await request(await listen(app))
        .post(`/admin/api/users/${testUser.id}/send-verification-email`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ emailLang: 'fr' });

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ success: true });
      expect(sendVerificationEmailMock).toHaveBeenCalledTimes(1);
      expect(sendVerificationEmailMock.mock.calls[0][3]).toBe('fr');
    });

    it('Admin endpoint returns 400 when user is already verified', async () => {
      await userStore.updateEmailVerified(testUser.id, true);

      const app = express();
      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        silent: true,
        authConfig: config,
      }));

      const res = await request(await listen(app))
        .post(`/admin/api/users/${testUser.id}/send-verification-email`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(400);
      expect(res.body.error).toBe('Email is already verified');
    });

    it('Admin endpoint returns 404 when user is not found', async () => {
      const app = express();
      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        silent: true,
        authConfig: config,
      }));

      const res = await request(await listen(app))
        .post('/admin/api/users/non-existent-id/send-verification-email')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toBe('User not found');
    });

    it('Admin endpoint returns 500 when authConfig is not configured on admin router', async () => {
      const app = express();
      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        silent: true,
        // no authConfig provided
      }));

      const res = await request(await listen(app))
        .post(`/admin/api/users/${testUser.id}/send-verification-email`)
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(500);
      expect(res.body.error).toBe('AuthConfig is required for email verification');
    });
  });
});
