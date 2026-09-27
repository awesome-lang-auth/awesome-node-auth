import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { createAuthRouter } from '../src/router/auth.router';
import { createAdminRouter } from '../src/router/admin.router';
import { IUserStore } from '../src/interfaces/user-store.interface';
import { AuthConfig } from '../src/models/auth-config.model';
import { InMemoryUserStore } from '../examples/in-memory-user-store';

const jwtSecret = 'test-jwt-secret-input-robustness-long-enough';

const config: AuthConfig = {
  accessTokenSecret: jwtSecret,
  refreshTokenSecret: jwtSecret,
};

describe('Issue #16: Input robustness and 4xx instead of 500 crashes', () => {
  let userStore: InMemoryUserStore;
  let adminToken: string;

  beforeEach(async () => {
    userStore = new InMemoryUserStore();
    const admin = await userStore.create({
      email: 'admin@test.com',
      isAdmin: true,
      roles: ['admin'],
    });
    adminToken = jwt.sign(
      { sub: admin.id, email: admin.email, role: 'admin', roles: ['admin'], isAdmin: true },
      jwtSecret,
      { expiresIn: '1h' }
    );
  });

  describe('1. Malformed Cookie Parsing (URIError prevention)', () => {
    it('handles malformed cookie (% or %ZZ) in auth middleware without crashing with 500', async () => {
      const app = express();
      // Notice: NO cookie-parser, so raw Cookie header fallback in tokenService is used
      app.use('/auth', createAuthRouter(userStore, config));

      const res = await request(app)
        .get('/auth/me')
        .set('Cookie', 'accessToken=%');

      // Must return 4xx (401 or 403), NOT crash with 500 URIError
      expect([401, 403]).toContain(res.status);
      expect(res.body.error).toBeDefined();
    });

    it('handles malformed cookie in admin router cookie parsing without crashing with 500', async () => {
      const app = express();
      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        silent: true,
      }));

      const res = await request(app)
        .get('/admin/api/ping')
        .set('Cookie', 'accessToken=%; other=%ZZ')
        .set('Accept', 'application/json');

      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: 'Unauthorized' });
    });
  });

  describe('2. Safe req.body destructuring in Admin endpoints', () => {
    function createAdminAppWithStores() {
      const app = express();
      // Mount without express.json() or with express.json() but sending non-JSON to test undefined req.body
      app.use(express.json());

      const mockRbacStore = {
        getRolesForUser: vi.fn().mockResolvedValue(['admin']),
        getPermissionsForUser: vi.fn().mockResolvedValue([]),
        assignRoleToUser: vi.fn().mockResolvedValue(undefined),
        removeRoleFromUser: vi.fn().mockResolvedValue(undefined),
        listAllRoles: vi.fn().mockResolvedValue([]),
        createRole: vi.fn().mockResolvedValue(undefined),
        deleteRole: vi.fn().mockResolvedValue(undefined),
      };

      const mockTenantStore = {
        getTenantsForUser: vi.fn().mockResolvedValue([]),
        getUsersForTenant: vi.fn().mockResolvedValue([]),
        associateUserWithTenant: vi.fn().mockResolvedValue(undefined),
        disassociateUserFromTenant: vi.fn().mockResolvedValue(undefined),
        createTenant: vi.fn().mockResolvedValue({ id: 't1', name: 'Tenant 1' }),
        deleteTenant: vi.fn().mockResolvedValue(undefined),
        listAllTenants: vi.fn().mockResolvedValue([]),
      };

      const mockApiKeyStore = {
        create: vi.fn().mockResolvedValue({ id: 'k1', key: 'test-key', name: 'Key 1' }),
        listAll: vi.fn().mockResolvedValue([]),
        revoke: vi.fn().mockResolvedValue(undefined),
      };

      const mockWebhookStore = {
        create: vi.fn().mockResolvedValue({ id: 'w1', url: 'https://example.com/webhook' }),
        listAll: vi.fn().mockResolvedValue([]),
        delete: vi.fn().mockResolvedValue(undefined),
      };

      const mockTemplateStore = {
        listMailTemplates: vi.fn().mockResolvedValue([]),
        getMailTemplate: vi.fn().mockResolvedValue(null),
        setMailTemplate: vi.fn().mockResolvedValue(undefined),
        deleteMailTemplate: vi.fn().mockResolvedValue(undefined),
        listUiTranslations: vi.fn().mockResolvedValue([]),
        getUiTranslation: vi.fn().mockResolvedValue(null),
        setUiTranslation: vi.fn().mockResolvedValue(undefined),
        deleteUiTranslation: vi.fn().mockResolvedValue(undefined),
      };

      const mockSettingsStore = {
        getRequire2FA: vi.fn().mockResolvedValue(false),
        setRequire2FA: vi.fn().mockResolvedValue(undefined),
      };

      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        adminSecret: 'super-admin-secret',
        rbacStore: mockRbacStore,
        tenantStore: mockTenantStore,
        apiKeyStore: mockApiKeyStore,
        webhookStore: mockWebhookStore,
        templateStore: mockTemplateStore,
        settingsStore: mockSettingsStore,
        silent: true,
      }));

      return app;
    }

    it('POST /admin/login handles empty or missing body with 400', async () => {
      const app = express();
      // Intentionally omit body parser to leave req.body undefined
      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        adminSecret: 'super-admin-secret',
        silent: true,
      }));

      const res = await request(app)
        .post('/admin/login')
        .set('Content-Type', 'application/json');

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'Password required' });
    });

    it('POST /admin/api/2fa-policy handles empty body with 400', async () => {
      const app = createAdminAppWithStores();
      const res = await request(app)
        .post('/admin/api/2fa-policy')
        .set('Cookie', `accessToken=${adminToken}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: '"required" must be a boolean' });
    });

    it('POST /admin/api/roles handles empty body with 400', async () => {
      const app = createAdminAppWithStores();
      const res = await request(app)
        .post('/admin/api/roles')
        .set('Cookie', `accessToken=${adminToken}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'name is required' });
    });

    it('POST /admin/api/tenants handles empty body with 400', async () => {
      const app = createAdminAppWithStores();
      const res = await request(app)
        .post('/admin/api/tenants')
        .set('Cookie', `accessToken=${adminToken}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'name is required' });
    });

    it('POST /admin/api/api-keys handles empty body with 400', async () => {
      const app = createAdminAppWithStores();
      const res = await request(app)
        .post('/admin/api/api-keys')
        .set('Cookie', `accessToken=${adminToken}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'name is required' });
    });

    it('POST /admin/api/webhooks handles empty body with 400', async () => {
      const app = createAdminAppWithStores();
      const res = await request(app)
        .post('/admin/api/webhooks')
        .set('Cookie', `accessToken=${adminToken}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'url is required' });
    });

    it('POST /admin/api/templates/mail handles empty body with 400', async () => {
      const app = createAdminAppWithStores();
      const res = await request(app)
        .post('/admin/api/templates/mail')
        .set('Cookie', `accessToken=${adminToken}`)
        .send({});

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'id is required' });
    });
  });

  describe('3. Repeated/array query parameters handling in Admin list endpoints', () => {
    it('GET /admin/api/users safely handles repeated query params ?limit=10&limit=20&filter=a&filter=b', async () => {
      const app = express();
      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        silent: true,
      }));

      const res = await request(app)
        .get('/admin/api/users?limit=10&limit=20&offset=0&offset=5&filter=admin&filter=other')
        .set('Cookie', `accessToken=${adminToken}`)
        .set('Accept', 'application/json');

      expect(res.status).toBe(200);
      expect(res.body.users).toBeDefined();
      expect(Array.isArray(res.body.users)).toBe(true);
      expect(res.body.total).toBeDefined();
    });

    it('GET /admin/api/sessions safely handles repeated query params', async () => {
      const app = express();
      const mockSessionStore = {
        createSession: vi.fn(),
        getSession: vi.fn(),
        revokeSession: vi.fn(),
        revokeAllSessionsForUser: vi.fn(),
        getAllSessions: vi.fn().mockResolvedValue([]),
      };

      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        sessionStore: mockSessionStore,
        silent: true,
      }));

      const res = await request(app)
        .get('/admin/api/sessions?limit=5&limit=15&offset=2&offset=10')
        .set('Cookie', `accessToken=${adminToken}`)
        .set('Accept', 'application/json');

      expect(res.status).toBe(200);
      expect(res.body.sessions).toBeDefined();
      // Verify mock was called with parsed numeric limit 5 and offset 2
      expect(mockSessionStore.getAllSessions).toHaveBeenCalledWith(5, 2);
    });

    it('GET /admin/api/api-keys safely handles repeated query params', async () => {
      const app = express();
      const mockApiKeyStore = {
        create: vi.fn(),
        listAll: vi.fn().mockResolvedValue([]),
        revoke: vi.fn(),
      };

      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        apiKeyStore: mockApiKeyStore,
        silent: true,
      }));

      const res = await request(app)
        .get('/admin/api/api-keys?limit=10&limit=50&offset=1&offset=20&filter=mykey&filter=other')
        .set('Cookie', `accessToken=${adminToken}`)
        .set('Accept', 'application/json');

      expect(res.status).toBe(200);
      expect(mockApiKeyStore.listAll).toHaveBeenCalledWith(500, 0);
    });

    it('GET /admin/api/webhooks safely handles repeated query params', async () => {
      const app = express();
      const mockWebhookStore = {
        create: vi.fn(),
        listAll: vi.fn().mockResolvedValue([]),
        delete: vi.fn(),
      };

      app.use('/admin', createAdminRouter(userStore, {
        accessPolicy: 'is-admin-flag',
        jwtSecret,
        webhookStore: mockWebhookStore,
        silent: true,
      }));

      const res = await request(app)
        .get('/admin/api/webhooks?limit=10&limit=30&offset=0&offset=5')
        .set('Cookie', `accessToken=${adminToken}`)
        .set('Accept', 'application/json');

      expect(res.status).toBe(200);
      expect(mockWebhookStore.listAll).toHaveBeenCalledWith(10, 0);
    });
  });
});
