/**
 * Tests for Swagger/OpenAPI routes on the auth and admin routers.
 */
import { describe, it, expect, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createAuthRouter } from '../src/router/auth.router';
import { createAdminRouter } from '../src/router/admin.router';
import { buildAuthOpenApiSpec, buildAdminOpenApiSpec } from '../src/router/openapi';
import type { IUserStore } from '../src/interfaces/user-store.interface';
import type { AuthConfig } from '../src/models/auth-config.model';

// ─────────────────────────────────────────────────────────────────────────────
// Minimal stubs
// ─────────────────────────────────────────────────────────────────────────────

const config: AuthConfig = {
  accessTokenSecret: 'test-access-secret-very-long-and-secure',
  refreshTokenSecret: 'test-refresh-secret-very-long-and-secure',
  accessTokenExpiresIn: '15m',
  refreshTokenExpiresIn: '7d',
};

const userStore: IUserStore = {
  findByEmail: vi.fn(),
  findById: vi.fn(),
  create: vi.fn(),
  updateRefreshToken: vi.fn(),
  updateLastLogin: vi.fn(),
  updateResetToken: vi.fn(),
  updatePassword: vi.fn(),
  updateTotpSecret: vi.fn(),
  updateMagicLinkToken: vi.fn(),
  updateSmsCode: vi.fn(),
};

const ADMIN_SECRET = 'admin-test-secret';

function buildAuthApp(swaggerOpt: boolean | 'auto', nodeEnv?: string) {
  const savedEnv = process.env['NODE_ENV'];
  try {
    if (nodeEnv !== undefined) process.env['NODE_ENV'] = nodeEnv;
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, config, { swagger: swaggerOpt }));
    return app;
  } finally {
    process.env['NODE_ENV'] = savedEnv;
  }
}

function buildAdminApp(swaggerOpt: boolean | 'auto', nodeEnv?: string) {
  const savedEnv = process.env['NODE_ENV'];
  try {
    if (nodeEnv !== undefined) process.env['NODE_ENV'] = nodeEnv;
    const app = express();
    app.use(express.json());
    app.use('/admin', createAdminRouter(userStore, { adminSecret: ADMIN_SECRET, swagger: swaggerOpt }));
    return app;
  } finally {
    process.env['NODE_ENV'] = savedEnv;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// buildAuthOpenApiSpec
// ─────────────────────────────────────────────────────────────────────────────
describe('buildAuthOpenApiSpec', () => {
  it('returns a valid OpenAPI 3.0 document', () => {
    const spec = buildAuthOpenApiSpec();
    expect(spec.openapi).toBe('3.0.3');
    expect(spec.info.title).toContain('awesome-node-auth');
    expect(typeof spec.paths).toBe('object');
  });

  it('always includes core auth paths', () => {
    const spec = buildAuthOpenApiSpec({}, '/auth');
    expect(spec.paths['/auth/login']).toBeDefined();
    expect(spec.paths['/auth/logout']).toBeDefined();
    expect(spec.paths['/auth/refresh']).toBeDefined();
    expect(spec.paths['/auth/me']).toBeDefined();
    expect(spec.paths['/auth/forgot-password']).toBeDefined();
    expect(spec.paths['/auth/reset-password']).toBeDefined();
    expect(spec.paths['/auth/change-password']).toBeDefined();
    expect(spec.paths['/auth/2fa/setup']).toBeDefined();
    expect(spec.paths['/auth/2fa/verify-setup']).toBeDefined();
    expect(spec.paths['/auth/2fa/verify']).toBeDefined();
    expect(spec.paths['/auth/2fa/disable']).toBeDefined();
    expect(spec.paths['/auth/send-verification-email']).toBeDefined();
    expect(spec.paths['/auth/verify-email']).toBeDefined();
    expect(spec.paths['/auth/change-email/request']).toBeDefined();
    expect(spec.paths['/auth/change-email/confirm']).toBeDefined();
    expect(spec.paths['/auth/magic-link/send']).toBeDefined();
    expect(spec.paths['/auth/magic-link/verify']).toBeDefined();
    expect(spec.paths['/auth/sms/send']).toBeDefined();
    expect(spec.paths['/auth/sms/verify']).toBeDefined();
    expect(spec.paths['/auth/account']).toBeDefined();
  });

  it('includes register path only when hasRegister=true', () => {
    expect(buildAuthOpenApiSpec({ hasRegister: true }, '/auth').paths['/auth/register']).toBeDefined();
    expect(buildAuthOpenApiSpec({ hasRegister: false }, '/auth').paths['/auth/register']).toBeUndefined();
  });

  it('auth router OpenAPI includes /register when the default register handler is active', async () => {
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, config, { swagger: true }));

    const res = await request(app).get('/auth/openapi.json');

    expect(res.status).toBe(200);
    expect(res.body.paths['/auth/register']).toBeDefined();
  });

  it('includes sessions/cleanup path only when hasSessionsCleanup=true', () => {
    expect(buildAuthOpenApiSpec({ hasSessionsCleanup: true }, '/auth').paths['/auth/sessions/cleanup']).toBeDefined();
    expect(buildAuthOpenApiSpec({ hasSessionsCleanup: false }, '/auth').paths['/auth/sessions/cleanup']).toBeUndefined();
  });

  it('includes Google OAuth paths only when hasGoogleOAuth=true', () => {
    const withGoogle = buildAuthOpenApiSpec({ hasGoogleOAuth: true }, '/auth');
    expect(withGoogle.paths['/auth/oauth/google']).toBeDefined();
    expect(withGoogle.paths['/auth/oauth/google/callback']).toBeDefined();
    const withoutGoogle = buildAuthOpenApiSpec({ hasGoogleOAuth: false }, '/auth');
    expect(withoutGoogle.paths['/auth/oauth/google']).toBeUndefined();
  });

  it('includes GitHub OAuth paths only when hasGithubOAuth=true', () => {
    const withGithub = buildAuthOpenApiSpec({ hasGithubOAuth: true }, '/auth');
    expect(withGithub.paths['/auth/oauth/github']).toBeDefined();
    const withoutGithub = buildAuthOpenApiSpec({ hasGithubOAuth: false }, '/auth');
    expect(withoutGithub.paths['/auth/oauth/github']).toBeUndefined();
  });

  it('includes generic OAuth paths for provided provider names', () => {
    const spec = buildAuthOpenApiSpec({ oauthProviders: ['facebook', 'twitter'] }, '/auth');
    expect(spec.paths['/auth/oauth/facebook']).toBeDefined();
    expect(spec.paths['/auth/oauth/twitter']).toBeDefined();
    expect(spec.paths['/auth/oauth/facebook/callback']).toBeDefined();
  });

  it('includes linked-account paths only when hasLinkedAccounts=true', () => {
    const withLinked = buildAuthOpenApiSpec({ hasLinkedAccounts: true }, '/auth');
    expect(withLinked.paths['/auth/linked-accounts']).toBeDefined();
    expect(withLinked.paths['/auth/link-request']).toBeDefined();
    expect(withLinked.paths['/auth/link-verify']).toBeDefined();
    const withoutLinked = buildAuthOpenApiSpec({ hasLinkedAccounts: false }, '/auth');
    expect(withoutLinked.paths['/auth/linked-accounts']).toBeUndefined();
  });

  it('uses the provided basePath', () => {
    const spec = buildAuthOpenApiSpec({}, '/api/auth');
    expect(Object.keys(spec.paths).every((p) => p.startsWith('/api/auth'))).toBe(true);
  });

  it('includes BearerAuth security scheme', () => {
    const spec = buildAuthOpenApiSpec();
    expect(spec.components?.securitySchemes?.['BearerAuth']).toBeDefined();
  });

  it('includes LoginRequest schema', () => {
    const spec = buildAuthOpenApiSpec();
    expect(spec.components?.schemas?.['LoginRequest']).toBeDefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// buildAdminOpenApiSpec
// ─────────────────────────────────────────────────────────────────────────────
describe('buildAdminOpenApiSpec', () => {
  it('returns a valid OpenAPI 3.0 document', () => {
    const spec = buildAdminOpenApiSpec();
    expect(spec.openapi).toBe('3.0.3');
    expect(spec.info.title).toContain('Admin');
    expect(typeof spec.paths).toBe('object');
  });

  it('always includes core admin paths', () => {
    const spec = buildAdminOpenApiSpec({}, '/admin');
    expect(spec.paths['/admin/api/ping']).toBeDefined();
    expect(spec.paths['/admin/api/users']).toBeDefined();
    expect(spec.paths['/admin/api/users/{id}']).toBeDefined();
    expect(spec.paths['/admin/api/2fa-policy']).toBeDefined();
  });

  it('includes session endpoints only when hasSessions=true', () => {
    const with_ = buildAdminOpenApiSpec({ hasSessions: true }, '/admin');
    expect(with_.paths['/admin/api/sessions']).toBeDefined();
    expect(with_.paths['/admin/api/sessions/{handle}']).toBeDefined();
    const without = buildAdminOpenApiSpec({ hasSessions: false }, '/admin');
    expect(without.paths['/admin/api/sessions']).toBeUndefined();
  });

  it('includes role endpoints only when hasRoles=true', () => {
    const with_ = buildAdminOpenApiSpec({ hasRoles: true }, '/admin');
    expect(with_.paths['/admin/api/roles']).toBeDefined();
    expect(with_.paths['/admin/api/users/{id}/roles']).toBeDefined();
    const without = buildAdminOpenApiSpec({ hasRoles: false }, '/admin');
    expect(without.paths['/admin/api/roles']).toBeUndefined();
  });

  it('includes tenant endpoints only when hasTenants=true', () => {
    const with_ = buildAdminOpenApiSpec({ hasTenants: true }, '/admin');
    expect(with_.paths['/admin/api/tenants']).toBeDefined();
    expect(with_.paths['/admin/api/tenants/{id}/users']).toBeDefined();
    const without = buildAdminOpenApiSpec({ hasTenants: false }, '/admin');
    expect(without.paths['/admin/api/tenants']).toBeUndefined();
  });

  it('includes metadata endpoints only when hasMetadata=true', () => {
    const with_ = buildAdminOpenApiSpec({ hasMetadata: true }, '/admin');
    expect(with_.paths['/admin/api/users/{id}/metadata']).toBeDefined();
    const without = buildAdminOpenApiSpec({ hasMetadata: false }, '/admin');
    expect(without.paths['/admin/api/users/{id}/metadata']).toBeUndefined();
  });

  it('includes settings endpoints only when hasSettings=true', () => {
    const with_ = buildAdminOpenApiSpec({ hasSettings: true }, '/admin');
    expect(with_.paths['/admin/api/settings']).toBeDefined();
    const without = buildAdminOpenApiSpec({ hasSettings: false }, '/admin');
    expect(without.paths['/admin/api/settings']).toBeUndefined();
  });

  it('uses the provided basePath', () => {
    const spec = buildAdminOpenApiSpec({}, '/api/admin');
    expect(Object.keys(spec.paths).every((p) => p.startsWith('/api/admin'))).toBe(true);
  });

  it('includes AdminAuth security scheme', () => {
    const spec = buildAdminOpenApiSpec();
    expect(spec.components?.securitySchemes?.['AdminAuth']).toBeDefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Auth router — swagger HTTP routes
// ─────────────────────────────────────────────────────────────────────────────
describe('createAuthRouter — swagger routes', () => {
  it('serves GET /auth/openapi.json when swagger=true', async () => {
    const app = buildAuthApp(true);
    const res = await request(app).get('/auth/openapi.json');
    expect(res.status).toBe(200);
    expect(res.body.openapi).toBe('3.0.3');
    expect(res.body.paths['/auth/login']).toBeDefined();
  });

  it('serves GET /auth/docs HTML when swagger=true', async () => {
    const app = buildAuthApp(true);
    const res = await request(app).get('/auth/docs');
    expect(res.status).toBe(200);
    expect(res.text).toContain('swagger-ui');
  });

  it('returns 404 for /auth/openapi.json when swagger=false', async () => {
    const app = buildAuthApp(false);
    const res = await request(app).get('/auth/openapi.json');
    expect(res.status).toBe(404);
  });

  it('enables swagger in development when swagger=auto', async () => {
    const app = buildAuthApp('auto', 'development');
    const res = await request(app).get('/auth/openapi.json');
    expect(res.status).toBe(200);
  });

  it('disables swagger in production when swagger=auto', async () => {
    const app = buildAuthApp('auto', 'production');
    const res = await request(app).get('/auth/openapi.json');
    expect(res.status).toBe(404);
  });

  it('spec reflects hasRegister when onRegister is provided', async () => {
    const savedEnv = process.env['NODE_ENV'];
    try {
      process.env['NODE_ENV'] = 'development';
      const app = express();
      app.use(express.json());
      app.use('/auth', createAuthRouter(userStore, config, {
        swagger: true,
        onRegister: async () => ({ id: '1', email: 'x@x.com' }),
      }));
      const res = await request(app).get('/auth/openapi.json');
      expect(res.status).toBe(200);
      expect(res.body.paths['/auth/register']).toBeDefined();
    } finally {
      process.env['NODE_ENV'] = savedEnv;
    }
  });

  it('spec includes register path when the default register handler is available', async () => {
    const app = buildAuthApp(true);
    const res = await request(app).get('/auth/openapi.json');
    expect(res.status).toBe(200);
    expect(res.body.paths['/auth/register']).toBeDefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Admin router — swagger HTTP routes
// ─────────────────────────────────────────────────────────────────────────────
describe('createAdminRouter — swagger routes', () => {
  it('serves GET /admin/api/openapi.json when swagger=true', async () => {
    const app = buildAdminApp(true);
    const res = await request(app).get('/admin/api/openapi.json');
    expect(res.status).toBe(200);
    expect(res.body.openapi).toBe('3.0.3');
    expect(res.body.paths['/admin/api/users']).toBeDefined();
  });

  it('serves GET /admin/api/docs HTML when swagger=true', async () => {
    const app = buildAdminApp(true);
    const res = await request(app).get('/admin/api/docs');
    expect(res.status).toBe(200);
    expect(res.text).toContain('swagger-ui');
  });

  it('returns 404 for /admin/api/openapi.json when swagger=false', async () => {
    const app = buildAdminApp(false);
    const res = await request(app).get('/admin/api/openapi.json');
    expect(res.status).toBe(404);
  });

  it('enables swagger in development when swagger=auto', async () => {
    const app = buildAdminApp('auto', 'development');
    const res = await request(app).get('/admin/api/openapi.json');
    expect(res.status).toBe(200);
  });

  it('disables swagger in production when swagger=auto', async () => {
    const app = buildAdminApp('auto', 'production');
    const res = await request(app).get('/admin/api/openapi.json');
    expect(res.status).toBe(404);
  });

  it('spec reflects optional stores when provided', async () => {
    const savedEnv = process.env['NODE_ENV'];
    try {
      process.env['NODE_ENV'] = 'development';
      const mockSession = {
        getSessionsForUser: vi.fn(),
        revokeSession: vi.fn(),
        listAllSessions: vi.fn(),
      };
      const app = express();
      app.use(express.json());
      app.use('/admin', createAdminRouter(userStore, {
        adminSecret: ADMIN_SECRET,
        swagger: true,
        sessionStore: mockSession as never,
      }));
      const res = await request(app).get('/admin/api/openapi.json');
      expect(res.status).toBe(200);
      expect(res.body.paths['/admin/api/sessions']).toBeDefined();
    } finally {
      process.env['NODE_ENV'] = savedEnv;
    }
  });

  it('spec does not include sessions when sessionStore is absent', async () => {
    const app = buildAdminApp(true);
    const res = await request(app).get('/admin/api/openapi.json');
    expect(res.status).toBe(200);
    expect(res.body.paths['/admin/api/sessions']).toBeUndefined();
  });
});
