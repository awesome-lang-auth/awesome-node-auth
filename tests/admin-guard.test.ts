/**
 * Admin guard: which unauthenticated requests reach a handler.
 *
 * The session-based guard lets an unauthenticated browser `GET` through with
 * an `adminNeedsAuth` marker so the HTML panel can render its sign-in form.
 * Only the panel route may receive that marker: every other guarded route
 * answers 401 to an unauthenticated request, whatever its `Accept` header.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createAdminRouter } from '../src/router/admin.router';
import { InMemoryUserStore } from '../examples/in-memory-user-store';

const jwtSecret = 'admin-guard-secret-very-long-and-secure';

function buildApp(userStore: InMemoryUserStore, loginPath?: string): express.Application {
  const app = express();
  app.use(express.json());
  app.use('/admin', createAdminRouter(userStore, {
    accessPolicy: 'is-admin-flag',
    jwtSecret,
    loginPath,
    silent: true,
  }));
  return app;
}

describe('admin guard: unauthenticated browser requests', () => {
  let userStore: InMemoryUserStore;

  beforeEach(async () => {
    userStore = new InMemoryUserStore();
    await userStore.create({ email: 'someone@example.com', phoneNumber: '+10000000000', isAdmin: true });
  });

  it('REGRESSION-ADMIN-GUARD-HTML-ACCEPT: GET <admin>/api/users with Accept: text/html and no credential is 401, and the panel still renders its sign-in form', async () => {
    const app = buildApp(userStore);

    const users = await request(app)
      .get('/admin/api/users')
      .set('Accept', 'text/html,application/xhtml+xml');
    expect(users.status).toBe(401);
    expect(users.body).toEqual({ error: 'Unauthorized' });
    expect(users.text).not.toContain('someone@example.com');

    const panel = await request(app)
      .get('/admin/')
      .set('Accept', 'text/html');
    expect(panel.status).toBe(200);
    expect(panel.headers['content-type']).toContain('text/html');
    expect(panel.text).toContain('id="login"');
    expect(panel.text).toContain('id="email-input"');
  });

  it('every guarded GET under /api answers 401 to an unauthenticated browser request', async () => {
    const app = buildApp(userStore);
    for (const path of ['/admin/api/ping', '/admin/api/users/1', '/admin/api/sessions', '/admin/api/settings', '/admin/api/roles']) {
      const res = await request(app).get(path).set('Accept', 'text/html');
      expect(res.status, path).toBe(401);
      expect(res.body, path).toEqual({ error: 'Unauthorized' });
    }
  });

  it('with loginPath, the panel still redirects to the login page and the API still answers 401', async () => {
    const app = buildApp(userStore, '/login');

    const panel = await request(app).get('/admin/').set('Accept', 'text/html');
    expect(panel.status).toBe(302);
    expect(panel.headers['location']).toBe('/login?redirect=%2Fadmin%2F');

    const users = await request(app).get('/admin/api/users').set('Accept', 'text/html');
    expect(users.status).toBe(401);
    expect(users.body).toEqual({ error: 'Unauthorized' });
  });

  it('an unauthenticated API request without Accept: text/html is 401, as before', async () => {
    const app = buildApp(userStore);
    const res = await request(app).get('/admin/api/users').set('Accept', 'application/json');
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'Unauthorized' });
  });
});

describe('createAdminRouter: empty adminSecret', () => {
  it('throws when adminSecret is present but empty and no accessPolicy is set', () => {
    const userStore = new InMemoryUserStore();
    expect(() => createAdminRouter(userStore, { adminSecret: '' })).toThrow(/adminSecret` is empty/);
    // An unset environment variable passed through as a string.
    const unset = process.env['M22_SURELY_UNSET_ADMIN_SECRET'] as string;
    expect(() => createAdminRouter(userStore, { adminSecret: unset })).toThrow(/adminSecret` is empty/);
  });

  it('refuses the empty secret through buildAllRouters() too', async () => {
    const { AuthConfigurator } = await import('../src/auth-configurator');
    const auth = new AuthConfigurator(
      { accessTokenSecret: jwtSecret, refreshTokenSecret: `${jwtSecret}-refresh` },
      new InMemoryUserStore(),
    );
    expect(() => auth.buildAllRouters({ admin: { adminSecret: '' } })).toThrow(/adminSecret` is empty/);
  });

  it('does not throw for a non-empty secret, without adminSecret, or when accessPolicy is set', async () => {
    const userStore = new InMemoryUserStore();
    expect(() => createAdminRouter(userStore, { adminSecret: 's3cret', silent: true })).not.toThrow();
    expect(() => createAdminRouter(userStore, { accessPolicy: 'is-admin-flag', jwtSecret, adminSecret: '', silent: true })).not.toThrow();

    // Neither option: still the documented unprotected router with a WARNING.
    const write = process.stderr.write.bind(process.stderr);
    const lines: string[] = [];
    process.stderr.write = ((chunk: string) => { lines.push(String(chunk)); return true; }) as typeof process.stderr.write;
    try {
      expect(() => createAdminRouter(userStore, { silent: true })).not.toThrow();
    } finally {
      process.stderr.write = write;
    }
    expect(lines.join('')).toContain('WARNING: createAdminRouter called without `accessPolicy` or `adminSecret`');

    // The legacy secret still guards the API.
    const app = express();
    app.use('/admin', createAdminRouter(userStore, { adminSecret: 's3cret', silent: true }));
    expect((await request(app).get('/admin/api/ping')).status).toBe(401);
    expect((await request(app).get('/admin/api/ping').set('Authorization', 'Bearer s3cret')).status).toBe(200);
  });
});
