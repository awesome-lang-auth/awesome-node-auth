/**
 * Event payload hygiene for the events the routers and AuthConfigurator
 * publish on an AuthEventBus: bounded client strings, explicit OAuth conflict
 * fields, the acting admin on privilege changes, and listener errors that do
 * not fail a completed operation.
 */
import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createAuthRouter } from '../src/router/auth.router';
import { createAdminRouter } from '../src/router/admin.router';
import { AuthConfigurator } from '../src/auth-configurator';
import { AuthConfig } from '../src/models/auth-config.model';
import { AuthError } from '../src/models/errors';
import { IRolesPermissionsStore } from '../src/interfaces/roles-permissions-store.interface';
import { AuthEventBus, AuthEventPayload } from '../src/events/auth-event-bus';
import { AuthEventNames } from '../src/events/auth-event-names';
import { GenericOAuthStrategy } from '../src/strategies/oauth/generic-oauth.strategy';
import { PasswordService } from '../src/services/password.service';
import { TokenService } from '../src/services/token.service';
import { InMemoryUserStore } from '../examples/in-memory-user-store';

const config: AuthConfig = {
  accessTokenSecret: 'events-access-secret-very-long-and-secure',
  refreshTokenSecret: 'events-refresh-secret-very-long-and-secure',
  accessTokenExpiresIn: '15m',
  refreshTokenExpiresIn: '7d',
  email: { siteUrl: 'http://localhost:3000' },
};

const passwordService = new PasswordService();
const tokenService = new TokenService();

function makeRbacStore(rolesForUser: string[] = []): IRolesPermissionsStore {
  return {
    addRoleToUser: vi.fn().mockResolvedValue(undefined),
    removeRoleFromUser: vi.fn().mockResolvedValue(undefined),
    getRolesForUser: vi.fn().mockResolvedValue(rolesForUser),
    createRole: vi.fn().mockResolvedValue(undefined),
    deleteRole: vi.fn().mockResolvedValue(undefined),
    addPermissionToRole: vi.fn().mockResolvedValue(undefined),
    removePermissionFromRole: vi.fn().mockResolvedValue(undefined),
    getPermissionsForRole: vi.fn().mockResolvedValue([]),
    getPermissionsForUser: vi.fn().mockResolvedValue([]),
    userHasPermission: vi.fn().mockResolvedValue(false),
  };
}

function collect(bus: AuthEventBus): AuthEventPayload[] {
  const seen: AuthEventPayload[] = [];
  bus.onEvent('*', (payload) => seen.push(payload));
  return seen;
}

describe('router event payloads', () => {
  let stderrSpy: MockInstance;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  it('AUTH_LOGIN_FAILED keeps a client e-mail only as a string of at most 320 characters', async () => {
    const bus = new AuthEventBus();
    const seen = collect(bus);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(new InMemoryUserStore(), config, { eventBus: bus }));

    await request(app).post('/auth/login').send({ email: { nested: 'y'.repeat(2000) }, password: 'p' });
    await request(app).post('/auth/login').send({ email: `${'a'.repeat(400)}@x.test`, password: 'p' });
    await request(app).post('/auth/login').send({ email: 'nobody@x.test', password: 'p' });

    const failed = seen.filter((e) => e.event === AuthEventNames.AUTH_LOGIN_FAILED);
    expect(failed).toHaveLength(3);
    expect((failed[0].data as Record<string, unknown>)['email']).toBeUndefined();
    expect(((failed[1].data as Record<string, unknown>)['email'] as string).length).toBe(320);
    expect((failed[2].data as Record<string, unknown>)['email']).toBe('nobody@x.test');
  });

  it('keeps X-Correlation-Id only when it is 1-128 characters of [A-Za-z0-9_.:-]', async () => {
    const bus = new AuthEventBus();
    const seen = collect(bus);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(new InMemoryUserStore(), config, { eventBus: bus }));

    const send = (id: string) => request(app).post('/auth/login')
      .set('X-Correlation-Id', id)
      .send({ email: 'nobody@x.test', password: 'p' });
    await send('req-2f1c:9a.b_7');
    await send('x'.repeat(129));
    await send('bad id <script>');

    expect(seen.map((e) => e.correlationId)).toEqual(['req-2f1c:9a.b_7', undefined, undefined]);
  });

  it('AUTH_OAUTH_CONFLICT carries only provider, email and providerAccountId', async () => {
    class ConflictStrategy extends GenericOAuthStrategy {
      override async handleCallback(): Promise<never> {
        throw new AuthError('conflict', 'OAUTH_ACCOUNT_CONFLICT', 409, {
          email: 'conflict@x.test',
          providerAccountId: 'acct-1',
          provider: 'spoofed',
          accessToken: 'provider-token',
        });
      }
      async findOrCreateUser(): Promise<never> { throw new Error('not reached'); }
    }
    const bus = new AuthEventBus();
    const seen = collect(bus);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(new InMemoryUserStore(), config, {
      eventBus: bus,
      oauthStrategies: [new ConflictStrategy({
        name: 'fakeprovider',
        clientId: 'c',
        clientSecret: 's',
        callbackUrl: 'http://cb',
        authorizationUrl: 'http://auth',
        tokenUrl: 'http://token',
        userInfoUrl: 'http://userinfo',
        scope: 'email',
      })],
    }));

    const res = await request(app).get('/auth/oauth/fakeprovider/callback?code=fake-code');

    expect(res.status).toBe(302);
    const conflict = seen.find((e) => e.event === AuthEventNames.AUTH_OAUTH_CONFLICT);
    expect(conflict?.data).toEqual({ provider: 'fakeprovider', email: 'conflict@x.test', providerAccountId: 'acct-1' });
  });

  it('ROLE_ASSIGNED / ROLE_REVOKED from the admin router carry the acting admin as data.actorId', async () => {
    const store = new InMemoryUserStore();
    const admin = await store.create({ email: 'admin@x.test', password: await passwordService.hash('secret') });
    const bus = new AuthEventBus();
    const seen = collect(bus);
    const app = express();
    app.use('/admin', createAdminRouter(store, {
      accessPolicy: (user) => user.roles.includes('admin'),
      jwtSecret: config.accessTokenSecret,
      rbacStore: makeRbacStore(['admin']),
      eventBus: bus,
      silent: true,
    }));
    const token = tokenService.generateTokenPair({ sub: admin.id, email: admin.email }, config).accessToken;
    const cookie = `accessToken=${token}`;

    expect((await request(app).post('/admin/users/u-9/promote').set('Cookie', cookie).send({})).status).toBe(200);
    expect((await request(app).post('/admin/api/users/u-9/roles').set('Cookie', cookie).send({ role: 'editor' })).status).toBe(200);
    expect((await request(app).delete('/admin/api/users/u-9/roles/editor').set('Cookie', cookie)).status).toBe(200);

    expect(seen.map((e) => [e.event, e.userId, e.data])).toEqual([
      [AuthEventNames.ROLE_ASSIGNED, 'u-9', { role: 'admin', method: 'role', actorId: admin.id }],
      [AuthEventNames.ROLE_ASSIGNED, 'u-9', { role: 'editor', actorId: admin.id }],
      [AuthEventNames.ROLE_REVOKED, 'u-9', { role: 'editor', actorId: admin.id }],
    ]);
  });

  it('records no actorId under adminSecret or accessPolicy "open", even when an upstream middleware set req.user', async () => {
    const store = new InMemoryUserStore();
    const bus = new AuthEventBus();
    const seen = collect(bus);
    const upstreamUser = (req: express.Request, _res: express.Response, next: express.NextFunction) => {
      (req as unknown as { user: unknown }).user = { id: 'upstream-user' };
      next();
    };

    const secretApp = express();
    secretApp.use(upstreamUser);
    secretApp.use('/admin', createAdminRouter(store, {
      adminSecret: 'the-admin-secret',
      rbacStore: makeRbacStore(),
      eventBus: bus,
      silent: true,
    }));
    const viaSecret = await request(secretApp)
      .post('/admin/users/u-10/promote')
      .set('Authorization', 'Bearer the-admin-secret')
      .send({});
    expect(viaSecret.status).toBe(200);

    const openApp = express();
    openApp.use(upstreamUser);
    openApp.use('/admin', createAdminRouter(store, {
      accessPolicy: 'open',
      rbacStore: makeRbacStore(),
      eventBus: bus,
      silent: true,
    }));
    const viaOpen = await request(openApp).post('/admin/users/u-11/promote').send({});
    expect(viaOpen.status).toBe(200);

    expect(seen.map((e) => [e.userId, e.data])).toEqual([
      ['u-10', { role: 'admin', method: 'role', actorId: undefined }],
      ['u-11', { role: 'admin', method: 'role', actorId: undefined }],
    ]);
    for (const event of seen) {
      expect((event.data as Record<string, unknown>)['actorId']).toBeUndefined();
    }
  });

  it('a throwing listener does not fail a completed operation', async () => {
    const store = new InMemoryUserStore();
    await store.create({ email: 'user@x.test', password: await passwordService.hash('password123') });
    const bus = new AuthEventBus();
    bus.onEvent('*', () => { throw new Error('listener failure'); });
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { eventBus: bus }));

    const login = await request(app)
      .post('/auth/login')
      .set('X-Auth-Strategy', 'bearer')
      .send({ email: 'user@x.test', password: 'password123' });
    expect(login.status).toBe(200);
    expect(typeof login.body.accessToken).toBe('string');

    const changed = await request(app)
      .post('/auth/change-password')
      .set('Authorization', `Bearer ${login.body.accessToken as string}`)
      .send({ currentPassword: 'password123', newPassword: 'password456' });
    expect(changed.status).toBe(200);

    const auth = new AuthConfigurator(config, store, { eventBus: bus });
    await expect(auth.promoteToAdmin('1', { rbacStore: makeRbacStore() })).resolves.toBeUndefined();

    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('an event listener for identity.auth.login.success threw: listener failure'));
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('an event listener for identity.user.password.changed threw'));
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('an event listener for identity.role.assigned threw'));
  });
});
