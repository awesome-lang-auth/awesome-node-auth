/**
 * Tests for new auth endpoints: change-password, email verification, change-email.
 * Tests for the admin router.
 */
import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createAuthRouter } from '../src/router/auth.router';
import { createAdminRouter } from '../src/router/admin.router';
import { IUserStore } from '../src/interfaces/user-store.interface';
import { ISessionStore } from '../src/interfaces/session-store.interface';
import { IRolesPermissionsStore } from '../src/interfaces/roles-permissions-store.interface';
import { ITenantStore } from '../src/interfaces/tenant-store.interface';
import { IUserMetadataStore } from '../src/interfaces/user-metadata-store.interface';
import { ILinkedAccountsStore, LinkedAccount } from '../src/interfaces/linked-accounts-store.interface';
import { BaseUser } from '../src/models/user.model';
import { SessionInfo } from '../src/models/session.model';
import { Tenant } from '../src/models/tenant.model';
import { AuthConfig } from '../src/models/auth-config.model';
import { PasswordService } from '../src/services/password.service';
import { TokenService } from '../src/services/token.service';
import { AuthEventBus } from '../src/events/auth-event-bus';
import { AuthEventNames } from '../src/events/auth-event-names';

const passwordService = new PasswordService();
const tokenService = new TokenService();

const config: AuthConfig = {
  accessTokenSecret: 'test-access-secret-very-long-and-secure',
  refreshTokenSecret: 'test-refresh-secret-very-long-and-secure',
  accessTokenExpiresIn: '15m',
  refreshTokenExpiresIn: '7d',
  email: {
    sendPasswordReset: vi.fn().mockResolvedValue(undefined),
    sendVerificationEmail: vi.fn().mockResolvedValue(undefined),
    sendEmailChanged: vi.fn().mockResolvedValue(undefined),
    siteUrl: 'http://localhost:3000',
  },
};

let users: Map<string, BaseUser>;
let passwordHash: string;

function createFullStore(): IUserStore {
  return {
    findByEmail: vi.fn((email: string) => Promise.resolve([...users.values()].find(u => u.email === email) ?? null)),
    findById: vi.fn((id: string) => Promise.resolve(users.get(id) ?? null)),
    create: vi.fn((data: Partial<BaseUser>) => {
      const id = `new-${users.size + 1}`;
      const user: BaseUser = { id, email: String(data.email), password: data.password };
      users.set(id, user);
      return Promise.resolve(user);
    }),
    updateRefreshToken: vi.fn((id, token, expiry) => {
      const u = users.get(id);
      if (u) { u.refreshToken = token; u.refreshTokenExpiry = expiry; }
      return Promise.resolve();
    }),
    updateLastLogin: vi.fn((id) => {
      const u = users.get(id);
      if (u) u.lastLogin = new Date();
      return Promise.resolve();
    }),
    updateResetToken: vi.fn(),
    updatePassword: vi.fn((id, hash) => {
      const u = users.get(id);
      if (u) u.password = hash;
      return Promise.resolve();
    }),
    updateTotpSecret: vi.fn(),
    updateMagicLinkToken: vi.fn(),
    updateSmsCode: vi.fn(),
    findByResetToken: vi.fn((token) => Promise.resolve([...users.values()].find(u => u.resetToken === token) ?? null)),
    findByMagicLinkToken: vi.fn((token) => Promise.resolve([...users.values()].find(u => u.magicLinkToken === token) ?? null)),
    // Email verification
    updateEmailVerificationToken: vi.fn((id, token, expiry) => {
      const u = users.get(id);
      if (u) { u.emailVerificationToken = token; u.emailVerificationTokenExpiry = expiry; }
      return Promise.resolve();
    }),
    updateEmailVerified: vi.fn((id, verified) => {
      const u = users.get(id);
      if (u) u.isEmailVerified = verified;
      return Promise.resolve();
    }),
    findByEmailVerificationToken: vi.fn((token) =>
      Promise.resolve([...users.values()].find(u => u.emailVerificationToken === token) ?? null)
    ),
    // Change email
    updateEmailChangeToken: vi.fn((id, pendingEmail, token, expiry) => {
      const u = users.get(id);
      if (u) { u.pendingEmail = pendingEmail; u.emailChangeToken = token; u.emailChangeTokenExpiry = expiry; }
      return Promise.resolve();
    }),
    updateEmail: vi.fn((id, newEmail) => {
      const u = users.get(id);
      if (u) { u.email = newEmail; u.pendingEmail = null; u.emailChangeToken = null; }
      return Promise.resolve();
    }),
    findByEmailChangeToken: vi.fn((token) =>
      Promise.resolve([...users.values()].find(u => u.emailChangeToken === token) ?? null)
    ),
    // Admin
    listUsers: vi.fn((limit, offset) => Promise.resolve([...users.values()].slice(offset, offset + limit))),
  };
}

function getAccessToken(user: BaseUser): string {
  return tokenService.generateTokenPair({ sub: user.id, email: user.email }, config).accessToken;
}

// ---------------------------------------------------------------------------
// change-password
// ---------------------------------------------------------------------------

describe('POST /auth/change-password', () => {
  let app: express.Application;
  let store: IUserStore;

  beforeAll(async () => { passwordHash = await passwordService.hash('oldpass123'); });

  beforeEach(() => {
    users = new Map();
    users.set('1', { id: '1', email: 'user@test.com', password: passwordHash });
    store = createFullStore();
    app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config));
  });

  it('changes password with correct current password', async () => {
    const token = getAccessToken(users.get('1')!);
    const res = await request(app)
      .post('/auth/change-password')
      .set('Cookie', `accessToken=${token}`)
      .send({ currentPassword: 'oldpass123', newPassword: 'newpass456' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(store.updatePassword).toHaveBeenCalledWith('1', expect.any(String));
  });

  it('rejects wrong current password', async () => {
    const token = getAccessToken(users.get('1')!);
    const res = await request(app)
      .post('/auth/change-password')
      .set('Cookie', `accessToken=${token}`)
      .send({ currentPassword: 'wrongpass', newPassword: 'newpass456' });
    expect(res.status).toBe(401);
  });

  it('requires authentication', async () => {
    const res = await request(app)
      .post('/auth/change-password')
      .send({ currentPassword: 'old', newPassword: 'new' });
    expect(res.status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// Email verification
// ---------------------------------------------------------------------------

describe('Email verification flow', () => {
  let app: express.Application;
  let store: IUserStore;

  beforeAll(async () => { passwordHash = await passwordService.hash('pass'); });

  beforeEach(() => {
    users = new Map();
    users.set('1', { id: '1', email: 'user@test.com', password: passwordHash, isEmailVerified: false });
    store = createFullStore();
    app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config));
  });

  it('sends verification email', async () => {
    const token = getAccessToken(users.get('1')!);
    const res = await request(app)
      .post('/auth/send-verification-email')
      .set('Cookie', `accessToken=${token}`)
      .send({});
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(store.updateEmailVerificationToken).toHaveBeenCalledWith('1', expect.any(String), expect.any(Date));
    expect(config.email!.sendVerificationEmail).toHaveBeenCalled();
  });

  it('rejects re-sending if already verified', async () => {
    users.get('1')!.isEmailVerified = true;
    const token = getAccessToken(users.get('1')!);
    const res = await request(app)
      .post('/auth/send-verification-email')
      .set('Cookie', `accessToken=${token}`)
      .send({});
    expect(res.status).toBe(400);
  });

  it('verifies email with valid token', async () => {
    const user = users.get('1')!;
    user.emailVerificationToken = 'valid-token-abc';
    user.emailVerificationTokenExpiry = new Date(Date.now() + 3600_000);
    const res = await request(app)
      .get('/auth/verify-email?token=valid-token-abc');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(store.updateEmailVerified).toHaveBeenCalledWith('1', true);
  });

  it('rejects expired verification token', async () => {
    const user = users.get('1')!;
    user.emailVerificationToken = 'expired-token';
    user.emailVerificationTokenExpiry = new Date(Date.now() - 1000);
    const res = await request(app).get('/auth/verify-email?token=expired-token');
    expect(res.status).toBe(400);
  });

  it('rejects invalid verification token', async () => {
    const res = await request(app).get('/auth/verify-email?token=no-such-token');
    expect(res.status).toBe(400);
  });

  it('returns 400 when token param is missing', async () => {
    const res = await request(app).get('/auth/verify-email');
    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// Change email
// ---------------------------------------------------------------------------

describe('Change email flow', () => {
  let app: express.Application;
  let store: IUserStore;

  beforeAll(async () => { passwordHash = await passwordService.hash('pass'); });

  beforeEach(() => {
    users = new Map();
    users.set('1', { id: '1', email: 'old@test.com', password: passwordHash });
    store = createFullStore();
    app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config));
  });

  it('requests email change and sends verification to new address', async () => {
    const token = getAccessToken(users.get('1')!);
    const res = await request(app)
      .post('/auth/change-email/request')
      .set('Cookie', `accessToken=${token}`)
      .send({ newEmail: 'new@test.com' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(store.updateEmailChangeToken).toHaveBeenCalledWith('1', 'new@test.com', expect.any(String), expect.any(Date));
    expect(config.email!.sendVerificationEmail).toHaveBeenCalledWith('new@test.com', expect.any(String), expect.any(String), undefined);
  });

  it('rejects if new email is already in use', async () => {
    users.set('2', { id: '2', email: 'taken@test.com' });
    const token = getAccessToken(users.get('1')!);
    const res = await request(app)
      .post('/auth/change-email/request')
      .set('Cookie', `accessToken=${token}`)
      .send({ newEmail: 'taken@test.com' });
    expect(res.status).toBe(409);
  });

  it('confirms email change with valid token', async () => {
    const user = users.get('1')!;
    user.pendingEmail = 'new@test.com';
    user.emailChangeToken = 'change-token-xyz';
    user.emailChangeTokenExpiry = new Date(Date.now() + 3600_000);
    const res = await request(app)
      .post('/auth/change-email/confirm')
      .send({ token: 'change-token-xyz' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(store.updateEmail).toHaveBeenCalledWith('1', 'new@test.com');
    expect(config.email!.sendEmailChanged).toHaveBeenCalledWith('old@test.com', 'new@test.com');
  });

  it('emits USER_EMAIL_CHANGED when email change is confirmed', async () => {
    const bus = new AuthEventBus();
    const events: string[] = [];
    const payloads: Array<Record<string, unknown>> = [];
    bus.onEvent('*', (payload) => {
      events.push(payload.event);
      payloads.push((payload.data ?? {}) as Record<string, unknown>);
    });

    const user = users.get('1')!;
    user.pendingEmail = 'new@test.com';
    user.emailChangeToken = 'change-token-event';
    user.emailChangeTokenExpiry = new Date(Date.now() + 3600_000);

    const eventApp = express();
    eventApp.use(express.json());
    eventApp.use('/auth', createAuthRouter(store, config, { eventBus: bus }));

    const res = await request(eventApp)
      .post('/auth/change-email/confirm')
      .send({ token: 'change-token-event' });

    expect(res.status).toBe(200);
    expect(events).toContain(AuthEventNames.USER_EMAIL_CHANGED);
    expect(payloads).toContainEqual(expect.objectContaining({ oldEmail: 'old@test.com', newEmail: 'new@test.com' }));
  });

  it('rejects expired email-change token', async () => {
    const user = users.get('1')!;
    user.pendingEmail = 'new@test.com';
    user.emailChangeToken = 'expired-change-token';
    user.emailChangeTokenExpiry = new Date(Date.now() - 1000);
    const res = await request(app)
      .post('/auth/change-email/confirm')
      .send({ token: 'expired-change-token' });
    expect(res.status).toBe(400);
  });

  it('rejects invalid email-change token', async () => {
    const res = await request(app).post('/auth/change-email/confirm').send({ token: 'bad-token' });
    expect(res.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// Admin router
// ---------------------------------------------------------------------------

function createAdminStores() {
  const adminUsers = new Map<string, BaseUser>([
    ['1', { id: '1', email: 'alice@test.com', role: 'admin', isEmailVerified: true }],
    ['2', { id: '2', email: 'bob@test.com', role: 'user', isEmailVerified: false }],
  ]);

  const userStore: IUserStore = {
    findByEmail: vi.fn(),
    findById: vi.fn((id) => Promise.resolve(adminUsers.get(id as string) ?? null)),
    create: vi.fn(),
    updateRefreshToken: vi.fn(), updateResetToken: vi.fn(), updatePassword: vi.fn(),
    updateTotpSecret: vi.fn(), updateMagicLinkToken: vi.fn(), updateSmsCode: vi.fn(),
    updateLastLogin: vi.fn(),
    listUsers: vi.fn((limit, offset) => Promise.resolve([...adminUsers.values()].slice(offset, offset + limit))),
  };

  const sessionRecords = new Map<string, SessionInfo>([
    ['h1', { sessionHandle: 'h1', userId: '1', createdAt: new Date(), expiresAt: new Date(Date.now() + 86400_000), ipAddress: '127.0.0.1' }],
  ]);
  const sessionStore: ISessionStore = {
    createSession: vi.fn(), getSession: vi.fn(), getSessionsForUser: vi.fn(),
    updateSessionLastActive: vi.fn(),
    revokeSession: vi.fn((h) => { sessionRecords.delete(h); return Promise.resolve(); }),
    revokeAllSessionsForUser: vi.fn(),
    getAllSessions: vi.fn((limit, offset) => Promise.resolve([...sessionRecords.values()].slice(offset, offset + limit))),
  };

  const rolePerms = new Map<string, Set<string>>([
    ['admin', new Set(['users:read', 'users:delete'])],
    ['viewer', new Set(['users:read'])],
  ]);
  const userRoles = new Map<string, Set<string>>();
  const rbacStore: IRolesPermissionsStore = {
    addRoleToUser: vi.fn((userId, role) => { if (!userRoles.has(userId)) userRoles.set(userId, new Set()); userRoles.get(userId)!.add(role); return Promise.resolve(); }),
    removeRoleFromUser: vi.fn((userId, role) => { userRoles.get(userId)?.delete(role); return Promise.resolve(); }),
    getRolesForUser: vi.fn((userId) => Promise.resolve([...(userRoles.get(userId) ?? [])])),
    createRole: vi.fn((name, perms) => { rolePerms.set(name, new Set(perms)); return Promise.resolve(); }),
    deleteRole: vi.fn((name) => { rolePerms.delete(name); return Promise.resolve(); }),
    addPermissionToRole: vi.fn(), removePermissionFromRole: vi.fn(),
    getPermissionsForRole: vi.fn((name) => Promise.resolve([...(rolePerms.get(name) ?? [])])),
    getPermissionsForUser: vi.fn(), userHasPermission: vi.fn(),
    getAllRoles: vi.fn(() => Promise.resolve([...rolePerms.keys()])),
  };

  const tenantRecords = new Map<string, Tenant>([
    ['t1', { id: 't1', name: 'Acme Corp', isActive: true }],
  ]);
  const tenantMemberships = new Map<string, Set<string>>();
  const tenantStore: ITenantStore = {
    createTenant: vi.fn((data) => {
      const t: Tenant = { id: `t${tenantRecords.size + 2}`, ...data };
      tenantRecords.set(t.id, t);
      return Promise.resolve(t);
    }),
    getTenantById: vi.fn(), updateTenant: vi.fn(),
    deleteTenant: vi.fn((id) => { tenantRecords.delete(id); return Promise.resolve(); }),
    getAllTenants: vi.fn(() => Promise.resolve([...tenantRecords.values()])),
    associateUserWithTenant: vi.fn((userId, tenantId) => { if (!tenantMemberships.has(tenantId)) tenantMemberships.set(tenantId, new Set()); tenantMemberships.get(tenantId)!.add(userId); return Promise.resolve(); }),
    disassociateUserFromTenant: vi.fn((userId, tenantId) => { tenantMemberships.get(tenantId)?.delete(userId); return Promise.resolve(); }),
    getTenantsForUser: vi.fn(),
    getUsersForTenant: vi.fn((tenantId) => Promise.resolve([...(tenantMemberships.get(tenantId) ?? [])])),
  };

  const metadataStore = new Map<string, Record<string, unknown>>();
  const userMetadataStore: IUserMetadataStore = {
    getMetadata: vi.fn((userId) => Promise.resolve(metadataStore.get(userId) ?? {})),
    updateMetadata: vi.fn((userId, data) => { metadataStore.set(userId, { ...(metadataStore.get(userId) ?? {}), ...data }); return Promise.resolve(); }),
    clearMetadata: vi.fn((userId) => { metadataStore.delete(userId); return Promise.resolve(); }),
  };

  const linkedAccountsData = new Map<string, LinkedAccount[]>([
    ['1', [{ provider: 'google', providerAccountId: 'g123', email: 'alice@gmail.com', name: 'Alice' }]],
    ['2', [{ provider: 'github', providerAccountId: 'gh456' }, { provider: 'google', providerAccountId: 'g789' }]],
  ]);
  const linkedAccountsStore: ILinkedAccountsStore = {
    getLinkedAccounts: vi.fn((userId) => Promise.resolve(linkedAccountsData.get(userId) ?? [])),
    linkAccount: vi.fn(),
    unlinkAccount: vi.fn(),
    findUserByProviderAccount: vi.fn(),
  };

  return { userStore, sessionStore, rbacStore, tenantStore, userMetadataStore, linkedAccountsStore };
}

describe('Admin Router', () => {
  const ADMIN_SECRET = 'super-secret-admin-key';
  let app: express.Application;
  let stores: ReturnType<typeof createAdminStores>;

  beforeEach(() => {
    stores = createAdminStores();
    app = express();
    app.use(express.json());
    app.use('/admin', createAdminRouter(stores.userStore, {
      adminSecret: ADMIN_SECRET,
      sessionStore: stores.sessionStore,
      rbacStore: stores.rbacStore,
      tenantStore: stores.tenantStore,
      userMetadataStore: stores.userMetadataStore,
      linkedAccountsStore: stores.linkedAccountsStore,
    }));
  });

  it('GET /admin serves the HTML UI', async () => {
    const res = await request(app).get('/admin/');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/html/);
    expect(res.text).toContain('awesome-node-auth Admin');
  });

  it('GET /admin/api/ping returns 401 without auth', async () => {
    const res = await request(app).get('/admin/api/ping');
    expect(res.status).toBe(401);
  });

  it('GET /admin/api/ping returns 403 with wrong secret', async () => {
    const res = await request(app).get('/admin/api/ping').set('Authorization', 'Bearer wrong');
    expect(res.status).toBe(403);
  });

  it('GET /admin/api/ping succeeds with correct secret', async () => {
    const res = await request(app).get('/admin/api/ping').set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.features.sessions).toBe(true);
    expect(res.body.features.roles).toBe(true);
    expect(res.body.features.tenants).toBe(true);
  });

  it('GET /admin/api/users lists users', async () => {
    const res = await request(app).get('/admin/api/users?limit=10&offset=0').set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(res.body.users).toHaveLength(2);
    // No sensitive fields exposed
    const u = res.body.users[0];
    expect(u.password).toBeUndefined();
    expect(u.refreshToken).toBeUndefined();
  });

  it('GET /admin/api/users/:id returns user', async () => {
    const res = await request(app).get('/admin/api/users/1').set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(res.body.email).toBe('alice@test.com');
  });

  it('GET /admin/api/sessions lists sessions', async () => {
    const res = await request(app).get('/admin/api/sessions').set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(res.body.sessions).toHaveLength(1);
  });

  it('DELETE /admin/api/sessions/:handle revokes a session', async () => {
    const res = await request(app).delete('/admin/api/sessions/h1').set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(stores.sessionStore.revokeSession).toHaveBeenCalled();
  });

  it('GET /admin/api/roles lists roles with permissions', async () => {
    const res = await request(app).get('/admin/api/roles').set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    const adminRole = res.body.roles.find((r: { name: string }) => r.name === 'admin');
    expect(adminRole).toBeDefined();
    expect(adminRole.permissions).toContain('users:delete');
  });

  it('POST /admin/api/roles creates a role', async () => {
    const res = await request(app)
      .post('/admin/api/roles')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`)
      .send({ name: 'editor', permissions: ['posts:write'] });
    expect(res.status).toBe(200);
    expect(stores.rbacStore.createRole).toHaveBeenCalledWith('editor', ['posts:write']);
  });

  it('DELETE /admin/api/roles/:name deletes a role', async () => {
    const res = await request(app).delete('/admin/api/roles/viewer').set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(stores.rbacStore.deleteRole).toHaveBeenCalledWith('viewer');
  });

  it('GET /admin/api/tenants lists tenants', async () => {
    const res = await request(app).get('/admin/api/tenants').set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(res.body.tenants).toHaveLength(1);
    expect(res.body.tenants[0].name).toBe('Acme Corp');
  });

  it('POST /admin/api/tenants creates a tenant', async () => {
    const res = await request(app)
      .post('/admin/api/tenants')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`)
      .send({ name: 'Widgets Inc' });
    expect(res.status).toBe(200);
    expect(stores.tenantStore.createTenant).toHaveBeenCalledWith({ name: 'Widgets Inc', isActive: true });
  });

  it('DELETE /admin/api/tenants/:id deletes a tenant', async () => {
    const res = await request(app).delete('/admin/api/tenants/t1').set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(stores.tenantStore.deleteTenant).toHaveBeenCalledWith('t1');
  });

  it('GET /admin/api/users/:id/metadata returns empty object by default', async () => {
    const res = await request(app)
      .get('/admin/api/users/1/metadata')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({});
  });

  it('PUT /admin/api/users/:id/metadata saves metadata', async () => {
    const res = await request(app)
      .put('/admin/api/users/1/metadata')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`)
      .send({ plan: 'pro', score: 42 });
    expect(res.status).toBe(200);
    expect(stores.userMetadataStore.updateMetadata).toHaveBeenCalledWith('1', { plan: 'pro', score: 42 });
  });

  it('GET /admin/api/users/:id/metadata reflects saved metadata', async () => {
    await request(app)
      .put('/admin/api/users/1/metadata')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`)
      .send({ plan: 'enterprise' });
    const res = await request(app)
      .get('/admin/api/users/1/metadata')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(res.body.plan).toBe('enterprise');
  });

  it('GET /admin/api/users/:id/roles returns user roles', async () => {
    const res = await request(app).get('/admin/api/users/1/roles').set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.roles)).toBe(true);
  });

  it('POST /admin/api/users/:id/roles assigns a role to a user', async () => {
    const res = await request(app)
      .post('/admin/api/users/1/roles')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`)
      .send({ role: 'admin' });
    expect(res.status).toBe(200);
    expect(stores.rbacStore.addRoleToUser).toHaveBeenCalledWith('1', 'admin', undefined);
  });

  it('DELETE /admin/api/users/:id/roles/:role removes a role from a user', async () => {
    const res = await request(app)
      .delete('/admin/api/users/1/roles/admin')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(stores.rbacStore.removeRoleFromUser).toHaveBeenCalledWith('1', 'admin');
  });

  it('GET /admin/api/tenants/:id/users lists tenant members', async () => {
    const res = await request(app)
      .get('/admin/api/tenants/t1/users')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.userIds)).toBe(true);
  });

  it('POST /admin/api/tenants/:id/users adds a user to a tenant', async () => {
    const res = await request(app)
      .post('/admin/api/tenants/t1/users')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`)
      .send({ userId: '1' });
    expect(res.status).toBe(200);
    expect(stores.tenantStore.associateUserWithTenant).toHaveBeenCalledWith('1', 't1');
  });

  it('DELETE /admin/api/tenants/:id/users/:userId removes a user from a tenant', async () => {
    const res = await request(app)
      .delete('/admin/api/tenants/t1/users/1')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(stores.tenantStore.disassociateUserFromTenant).toHaveBeenCalledWith('1', 't1');
  });

  it('GET /admin/api/ping reports linkedAccounts feature as true when store is provided', async () => {
    const res = await request(app).get('/admin/api/ping').set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(res.body.features.linkedAccounts).toBe(true);
  });

  it('GET /admin/api/users/:id/linked-accounts returns linked accounts', async () => {
    const res = await request(app)
      .get('/admin/api/users/1/linked-accounts')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(res.body.linkedAccounts).toHaveLength(1);
    expect(res.body.linkedAccounts[0].provider).toBe('google');
    expect(stores.linkedAccountsStore.getLinkedAccounts).toHaveBeenCalledWith('1');
  });

  it('GET /admin/api/users/:id/linked-accounts returns empty array when no accounts linked', async () => {
    const res = await request(app)
      .get('/admin/api/users/99/linked-accounts')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(res.body.linkedAccounts).toHaveLength(0);
  });

  it('GET /admin/api/users/:id/linked-accounts returns 401 without auth', async () => {
    const res = await request(app).get('/admin/api/users/1/linked-accounts');
    expect(res.status).toBe(401);
  });

  it('GET /admin/api/users/:id/linked-accounts returns 404 when store not configured', async () => {
    const appNoLinked = express();
    appNoLinked.use(express.json());
    appNoLinked.use('/admin', createAdminRouter(stores.userStore, { adminSecret: ADMIN_SECRET }));
    const res = await request(appNoLinked)
      .get('/admin/api/users/1/linked-accounts')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(404);
  });

  it('GET /admin HTML includes featLinkedAccounts=true when store is provided', async () => {
    const res = await request(app).get('/admin/');
    expect(res.status).toBe(200);
    expect(res.text).toContain('"featLinkedAccounts":true');
  });

  it('GET /admin HTML includes featLinkedAccounts=false when store is not provided', async () => {
    const appNoLinked = express();
    appNoLinked.use(express.json());
    appNoLinked.use('/admin', createAdminRouter(stores.userStore, { adminSecret: ADMIN_SECRET }));
    const res = await request(appNoLinked).get('/admin/');
    expect(res.status).toBe(200);
    expect(res.text).toContain('"featLinkedAccounts":false');
  });
});

// ---------------------------------------------------------------------------
// 2FA enforcement – login
// ---------------------------------------------------------------------------

describe('Login with require2FA flag', () => {
  let app: express.Application;
  let store: ReturnType<typeof createFullStore>;

  beforeAll(async () => { passwordHash = await passwordService.hash('pass'); });

  beforeEach(() => {
    users = new Map();
    store = createFullStore();
    app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config));
  });

  it('blocks login with 2FA_SETUP_REQUIRED when require2FA=true and no 2FA method available', async () => {
    users.set('1', { id: '1', email: 'user@test.com', password: passwordHash, require2FA: true, isTotpEnabled: false });
    const res = await request(app).post('/auth/login').send({ email: 'user@test.com', password: 'pass' });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('2FA_SETUP_REQUIRED');
    expect(res.body.requires2FASetup).toBe(true);
    expect(res.body.tempToken).toBeDefined();
  });

  it('allows login normally when require2FA=true and 2FA is already enabled', async () => {
    users.set('1', { id: '1', email: 'user@test.com', password: passwordHash, require2FA: true, isTotpEnabled: true, totpSecret: 'secret' });
    const res = await request(app).post('/auth/login').send({ email: 'user@test.com', password: 'pass' });
    // Should go to the 2FA challenge step, not the setup block
    expect(res.status).toBe(200);
    expect(res.body.requiresTwoFactor).toBe(true);
    expect(res.body.requires2FASetup).toBeUndefined();
  });

  it('offers magic-link as 2FA method when require2FA=true and only email is configured', async () => {
    users.set('1', { id: '1', email: 'user@test.com', password: passwordHash, require2FA: true, isTotpEnabled: false });
    const configWithMagicLink: AuthConfig = {
      ...config,
      email: { ...config.email, sendMagicLink: vi.fn().mockResolvedValue(undefined) },
    };
    const appWithMagicLink = express();
    appWithMagicLink.use(express.json());
    appWithMagicLink.use('/auth', createAuthRouter(store, configWithMagicLink));
    const res = await request(appWithMagicLink).post('/auth/login').send({ email: 'user@test.com', password: 'pass' });
    expect(res.status).toBe(200);
    expect(res.body.requiresTwoFactor).toBe(true);
    expect(res.body.available2faMethods).toContain('magic-link');
    expect(res.body.available2faMethods).not.toContain('totp');
  });

  it('allows normal login when require2FA is not set', async () => {
    users.set('1', { id: '1', email: 'user@test.com', password: passwordHash });
    const res = await request(app).post('/auth/login').send({ email: 'user@test.com', password: 'pass' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Email verification modes
// ---------------------------------------------------------------------------

describe('Email verification modes', () => {
  let store: ReturnType<typeof createFullStore>;

  beforeAll(async () => { passwordHash = await passwordService.hash('pass'); });

  beforeEach(() => {
    users = new Map();
    store = createFullStore();
  });

  it('strict mode blocks unverified email', async () => {
    users.set('1', { id: '1', email: 'user@test.com', password: passwordHash, isEmailVerified: false });
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, { ...config, emailVerificationMode: 'strict' }));
    const res = await request(app).post('/auth/login').send({ email: 'user@test.com', password: 'pass' });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('EMAIL_NOT_VERIFIED');
  });

  it('strict mode allows verified email', async () => {
    users.set('1', { id: '1', email: 'user@test.com', password: passwordHash, isEmailVerified: true });
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, { ...config, emailVerificationMode: 'strict' }));
    const res = await request(app).post('/auth/login').send({ email: 'user@test.com', password: 'pass' });
    expect(res.status).toBe(200);
  });

  it('legacy requireEmailVerification:true is equivalent to strict mode', async () => {
    users.set('1', { id: '1', email: 'user@test.com', password: passwordHash, isEmailVerified: false });
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, { ...config, requireEmailVerification: true }));
    const res = await request(app).post('/auth/login').send({ email: 'user@test.com', password: 'pass' });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('EMAIL_NOT_VERIFIED');
  });

  it('lazy mode allows unverified email within grace period (no deadline set)', async () => {
    users.set('1', { id: '1', email: 'user@test.com', password: passwordHash, isEmailVerified: false });
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, { ...config, emailVerificationMode: 'lazy' }));
    const res = await request(app).post('/auth/login').send({ email: 'user@test.com', password: 'pass' });
    expect(res.status).toBe(200);
  });

  it('lazy mode blocks unverified email after deadline has passed', async () => {
    users.set('1', {
      id: '1',
      email: 'user@test.com',
      password: passwordHash,
      isEmailVerified: false,
      emailVerificationDeadline: new Date(Date.now() - 1000), // expired
    });
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, { ...config, emailVerificationMode: 'lazy' }));
    const res = await request(app).post('/auth/login').send({ email: 'user@test.com', password: 'pass' });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('EMAIL_VERIFICATION_REQUIRED');
  });

  it('none mode always allows login regardless of verification status', async () => {
    users.set('1', { id: '1', email: 'user@test.com', password: passwordHash, isEmailVerified: false });
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, { ...config, emailVerificationMode: 'none' }));
    const res = await request(app).post('/auth/login').send({ email: 'user@test.com', password: 'pass' });
    expect(res.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// 2FA Policy – admin batch endpoint
// ---------------------------------------------------------------------------

describe('Admin 2FA Policy endpoint', () => {
  const ADMIN_SECRET = 'secret';
  let app: express.Application;
  let userMap: Map<string, BaseUser>;

  function createStoreWith2FAPolicy() {
    userMap = new Map<string, BaseUser>([
      ['1', { id: '1', email: 'a@test.com' }],
      ['2', { id: '2', email: 'b@test.com' }],
    ]);
    const store = {
      findByEmail: vi.fn(),
      findById: vi.fn((id: string) => Promise.resolve(userMap.get(id) ?? null)),
      create: vi.fn(),
      updateRefreshToken: vi.fn(),
      updateResetToken: vi.fn(),
      updatePassword: vi.fn(),
      updateTotpSecret: vi.fn(),
      updateMagicLinkToken: vi.fn(),
      updateSmsCode: vi.fn(),
      listUsers: vi.fn((_limit: number, _offset: number) => Promise.resolve([...userMap.values()])),
      updateRequire2FA: vi.fn((id: string, required: boolean) => {
        const u = userMap.get(id);
        if (u) u.require2FA = required;
        return Promise.resolve();
      }),
    };
    return store;
  }

  beforeEach(() => {
    const store = createStoreWith2FAPolicy();
    app = express();
    app.use(express.json());
    app.use('/admin', createAdminRouter(store as any, { adminSecret: ADMIN_SECRET }));
  });

  it('POST /admin/api/2fa-policy enables require2FA for all users', async () => {
    const res = await request(app)
      .post('/admin/api/2fa-policy')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`)
      .send({ required: true });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.updated).toBe(2);
    expect([...userMap.values()].every(u => u.require2FA === true)).toBe(true);
  });

  it('POST /admin/api/2fa-policy disables require2FA for all users', async () => {
    // Pre-set require2FA on all users
    userMap.forEach(u => { u.require2FA = true; });
    const res = await request(app)
      .post('/admin/api/2fa-policy')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`)
      .send({ required: false });
    expect(res.status).toBe(200);
    expect(res.body.updated).toBe(2);
    expect([...userMap.values()].every(u => u.require2FA === false)).toBe(true);
  });

  it('POST /admin/api/2fa-policy returns 400 when required is not boolean', async () => {
    const res = await request(app)
      .post('/admin/api/2fa-policy')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`)
      .send({ required: 'yes' });
    expect(res.status).toBe(400);
  });

  it('POST /admin/api/2fa-policy returns 501 when updateRequire2FA is not implemented', async () => {
    // Use a store without updateRequire2FA
    const storeWithout = {
      findByEmail: vi.fn(), findById: vi.fn(), create: vi.fn(),
      updateRefreshToken: vi.fn(), updateResetToken: vi.fn(), updatePassword: vi.fn(),
      updateTotpSecret: vi.fn(), updateMagicLinkToken: vi.fn(), updateSmsCode: vi.fn(),
      listUsers: vi.fn(() => Promise.resolve([])),
    };
    const app2 = express();
    app2.use(express.json());
    app2.use('/admin', createAdminRouter(storeWithout as any, { adminSecret: ADMIN_SECRET }));
    const res = await request(app2)
      .post('/admin/api/2fa-policy')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`)
      .send({ required: true });
    expect(res.status).toBe(501);
  });

  it('GET /admin/api/ping reports twoFAPolicy feature flag', async () => {
    const res = await request(app)
      .get('/admin/api/ping')
      .set('Authorization', `Bearer ${ADMIN_SECRET}`);
    expect(res.status).toBe(200);
    expect(res.body.features.twoFAPolicy).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// GET /me endpoint
// ---------------------------------------------------------------------------

describe('GET /auth/me - enhanced profile', () => {
  let app: express.Application;
  let store: IUserStore;

  beforeAll(async () => { passwordHash = await passwordService.hash('pass'); });

  beforeEach(() => {
    users = new Map();
    users.set('1', {
      id: '1',
      email: 'user@test.com',
      password: passwordHash,
      role: 'user',
    });
    store = createFullStore();
  });

  it('returns standard JWT claims (sub, email, role)', async () => {
    app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config));
    const token = getAccessToken(users.get('1')!);
    const res = await request(app)
      .get('/auth/me')
      .set('Cookie', `accessToken=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.sub).toBe('1');
    expect(res.body.email).toBe('user@test.com');
    expect(res.body.role).toBe('user');
    expect(res.body.loginProvider).toBe('local');
    //expect(res.body.loginProvider).toBeUndefined();
    // Sensitive fields must not be exposed
    // Extra user fields not in buildPayload must not be exposed by default
    expect(res.body.id).toBeUndefined();
    expect(res.body.firstName).toBeUndefined();
    expect(res.body.lastName).toBeUndefined();
    expect(res.body.phoneNumber).toBeUndefined();
    expect(res.body.password).toBeUndefined();
    expect(res.body.refreshToken).toBeUndefined();
    expect(res.body.totpSecret).toBeUndefined();
    expect(res.body.resetToken).toBeUndefined();
  });

  it('includes custom claims added via buildTokenPayload', async () => {
    app = express();
    app.use(express.json());
    const configWithCustomClaims = {
      ...config,
      buildTokenPayload: (user: BaseUser) => ({ tenantId: 'tenant-42', loginProvider: user.loginProvider ?? 'local' }),
    };
    app.use('/auth', createAuthRouter(store, configWithCustomClaims));
    const token = getAccessToken(users.get('1')!);
    const res = await request(app)
      .get('/auth/me')
      .set('Cookie', `accessToken=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.sub).toBe('1');
    expect(res.body.tenantId).toBe('tenant-42');
    expect(res.body.loginProvider).toBe('local');
  });

  it('includes metadata when metadataStore is provided', async () => {
    const metadataStore: IUserMetadataStore = {
      getMetadata: vi.fn().mockResolvedValue({ plan: 'pro', score: 99 }),
      updateMetadata: vi.fn(),
      clearMetadata: vi.fn(),
    };
    app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { metadataStore }));
    const token = getAccessToken(users.get('1')!);
    const res = await request(app)
      .get('/auth/me')
      .set('Cookie', `accessToken=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.metadata).toEqual({ plan: 'pro', score: 99 });
    expect(metadataStore.getMetadata).toHaveBeenCalledWith('1');
  });

  it('includes roles and permissions when rbacStore is provided', async () => {
    const rbacStore: IRolesPermissionsStore = {
      getRolesForUser: vi.fn().mockResolvedValue(['admin', 'editor']),
      getPermissionsForUser: vi.fn().mockResolvedValue(['users:read', 'posts:write']),
      addRoleToUser: vi.fn(), removeRoleFromUser: vi.fn(),
      createRole: vi.fn(), deleteRole: vi.fn(),
      addPermissionToRole: vi.fn(), removePermissionFromRole: vi.fn(),
      getPermissionsForRole: vi.fn(), userHasPermission: vi.fn(),
    };
    app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { rbacStore }));
    const token = getAccessToken(users.get('1')!);
    const res = await request(app)
      .get('/auth/me')
      .set('Cookie', `accessToken=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.roles).toEqual(['admin', 'editor']);
    expect(res.body.permissions).toEqual(['users:read', 'posts:write']);
  });

  it('returns 404 when user no longer exists', async () => {
    app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config));
    const token = tokenService.generateTokenPair({ sub: 'nonexistent', email: 'gone@test.com' }, config).accessToken;
    const res = await request(app)
      .get('/auth/me')
      .set('Cookie', `accessToken=${token}`);
    expect(res.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// POST /auth/register (optional endpoint)
// ---------------------------------------------------------------------------

describe('POST /auth/register', () => {
  let store: IUserStore;

  beforeAll(async () => { passwordHash = await passwordService.hash('pass'); });

  beforeEach(() => {
    users = new Map();
    store = createFullStore();
  });

  it('registers a new user when onRegister is provided', async () => {
    const app = express();
    app.use(express.json());
    const onRegister = vi.fn(async (data: Record<string, unknown>) => {
      const user: BaseUser = { id: 'new-1', email: data['email'] as string };
      users.set('new-1', user);
      return user;
    });
    app.use('/auth', createAuthRouter(store, config, { onRegister }));
    const res = await request(app)
      .post('/auth/register')
      .send({ email: 'new@test.com', password: 'mypass' });
    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.userId).toBe('new-1');
    expect(onRegister).toHaveBeenCalledWith({ email: 'new@test.com', password: 'mypass' }, config, expect.objectContaining({ onRegister }));
  });

  it('returns 404 when onRegister is not configured', async () => {
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config));
    const res = await request(app)
      .post('/auth/register')
      .send({ email: 'new@test.com', password: 'mypass' });
    expect(res.status).toBe(404);
  });

  it('uses the built-in register handler when defaultRegister is set', async () => {
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { defaultRegister: true }));
    const res = await request(app)
      .post('/auth/register')
      .send({ email: 'new@test.com', password: 'mypass' });
    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.userId).toBe('new-1');
  });

  it('returns 500 when onRegister throws', async () => {
    const app = express();
    app.use(express.json());
    const onRegister = vi.fn().mockRejectedValue(new Error('DB error'));
    app.use('/auth', createAuthRouter(store, config, { onRegister }));
    const res = await request(app)
      .post('/auth/register')
      .send({ email: 'bad@test.com', password: 'pass' });
    expect(res.status).toBe(500);
  });
});

// ---------------------------------------------------------------------------
// POST /auth/sessions/cleanup
// ---------------------------------------------------------------------------

describe('POST /auth/sessions/cleanup', () => {
  let store: IUserStore;

  beforeEach(() => {
    users = new Map();
    store = createFullStore();
  });

  it('returns deleted count when sessionStore has deleteExpiredSessions', async () => {
    const sessionStore = {
      createSession: vi.fn(), getSession: vi.fn(), getSessionsForUser: vi.fn(),
      updateSessionLastActive: vi.fn(), revokeSession: vi.fn(), revokeAllSessionsForUser: vi.fn(),
      deleteExpiredSessions: vi.fn().mockResolvedValue(5),
    };
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { sessionStore }));
    const res = await request(app).post('/auth/sessions/cleanup');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.deleted).toBe(5);
    expect(sessionStore.deleteExpiredSessions).toHaveBeenCalled();
  });

  it('returns 404 when sessionStore does not implement deleteExpiredSessions', async () => {
    const sessionStore = {
      createSession: vi.fn(), getSession: vi.fn(), getSessionsForUser: vi.fn(),
      updateSessionLastActive: vi.fn(), revokeSession: vi.fn(), revokeAllSessionsForUser: vi.fn(),
    };
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { sessionStore }));
    const res = await request(app).post('/auth/sessions/cleanup');
    expect(res.status).toBe(404);
  });

  it('returns 404 when sessionStore is not provided', async () => {
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config));
    const res = await request(app).post('/auth/sessions/cleanup');
    expect(res.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// DELETE /auth/account — self-service account deletion
// ---------------------------------------------------------------------------

describe('DELETE /auth/account', () => {
  let store: ReturnType<typeof createFullStore> & { deleteUser?: ReturnType<typeof vi.fn> };
  let passwordHash: string;
  let app: express.Application;

  beforeAll(async () => { passwordHash = await new PasswordService().hash('pass'); });

  beforeEach(() => {
    users = new Map();
    users.set('u1', { id: 'u1', email: 'del@test.com', password: passwordHash });
    store = { ...createFullStore(), deleteUser: vi.fn(() => Promise.resolve()) };
    app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config));
  });

  function getToken(userId: string, email: string) {
    return tokenService.generateTokenPair({ sub: userId, email }, config).accessToken;
  }

  it('returns 403 without auth', async () => {
    const res = await request(app).delete('/auth/account');
    expect(res.status).toBe(403);
  });

  it('deletes own account and clears cookies', async () => {
    const token = getToken('u1', 'del@test.com');
    const res = await request(app)
      .delete('/auth/account')
      .set('Cookie', `accessToken=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect((store as any)['deleteUser']).toHaveBeenCalledWith('u1');
  });

  it('falls back to clearing tokens when deleteUser is not implemented', async () => {
    const { deleteUser: _unused, ...storeWithoutDelete } = store;
    const fallbackApp = express();
    fallbackApp.use(express.json());
    fallbackApp.use('/auth', createAuthRouter(storeWithoutDelete as IUserStore, config));
    const token = getToken('u1', 'del@test.com');
    const res = await request(fallbackApp)
      .delete('/auth/account')
      .set('Cookie', `accessToken=${token}`);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(storeWithoutDelete.updateRefreshToken).toHaveBeenCalledWith('u1', null, null);
  });

  it('revokes all sessions via sessionStore when provided', async () => {
    const sessionStore: ISessionStore = {
      createSession: vi.fn(), getSession: vi.fn(), getSessionsForUser: vi.fn(),
      updateSessionLastActive: vi.fn(),
      revokeSession: vi.fn(),
      revokeAllSessionsForUser: vi.fn(() => Promise.resolve()),
    };
    const sessionApp = express();
    sessionApp.use(express.json());
    sessionApp.use('/auth', createAuthRouter(store, config, { sessionStore }));
    const token = getToken('u1', 'del@test.com');
    await request(sessionApp)
      .delete('/auth/account')
      .set('Cookie', `accessToken=${token}`);
    expect(sessionStore.revokeAllSessionsForUser).toHaveBeenCalledWith('u1');
  });

  it('clears metadata when metadataStore provided', async () => {
    const metadataStore: IUserMetadataStore = {
      getMetadata: vi.fn(), updateMetadata: vi.fn(),
      clearMetadata: vi.fn(() => Promise.resolve()),
    };
    const metaApp = express();
    metaApp.use(express.json());
    metaApp.use('/auth', createAuthRouter(store, config, { metadataStore }));
    const token = getToken('u1', 'del@test.com');
    await request(metaApp)
      .delete('/auth/account')
      .set('Cookie', `accessToken=${token}`);
    expect(metadataStore.clearMetadata).toHaveBeenCalledWith('u1');
  });
});

// ---------------------------------------------------------------------------
// Admin Router — Control tab (settings store) and new endpoints
// ---------------------------------------------------------------------------

describe('Admin Router — settingsStore and GET /api/users/:id/tenants', () => {
  const ADMIN_SECRET = 'admin-secret-ctrl';
  let app: express.Application;
  let settingsData: Record<string, unknown>;
  let settingsStore: any;
  let tenantStore: ITenantStore;
  let userStore: IUserStore;

  beforeEach(() => {
    settingsData = { requireEmailVerification: false, require2FA: false };
    settingsStore = {
      getSettings: vi.fn(() => Promise.resolve({ ...settingsData })),
      updateSettings: vi.fn((s) => { Object.assign(settingsData, s); return Promise.resolve(); }),
    } as any;

    const tenantRecords = new Map<string, Tenant>([['t1', { id: 't1', name: 'Acme', isActive: true }]]);
    const memberships = new Map<string, Set<string>>();
    tenantStore = {
      createTenant: vi.fn(), getTenantById: vi.fn(), updateTenant: vi.fn(),
      deleteTenant: vi.fn(), getAllTenants: vi.fn(() => Promise.resolve([...tenantRecords.values()])),
      associateUserWithTenant: vi.fn((uid, tid) => {
        if (!memberships.has(uid)) memberships.set(uid, new Set());
        memberships.get(uid)!.add(tid); return Promise.resolve();
      }),
      disassociateUserFromTenant: vi.fn(), getUsersForTenant: vi.fn(),
      getTenantsForUser: vi.fn((uid) => {
        const ids = [...(memberships.get(uid) ?? [])];
        return Promise.resolve(ids.map(id => tenantRecords.get(id)!).filter(Boolean));
      }),
    };

    const dbUsers = new Map<string, BaseUser>([
      ['1', { id: '1', email: 'alice@test.com' }],
      ['2', { id: '2', email: 'bob@test.com' }],
    ]);
    userStore = {
      findByEmail: vi.fn(), findById: vi.fn((id) => Promise.resolve(dbUsers.get(id as string) ?? null)),
      create: vi.fn(), updateRefreshToken: vi.fn(), updateResetToken: vi.fn(),
      updatePassword: vi.fn(), updateTotpSecret: vi.fn(), updateMagicLinkToken: vi.fn(), updateSmsCode: vi.fn(),
      updateLastLogin: vi.fn(),
      listUsers: vi.fn((limit, offset) => Promise.resolve([...dbUsers.values()].slice(offset, offset + limit))),
    };

    app = express();
    app.use(express.json());
    app.use('/admin', createAdminRouter(userStore, {
      adminSecret: ADMIN_SECRET,
      settingsStore,
      tenantStore,
    }));
  });

  function auth() { return { 'Authorization': `Bearer ${ADMIN_SECRET}` }; }

  it('GET /admin/api/ping reports control feature enabled', async () => {
    const res = await request(app).get('/admin/api/ping').set(auth());
    expect(res.status).toBe(200);
    expect(res.body.features.control).toBe(true);
  });

  it('GET /admin serves HTML with Control tab when settingsStore is provided', async () => {
    const res = await request(app).get('/admin/').set(auth());
    expect(res.status).toBe(200);
    expect(res.text).toContain('Control');
  });

  it('GET /admin/api/settings returns current settings', async () => {
    const res = await request(app).get('/admin/api/settings').set(auth());
    expect(res.status).toBe(200);
    expect(res.body.requireEmailVerification).toBe(false);
  });

  it('PUT /admin/api/settings updates settings', async () => {
    const res = await request(app)
      .put('/admin/api/settings')
      .set(auth())
      .send({ requireEmailVerification: true });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(settingsStore.updateSettings).toHaveBeenCalledWith({ requireEmailVerification: true });
  });

  it('GET /admin/api/settings returns 404 when settingsStore not configured', async () => {
    const appNoSettings = express();
    appNoSettings.use(express.json());
    appNoSettings.use('/admin', createAdminRouter(userStore, { adminSecret: ADMIN_SECRET }));
    const res = await request(appNoSettings).get('/admin/api/settings').set(auth());
    expect(res.status).toBe(404);
  });

  it('GET /admin/api/users/:id/tenants returns tenant IDs for a user', async () => {
    // First associate user with tenant
    await tenantStore.associateUserWithTenant('1', 't1');
    const res = await request(app).get('/admin/api/users/1/tenants').set(auth());
    expect(res.status).toBe(200);
    expect(res.body.tenantIds).toContain('t1');
  });

  it('GET /admin/api/users/:id/tenants returns 404 when tenantStore not configured', async () => {
    const appNoTenant = express();
    appNoTenant.use(express.json());
    appNoTenant.use('/admin', createAdminRouter(userStore, { adminSecret: ADMIN_SECRET }));
    const res = await request(appNoTenant).get('/admin/api/users/1/tenants').set(auth());
    expect(res.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// Admin Router — user filter
// ---------------------------------------------------------------------------

describe('Admin Router — user and session filter', () => {
  const ADMIN_SECRET = 'admin-filter-secret';
  let app: express.Application;

  beforeEach(() => {
    const dbUsers = new Map<string, BaseUser>([
      ['1', { id: '1', email: 'alice@example.com' }],
      ['2', { id: '2', email: 'bob@example.com' }],
      ['3', { id: '3', email: 'charlie@other.com' }],
    ]);
    const userStore: IUserStore = {
      findByEmail: vi.fn(), findById: vi.fn(),
      create: vi.fn(), updateRefreshToken: vi.fn(), updateResetToken: vi.fn(),
      updatePassword: vi.fn(), updateTotpSecret: vi.fn(), updateMagicLinkToken: vi.fn(), updateSmsCode: vi.fn(),
      updateLastLogin: vi.fn(),
      listUsers: vi.fn((limit, offset) => Promise.resolve([...dbUsers.values()].slice(offset, offset + limit))),
    };

    const sessionRecords: SessionInfo[] = [
      { sessionHandle: 'h1', userId: 'uid-alice', createdAt: new Date(), expiresAt: new Date(), ipAddress: '10.0.0.1' },
      { sessionHandle: 'h2', userId: 'uid-bob', createdAt: new Date(), expiresAt: new Date(), ipAddress: '192.168.1.1' },
    ];
    const sessionStore: ISessionStore = {
      createSession: vi.fn(), getSession: vi.fn(), getSessionsForUser: vi.fn(),
      updateSessionLastActive: vi.fn(), revokeSession: vi.fn(), revokeAllSessionsForUser: vi.fn(),
      getAllSessions: vi.fn((_limit, _offset) => Promise.resolve(sessionRecords)),
    };

    app = express();
    app.use(express.json());
    app.use('/admin', createAdminRouter(userStore, { adminSecret: ADMIN_SECRET, sessionStore }));
  });

  function auth() { return { 'Authorization': `Bearer ${ADMIN_SECRET}` }; }

  it('GET /admin/api/users?filter= returns only matching users', async () => {
    const res = await request(app).get('/admin/api/users?filter=example').set(auth());
    expect(res.status).toBe(200);
    expect(res.body.users).toHaveLength(2);
    expect(res.body.users.every((u: { email: string }) => u.email.includes('example'))).toBe(true);
  });

  it('GET /admin/api/users?filter= with no match returns empty array', async () => {
    const res = await request(app).get('/admin/api/users?filter=zzznomatch').set(auth());
    expect(res.status).toBe(200);
    expect(res.body.users).toHaveLength(0);
    expect(res.body.total).toBe(0);
  });

  it('GET /admin/api/sessions?filter= returns only sessions matching userId', async () => {
    const res = await request(app).get('/admin/api/sessions?filter=uid-alice').set(auth());
    expect(res.status).toBe(200);
    expect(res.body.sessions).toHaveLength(1);
    expect(res.body.sessions[0].userId).toBe('uid-alice');
  });
});

// ── Admin Router — session-based login (accessPolicy) ─────────────────────────
describe('Admin Router — session-based login cookie fixes', () => {
  // Minimal in-memory user store
  const loginUsers = new Map([
    ['u1', { id: 'u1', email: 'admin@test.com', password: '' as string, isAdmin: true }],
  ]);

  beforeAll(async () => {
    // Pre-hash the password for the admin user.
    // Cost factor 4 is the minimum permitted by bcryptjs and keeps tests fast
    // while still exercising the real hashing path. Never use below 10 in production.
    const bcrypt = await import('bcryptjs');
    loginUsers.get('u1')!.password = await bcrypt.hash('secret', 4);
  });

  const userStore: IUserStore = {
    findByEmail: vi.fn((email) => Promise.resolve(
      [...loginUsers.values()].find(u => u.email === email) as any ?? null,
    )),
    findById: vi.fn((id) => Promise.resolve(loginUsers.get(id as string) as any ?? null)),
    create: vi.fn(),
    updateRefreshToken: vi.fn(),
    updateLastLogin: vi.fn(),
    listUsers: vi.fn(() => Promise.resolve([])),
    deleteUser: vi.fn(),
  } as unknown as IUserStore;

  const JWT_SECRET = 'test-admin-jwt-secret';

  function makeApp(extraOptions: Record<string, unknown> = {}) {
    const app = express();
    app.use(express.json());
    // Note: no cookie-parser — the admin router handles raw Cookie header parsing.
    app.use('/admin', createAdminRouter(userStore, {
      accessPolicy: 'is-admin-flag',
      jwtSecret: JWT_SECRET,
      ...extraOptions,
    }));
    return app;
  }

  it('POST /admin/login returns 401 for wrong password', async () => {
    const app = makeApp();
    const res = await request(app)
      .post('/admin/login')
      .send({ email: 'admin@test.com', password: 'wrong' });
    expect(res.status).toBe(401);
  });

  it('POST /admin/login sets an HttpOnly cookie on success', async () => {
    const app = makeApp();
    const res = await request(app)
      .post('/admin/login')
      .send({ email: 'admin@test.com', password: 'secret' });
    expect(res.status).toBe(200);
    const setCookie: string[] = Array.isArray(res.headers['set-cookie'])
      ? res.headers['set-cookie']
      : [res.headers['set-cookie'] ?? ''];
    expect(setCookie.some(c => c.includes('HttpOnly'))).toBe(true);
  });

  it('POST /admin/login sets cookie name "accessToken" on HTTP (non-secure)', async () => {
    const app = makeApp();
    const res = await request(app)
      .post('/admin/login')
      .send({ email: 'admin@test.com', password: 'secret' });
    expect(res.status).toBe(200);
    const setCookie: string[] = Array.isArray(res.headers['set-cookie'])
      ? res.headers['set-cookie']
      : [res.headers['set-cookie'] ?? ''];
    // On HTTP the cookie should be plain 'accessToken' (no __Host- prefix)
    expect(setCookie.some(c => c.startsWith('accessToken='))).toBe(true);
    expect(setCookie.some(c => c.startsWith('__Host-') || c.startsWith('__Secure-'))).toBe(false);
  });

  it('POST /admin/login includes maxAge aligned with 24h JWT expiry', async () => {
    const app = makeApp();
    const res = await request(app)
      .post('/admin/login')
      .send({ email: 'admin@test.com', password: 'secret' });
    expect(res.status).toBe(200);
    const setCookie: string[] = Array.isArray(res.headers['set-cookie'])
      ? res.headers['set-cookie']
      : [res.headers['set-cookie'] ?? ''];
    const tokenCookie = setCookie.find(c => c.startsWith('accessToken=') || c.startsWith('__Host-accessToken='));
    expect(tokenCookie).toBeDefined();
    // Cookie must have Max-Age (or Expires) so it survives browser restart
    expect(tokenCookie!.toLowerCase()).toMatch(/max-age=|expires=/);
  });

  it('POST /admin/login cookie is readable by the guard on the next request', async () => {
    const app = makeApp();
    // 1. Login
    const loginRes = await request(app)
      .post('/admin/login')
      .send({ email: 'admin@test.com', password: 'secret' });
    expect(loginRes.status).toBe(200);
    const setCookie: string[] = Array.isArray(loginRes.headers['set-cookie'])
      ? loginRes.headers['set-cookie']
      : [loginRes.headers['set-cookie'] ?? ''];
    // 2. Use the cookie to access a protected endpoint
    const pingRes = await request(app)
      .get('/admin/api/ping')
      .set('Cookie', setCookie.map(c => c.split(';')[0]).join('; '));
    expect(pingRes.status).toBe(200);
  });

  it('POST /admin/logout clears the cookie with matching name', async () => {
    const app = makeApp();
    const loginRes = await request(app)
      .post('/admin/login')
      .send({ email: 'admin@test.com', password: 'secret' });
    const loginCookies: string[] = Array.isArray(loginRes.headers['set-cookie'])
      ? loginRes.headers['set-cookie']
      : [loginRes.headers['set-cookie'] ?? ''];

    const logoutRes = await request(app)
      .post('/admin/logout')
      .set('Cookie', loginCookies.map(c => c.split(';')[0]).join('; '));
    expect(logoutRes.status).toBe(200);
    const clearCookies: string[] = Array.isArray(logoutRes.headers['set-cookie'])
      ? logoutRes.headers['set-cookie']
      : [logoutRes.headers['set-cookie'] ?? ''];
    // The logout response should clear the same cookie name that was set during login
    const loginCookieName = loginCookies[0].split('=')[0];
    expect(clearCookies.some(c => c.startsWith(loginCookieName + '='))).toBe(true);
    // Max-Age=0 or Expires in the past signals deletion
    const clearCookie = clearCookies.find(c => c.startsWith(loginCookieName + '='))!;
    expect(clearCookie.toLowerCase()).toMatch(/max-age=0|expires=.*1970/);
  });

  it('POST /admin/login uses __Host-accessToken prefix when x-forwarded-proto is https', async () => {
    const app = makeApp();
    const res = await request(app)
      .post('/admin/login')
      .set('x-forwarded-proto', 'https')
      .send({ email: 'admin@test.com', password: 'secret' });
    expect(res.status).toBe(200);
    const setCookie: string[] = Array.isArray(res.headers['set-cookie'])
      ? res.headers['set-cookie']
      : [res.headers['set-cookie'] ?? ''];
    // On HTTPS with default path (/) and no domain, cookie must use __Host- prefix
    expect(setCookie.some(c => c.startsWith('__Host-accessToken='))).toBe(true);
    // __Host- requires Secure + Path=/
    const hostCookie = setCookie.find(c => c.startsWith('__Host-accessToken='))!;
    expect(hostCookie.toLowerCase()).toContain('secure');
    expect(hostCookie.toLowerCase()).toContain('path=/');
  });

  it('POST /admin/logout clears __Host-accessToken on HTTPS', async () => {
    const app = makeApp();
    const loginRes = await request(app)
      .post('/admin/login')
      .set('x-forwarded-proto', 'https')
      .send({ email: 'admin@test.com', password: 'secret' });
    const loginCookies: string[] = Array.isArray(loginRes.headers['set-cookie'])
      ? loginRes.headers['set-cookie']
      : [loginRes.headers['set-cookie'] ?? ''];

    const logoutRes = await request(app)
      .post('/admin/logout')
      .set('x-forwarded-proto', 'https')
      .set('Cookie', loginCookies.map(c => c.split(';')[0]).join('; '));
    expect(logoutRes.status).toBe(200);
    const clearCookies: string[] = Array.isArray(logoutRes.headers['set-cookie'])
      ? logoutRes.headers['set-cookie']
      : [logoutRes.headers['set-cookie'] ?? ''];
    expect(clearCookies.some(c => c.startsWith('__Host-accessToken='))).toBe(true);
  });
});
