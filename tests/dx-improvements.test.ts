import { beforeEach, describe, expect, it, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { AuthConfigurator } from '../src/auth-configurator';
import { createAdminRouter } from '../src/router/admin.router';
import { AuthConfig } from '../src/models/auth-config.model';
import { BaseUser } from '../src/models/user.model';
import { IUserStore } from '../src/interfaces/user-store.interface';
import { IRolesPermissionsStore } from '../src/interfaces/roles-permissions-store.interface';
import { PasswordService } from '../src/services/password.service';
import { TokenService } from '../src/services/token.service';
import { AuthEventBus } from '../src/events/auth-event-bus';
import { AuthEventNames } from '../src/events/auth-event-names';

const config: AuthConfig = {
  accessTokenSecret: 'dx-access-secret-very-long-and-secure',
  refreshTokenSecret: 'dx-refresh-secret-very-long-and-secure',
  accessTokenExpiresIn: '15m',
  refreshTokenExpiresIn: '7d',
};

const passwordService = new PasswordService();
const tokenService = new TokenService();

function makeUserStore(user: BaseUser): IUserStore & { update: ReturnType<typeof vi.fn> } {
  return {
    findByEmail: vi.fn().mockResolvedValue(user),
    findById: vi.fn().mockResolvedValue(user),
    create: vi.fn(),
    updateRefreshToken: vi.fn().mockResolvedValue(undefined),
    updateLastLogin: vi.fn().mockResolvedValue(undefined),
    updateResetToken: vi.fn().mockResolvedValue(undefined),
    updatePassword: vi.fn().mockResolvedValue(undefined),
    updateTotpSecret: vi.fn().mockResolvedValue(undefined),
    updateMagicLinkToken: vi.fn().mockResolvedValue(undefined),
    updateSmsCode: vi.fn().mockResolvedValue(undefined),
    listUsers: vi.fn().mockResolvedValue([user]),
    update: vi.fn().mockResolvedValue(undefined),
  };
}

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

describe('DX improvements', () => {
  let adminUser: BaseUser;

  beforeEach(async () => {
    adminUser = {
      id: 'admin-1',
      email: 'admin@test.com',
      password: await passwordService.hash('secret'),
      isAdmin: true,
    };
  });

  it('AuthConfigurator.buildAllRouters mounts /auth and /auth/admin with jwtSecret auto-filled', async () => {
    const userStore = makeUserStore(adminUser);
    const auth = new AuthConfigurator(config, userStore);
    const app = express();
    app.use(express.json());
    app.use(auth.buildAllRouters({
      admin: {
        accessPolicy: 'is-admin-flag',
      },
    }));

    const loginRes = await request(app)
      .post('/auth/login')
      .send({ email: 'admin@test.com', password: 'secret' });
    expect(loginRes.status).toBe(200);

    const pingRes = await request(app)
      .get('/auth/admin/api/ping')
      .set('Cookie', (loginRes.headers['set-cookie'] as string[]).map((cookie) => cookie.split(';')[0]).join('; '));
    expect(pingRes.status).toBe(200);
  });

  it('preloads roles before invoking admin accessPolicy', async () => {
    const userStore = makeUserStore(adminUser);
    const rbacStore: IRolesPermissionsStore = {
      addRoleToUser: vi.fn().mockResolvedValue(undefined),
      removeRoleFromUser: vi.fn().mockResolvedValue(undefined),
      getRolesForUser: vi.fn().mockResolvedValue(['admin', 'ops']),
      createRole: vi.fn().mockResolvedValue(undefined),
      deleteRole: vi.fn().mockResolvedValue(undefined),
      addPermissionToRole: vi.fn().mockResolvedValue(undefined),
      removePermissionFromRole: vi.fn().mockResolvedValue(undefined),
      getPermissionsForRole: vi.fn().mockResolvedValue([]),
      getPermissionsForUser: vi.fn().mockResolvedValue([]),
      userHasPermission: vi.fn().mockResolvedValue(true),
    };
    let receivedRoles: string[] = [];

    const app = express();
    app.use(express.json());
    app.use('/admin', createAdminRouter(userStore, {
      accessPolicy: async (user) => {
        receivedRoles = user.roles;
        return user.roles.includes('admin');
      },
      jwtSecret: config.accessTokenSecret,
      rbacStore,
      silent: true,
    }));

    const token = tokenService.generateTokenPair({ sub: adminUser.id, email: adminUser.email }, config).accessToken;
    const res = await request(app)
      .get('/admin/api/ping')
      .set('Cookie', `accessToken=${token}`);

    expect(res.status).toBe(200);
    expect(receivedRoles).toEqual(['admin', 'ops']);
  });

  it('promoteToAdmin and revokeAdmin use role/flag helpers and emit events', async () => {
    const userStore = makeUserStore(adminUser);
    const bus = new AuthEventBus();
    const events: string[] = [];
    bus.onEvent('*', (payload) => events.push(payload.event));
    const rbacStore: IRolesPermissionsStore = {
      addRoleToUser: vi.fn().mockResolvedValue(undefined),
      removeRoleFromUser: vi.fn().mockResolvedValue(undefined),
      getRolesForUser: vi.fn().mockResolvedValue([]),
      createRole: vi.fn().mockResolvedValue(undefined),
      deleteRole: vi.fn().mockResolvedValue(undefined),
      addPermissionToRole: vi.fn().mockResolvedValue(undefined),
      removePermissionFromRole: vi.fn().mockResolvedValue(undefined),
      getPermissionsForRole: vi.fn().mockResolvedValue([]),
      getPermissionsForUser: vi.fn().mockResolvedValue([]),
      userHasPermission: vi.fn().mockResolvedValue(false),
    };
    const auth = new AuthConfigurator(config, userStore, { eventBus: bus });

    await auth.promoteToAdmin('user-1', { rbacStore });
    await auth.promoteToAdmin('user-2', { method: 'flag' });
    await auth.revokeAdmin('user-1', { method: 'both', rbacStore });

    expect(rbacStore.createRole).toHaveBeenCalledWith('admin');
    expect(rbacStore.addRoleToUser).toHaveBeenCalledWith('user-1', 'admin');
    expect(userStore.update).toHaveBeenCalledWith('user-2', { isAdmin: true });
    expect(userStore.update).toHaveBeenCalledWith('user-1', { isAdmin: false });
    expect(rbacStore.removeRoleFromUser).toHaveBeenCalledWith('user-1', 'admin');
    expect(events).toContain(AuthEventNames.ROLE_ASSIGNED);
    expect(events).toContain(AuthEventNames.ROLE_REVOKED);
  });

  it('POST /users/:id/promote promotes through the admin router', async () => {
    const userStore = makeUserStore(adminUser);
    const rbacStore: IRolesPermissionsStore = {
      addRoleToUser: vi.fn().mockResolvedValue(undefined),
      removeRoleFromUser: vi.fn().mockResolvedValue(undefined),
      getRolesForUser: vi.fn().mockResolvedValue([]),
      createRole: vi.fn().mockResolvedValue(undefined),
      deleteRole: vi.fn().mockResolvedValue(undefined),
      addPermissionToRole: vi.fn().mockResolvedValue(undefined),
      removePermissionFromRole: vi.fn().mockResolvedValue(undefined),
      getPermissionsForRole: vi.fn().mockResolvedValue([]),
      getPermissionsForUser: vi.fn().mockResolvedValue([]),
      userHasPermission: vi.fn().mockResolvedValue(false),
    };
    const app = express();
    app.use(express.json());
    app.use('/admin', createAdminRouter(userStore, {
      accessPolicy: 'open',
      rbacStore,
      silent: true,
    }));

    const res = await request(app)
      .post('/admin/users/user-9/promote')
      .send({});

    expect(res.status).toBe(200);
    expect(rbacStore.createRole).toHaveBeenCalledWith('admin');
    expect(rbacStore.addRoleToUser).toHaveBeenCalledWith('user-9', 'admin');
  });

  it('POST /users/:id/promote refuses non-JSON bodies with 415 and assigns no role', async () => {
    const userStore = makeUserStore(adminUser);
    const rbacStore = makeRbacStore(['admin']);
    const app = express();
    app.use('/admin', createAdminRouter(userStore, {
      accessPolicy: (user) => user.roles.includes('admin'),
      jwtSecret: config.accessTokenSecret,
      rbacStore,
      silent: true,
    }));
    const token = tokenService.generateTokenPair({ sub: adminUser.id, email: adminUser.email }, config).accessToken;
    const promote = () => request(app).post('/admin/users/user-9/promote').set('Cookie', `accessToken=${token}`);

    const form = await promote().set('Content-Type', 'application/x-www-form-urlencoded').send('');
    const text = await promote().set('Content-Type', 'text/plain').send('{"method":"role"}');
    const noBody = await promote();
    for (const res of [form, text, noBody]) {
      expect(res.status).toBe(415);
      expect(res.body).toEqual({ error: 'Content-Type must be application/json' });
    }
    expect(rbacStore.createRole).not.toHaveBeenCalled();
    expect(rbacStore.addRoleToUser).not.toHaveBeenCalled();

    const json = await promote().send({});
    expect(json.status).toBe(200);
    expect(json.body).toEqual({ success: true, method: 'role' });
    expect(rbacStore.addRoleToUser).toHaveBeenCalledWith('user-9', 'admin');
  });
});
