import { describe, it, expect, vi, beforeEach } from 'vitest';
import express, { Express } from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';
import jwt from 'jsonwebtoken';
import { createAdminRouter } from '../src/router/admin.router';
import { createAuthRouter } from '../src/router/auth.router';
import { IUserStore } from '../src/interfaces/user-store.interface';
import { IRolesPermissionsStore } from '../src/interfaces/roles-permissions-store.interface';
import { ISessionStore } from '../src/interfaces/session-store.interface';
import { ITenantStore } from '../src/interfaces/tenant-store.interface';
import { AuthConfig } from '../src/models/auth-config.model';
import { BaseUser } from '../src/models/user.model';

/*
 * Express decodes route parameters once.  Decoding them again made a value
 * containing a literal '%' throw URIError (500) and turned '%2541' into 'A'.
 * Each route below is called with `a%25b` (the value `a%b`) and `x%2541`
 * (the value `x%41`): the store must receive exactly those values.
 */

const secret = 'test-secret-route-params-decode-once-32ch';

const users = new Map<string, BaseUser>();
const userStore: IUserStore = {
  findById: async (id) => users.get(id) ?? null,
  findByEmail: async (email) => [...users.values()].find(u => u.email === email) ?? null,
  create: async (u) => ({ ...u, id: 'new' } as BaseUser),
  updateRefreshToken: async () => {},
  updateResetToken: async () => {},
  updatePassword: async () => {},
  updateTotpSecret: async () => {},
  updateMagicLinkToken: async () => {},
  updateSmsCode: async () => {},
} as IUserStore;

const config: AuthConfig = { accessTokenSecret: secret, refreshTokenSecret: `${secret}-refresh` };

const CASES: Array<{ encoded: string; value: string }> = [
  { encoded: 'a%25b', value: 'a%b' },
  { encoded: 'x%2541', value: 'x%41' },
];

describe('route params are decoded once (follow-up to #29)', () => {
  let rbacStore: IRolesPermissionsStore;
  let sessionStore: ISessionStore;
  let tenantStore: ITenantStore;
  let admin: Express;

  beforeEach(() => {
    rbacStore = {
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
    } as unknown as IRolesPermissionsStore;
    sessionStore = {
      createSession: vi.fn(),
      getSession: vi.fn(),
      getSessionsForUser: vi.fn().mockResolvedValue([]),
      updateSessionLastActive: vi.fn().mockResolvedValue(undefined),
      revokeSession: vi.fn().mockResolvedValue(undefined),
      revokeAllSessionsForUser: vi.fn().mockResolvedValue(undefined),
    } as unknown as ISessionStore;
    tenantStore = {
      createTenant: vi.fn(),
      getTenantById: vi.fn().mockResolvedValue(null),
      getAllTenants: vi.fn().mockResolvedValue([]),
      updateTenant: vi.fn().mockResolvedValue(undefined),
      deleteTenant: vi.fn().mockResolvedValue(undefined),
      associateUserWithTenant: vi.fn().mockResolvedValue(undefined),
      disassociateUserFromTenant: vi.fn().mockResolvedValue(undefined),
      getTenantsForUser: vi.fn().mockResolvedValue([]),
      getUsersForTenant: vi.fn().mockResolvedValue([]),
    } as unknown as ITenantStore;

    admin = express();
    admin.use(express.json());
    admin.use('/admin', createAdminRouter(userStore, {
      accessPolicy: 'open',
      jwtSecret: secret,
      rbacStore,
      sessionStore,
      tenantStore,
    }));
  });

  for (const { encoded, value } of CASES) {
    describe(`value ${JSON.stringify(value)} sent as ${encoded}`, () => {
      it('DELETE /admin/api/users/:id/roles/:role', async () => {
        const res = await request(await listen(admin)).delete(`/admin/api/users/u1/roles/${encoded}`);
        expect(res.status).toBe(200);
        expect(rbacStore.removeRoleFromUser).toHaveBeenCalledWith('u1', value);
      });

      it('DELETE /admin/api/sessions/:handle', async () => {
        const res = await request(await listen(admin)).delete(`/admin/api/sessions/${encoded}`);
        expect(res.status).toBe(200);
        expect(sessionStore.revokeSession).toHaveBeenCalledWith(value);
      });

      it('DELETE /admin/api/roles/:name', async () => {
        const res = await request(await listen(admin)).delete(`/admin/api/roles/${encoded}`);
        expect(res.status).toBe(200);
        expect(rbacStore.deleteRole).toHaveBeenCalledWith(value);
      });

      it('DELETE /admin/api/tenants/:id', async () => {
        const res = await request(await listen(admin)).delete(`/admin/api/tenants/${encoded}`);
        expect(res.status).toBe(200);
        expect(tenantStore.deleteTenant).toHaveBeenCalledWith(value);
      });

      it('GET /admin/api/tenants/:id/users', async () => {
        const res = await request(await listen(admin)).get(`/admin/api/tenants/${encoded}/users`);
        expect(res.status).toBe(200);
        expect(tenantStore.getUsersForTenant).toHaveBeenCalledWith(value);
      });

      it('POST /admin/api/tenants/:id/users', async () => {
        const res = await request(await listen(admin)).post(`/admin/api/tenants/${encoded}/users`).send({ userId: 'u1' });
        expect(res.status).toBe(200);
        expect(tenantStore.associateUserWithTenant).toHaveBeenCalledWith('u1', value);
      });

      it('DELETE /admin/api/tenants/:id/users/:userId (both params)', async () => {
        const res = await request(await listen(admin)).delete(`/admin/api/tenants/${encoded}/users/${encoded}`);
        expect(res.status).toBe(200);
        expect(tenantStore.disassociateUserFromTenant).toHaveBeenCalledWith(value, value);
      });

      it('POST /admin/api/users/:id/send-verification-email', async () => {
        const sent: string[] = [];
        users.clear();
        users.set(value, { id: value, email: 'p@example.com', isEmailVerified: false } as BaseUser);
        const cfg: AuthConfig = {
          ...config,
          email: { siteUrl: 'https://example.com', sendVerificationEmail: async (email) => { sent.push(email); } },
        };
        const store: IUserStore = {
          ...userStore,
          updateEmailVerificationToken: async () => {},
          updateEmailVerified: async () => {},
        } as IUserStore;
        const app = express();
        app.use('/admin', createAdminRouter(store, { accessPolicy: 'open', jwtSecret: secret, authConfig: cfg }));

        const res = await request(await listen(app)).post(`/admin/api/users/${encoded}/send-verification-email`);

        expect(res.status).toBe(200);
        expect(sent).toEqual(['p@example.com']);
      });

      it('DELETE /auth/sessions/:handle (user route)', async () => {
        vi.mocked(sessionStore.getSession).mockResolvedValue({ sessionHandle: value, userId: 'u1' } as never);
        const app = express();
        app.use(express.json());
        app.use('/auth', createAuthRouter(userStore, config, { sessionStore }));
        const token = jwt.sign({ sub: 'u1', email: 'u1@example.com', role: 'user' }, secret, { expiresIn: '1h' });

        const res = await request(await listen(app))
          .delete(`/auth/sessions/${encoded}`)
          .set('Authorization', `Bearer ${token}`);

        expect(res.status).toBe(200);
        expect(sessionStore.getSession).toHaveBeenCalledWith(value);
        expect(sessionStore.revokeSession).toHaveBeenCalledWith(value);
      });
    });
  }
});
