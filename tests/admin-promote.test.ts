/**
 * POST <admin>/api/users/:id/promote, and its deprecated alias
 * POST <admin>/users/:id/promote: same chain (rateLimiter → guard →
 * requireJsonBody), same behaviour.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { RequestHandler } from 'express';
import request from 'supertest';
import { createAdminRouter } from '../src/router/admin.router';
import { TokenService } from '../src/services/token.service';
import { IRolesPermissionsStore } from '../src/interfaces/roles-permissions-store.interface';
import { InMemoryUserStore } from '../examples/in-memory-user-store';

const jwtSecret = 'admin-promote-secret-very-long-and-secure';
const tokenService = new TokenService();

function makeRbacStore(): IRolesPermissionsStore {
  const roles = new Map<string, string[]>();
  return {
    addRoleToUser: vi.fn(async (userId: string, role: string) => { roles.set(userId, [...(roles.get(userId) ?? []), role]); }),
    removeRoleFromUser: vi.fn(async () => undefined),
    getRolesForUser: vi.fn(async (userId: string) => roles.get(userId) ?? []),
    createRole: vi.fn(async () => undefined),
    deleteRole: vi.fn(async () => undefined),
    addPermissionToRole: vi.fn(async () => undefined),
    removePermissionFromRole: vi.fn(async () => undefined),
    getPermissionsForRole: vi.fn(async () => []),
    getPermissionsForUser: vi.fn(async () => []),
    userHasPermission: vi.fn(async () => false),
  };
}

describe.each([
  ['/admin/api/users/:id/promote', (id: string) => `/admin/api/users/${id}/promote`],
  ['/admin/users/:id/promote (deprecated alias)', (id: string) => `/admin/users/${id}/promote`],
])('POST %s', (_label, promotePath) => {
  let userStore: InMemoryUserStore & { update: (id: string, patch: object) => Promise<void> };
  let rbacStore: IRolesPermissionsStore;
  let rateLimiter: ReturnType<typeof vi.fn>;
  let app: express.Application;
  let adminToken: string;
  let targetId: string;

  beforeEach(async () => {
    const store = new InMemoryUserStore() as InMemoryUserStore & { update: (id: string, patch: object) => Promise<void> };
    store.update = async (id, patch) => { const u = await store.findById(id); if (u) Object.assign(u, patch); };
    userStore = store;
    const admin = await userStore.create({ email: 'ops@example.com', isAdmin: true });
    targetId = (await userStore.create({ email: 'target@example.com' })).id;
    adminToken = tokenService.generateTokenPair({ sub: admin.id, email: admin.email }, { accessTokenSecret: jwtSecret, refreshTokenSecret: `${jwtSecret}-r` }).accessToken;
    rbacStore = makeRbacStore();
    rateLimiter = vi.fn((_req, _res, next) => next());
    app = express();
    app.use('/admin', createAdminRouter(userStore, {
      accessPolicy: 'is-admin-flag',
      jwtSecret,
      rbacStore,
      rateLimiter: rateLimiter as unknown as RequestHandler,
      silent: true,
    }));
  });

  it('promotes by role with a JSON body (default method)', async () => {
    const res = await request(app).post(promotePath(targetId)).set('Authorization', `Bearer ${adminToken}`).send({});
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, method: 'role' });
    expect(rbacStore.createRole).toHaveBeenCalledWith('admin');
    expect(rbacStore.addRoleToUser).toHaveBeenCalledWith(targetId, 'admin');
    expect(rateLimiter).toHaveBeenCalledTimes(1);
  });

  it('promotes by flag', async () => {
    const res = await request(app).post(promotePath(targetId)).set('Authorization', `Bearer ${adminToken}`).send({ method: 'flag' });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, method: 'flag' });
    expect((await userStore.findById(targetId))?.isAdmin).toBe(true);
  });

  it('answers 400 to an unknown method and assigns nothing', async () => {
    const promote = () => request(app).post(promotePath(targetId)).set('Authorization', `Bearer ${adminToken}`);
    for (const method of ['Flag', 'ROLE', 'both', 'xyz', '', 123, true, ['flag'], { flag: true }]) {
      const res = await promote().send({ method });
      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'method must be "flag" or "role"' });
    }
    expect(rbacStore.createRole).not.toHaveBeenCalled();
    expect(rbacStore.addRoleToUser).not.toHaveBeenCalled();
    expect((await userStore.findById(targetId))?.isAdmin).toBeUndefined();
  });

  it('treats a null method as the default (role)', async () => {
    const res = await request(app).post(promotePath(targetId)).set('Authorization', `Bearer ${adminToken}`).send({ method: null });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true, method: 'role' });
    expect(rbacStore.addRoleToUser).toHaveBeenCalledWith(targetId, 'admin');
  });

  it('answers 401 without a session, after the rate limiter', async () => {
    const res = await request(app).post(promotePath(targetId)).send({});
    expect(res.status).toBe(401);
    expect(rateLimiter).toHaveBeenCalledTimes(1);
    expect(rbacStore.addRoleToUser).not.toHaveBeenCalled();
  });

  it('answers 415 to a body that is not JSON, and assigns nothing', async () => {
    const promote = () => request(app).post(promotePath(targetId)).set('Authorization', `Bearer ${adminToken}`);
    for (const res of [
      await promote().set('Content-Type', 'application/x-www-form-urlencoded').send(''),
      await promote().set('Content-Type', 'text/plain').send('{"method":"role"}'),
      await promote(),
    ]) {
      expect(res.status).toBe(415);
      expect(res.body).toEqual({ error: 'Content-Type must be application/json' });
    }
    expect(rbacStore.createRole).not.toHaveBeenCalled();
    expect(rbacStore.addRoleToUser).not.toHaveBeenCalled();
  });
});
