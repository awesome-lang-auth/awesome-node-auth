/**
 * Built-in register handler — `RouterOptions.defaultRegister`.
 *
 * The handler is opt-in (without `onRegister` or `defaultRegister`,
 * `POST /register` is not mounted, as in 1.9.0) and persists an allow-list of
 * fields only.  Tests tagged REGRESSION-REGISTER-MASS-ASSIGNMENT guard against
 * forwarding the raw request body to `IUserStore.create`.
 */
import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from 'vitest';
import express from 'express';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { createAuthRouter, RouterOptions } from '../src/router/auth.router';
import { AuthConfig } from '../src/models/auth-config.model';
import { IUserStore } from '../src/interfaces/user-store.interface';
import { PasswordService } from '../src/services/password.service';
import { InMemoryUserStore } from '../examples/in-memory-user-store';

const passwordService = new PasswordService();

const baseConfig: AuthConfig = {
  accessTokenSecret: 'register-test-access-secret-very-long-and-secure',
  refreshTokenSecret: 'register-test-refresh-secret-very-long-and-secure',
  accessTokenExpiresIn: '15m',
  refreshTokenExpiresIn: '7d',
};

function buildApp(store: IUserStore, options: RouterOptions = {}, config: AuthConfig = baseConfig) {
  const app = express();
  app.use(express.json());
  app.use('/auth', createAuthRouter(store, config, options));
  return app;
}

describe('built-in register handler (defaultRegister)', () => {
  let stderrSpy: MockInstance;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  it('REGRESSION-REGISTER-MASS-ASSIGNMENT: drops privileged fields from the body and leaves the existing user untouched', async () => {
    const store = new InMemoryUserStore();
    const existing = await store.create({
      email: 'victim@x.test',
      password: await passwordService.hash('victim-pass'),
      isEmailVerified: true,
    });
    const before = structuredClone(await store.findById(existing.id));
    const app = buildApp(store, { defaultRegister: true });

    const res = await request(app)
      .post('/auth/register')
      .send({
        email: 'eve@x.test',
        password: 'eve-pass-123',
        firstName: 'Eve',
        lastName: ['not', 'a', 'string'],
        id: existing.id,
        isAdmin: true,
        isEmailVerified: true,
        role: 'admin',
        roles: ['admin'],
        permissions: ['*'],
        loginProvider: 'google',
        providerAccountId: 'google-123',
        emailVerificationDeadline: '2999-01-01T00:00:00.000Z',
        emailVerificationToken: 'planted-verify',
        resetToken: 'planted-reset',
        magicLinkToken: 'planted-magic',
        accountLinkToken: 'planted-link',
        accountLinkPendingEmail: 'other@x.test',
        totpSecret: 'JBSWY3DPEHPK3PXP',
        isTotpEnabled: true,
        require2FA: false,
        phoneNumber: '+10000000000',
        tenantId: 'tenant-1',
        metadata: { plan: 'enterprise' },
      });

    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.userId).not.toBe(existing.id);

    // Only the allow-listed fields reach the store (the store adds `id`).
    const created = await store.findById(res.body.userId);
    expect(created).not.toBeNull();
    expect(Object.keys(created!).sort()).toEqual(['email', 'firstName', 'id', 'password']);
    expect(created!.email).toBe('eve@x.test');
    expect(created!.firstName).toBe('Eve');
    expect(await passwordService.compare('eve-pass-123', created!.password as string)).toBe(true);

    // The existing user is untouched.
    expect(await store.findById(existing.id)).toEqual(before);

    // The new account is a normal, unverified user with its own id.
    const login = await request(app)
      .post('/auth/login')
      .set('X-Auth-Strategy', 'bearer')
      .send({ email: 'eve@x.test', password: 'eve-pass-123' });
    expect(login.status).toBe(200);
    const claims = jwt.decode(login.body.accessToken as string) as Record<string, unknown>;
    expect(claims['sub']).toBe(created!.id);
    expect(claims['role']).toBeUndefined();
    expect(claims['isEmailVerified']).toBe(false);
    expect(claims['loginProvider']).toBe('local');
  });

  it('REGRESSION-REGISTER-MASS-ASSIGNMENT: without onRegister or defaultRegister, POST /register is not mounted (404)', async () => {
    const store = new InMemoryUserStore();
    const createSpy = vi.spyOn(store, 'create');
    const app = buildApp(store, { swagger: true });

    const res = await request(app)
      .post('/auth/register')
      .send({ email: 'eve@x.test', password: 'eve-pass-123', isAdmin: true });

    expect(res.status).toBe(404);
    expect(createSpy).not.toHaveBeenCalled();
    const spec = await request(app).get('/auth/openapi.json');
    expect(spec.body.paths['/auth/register']).toBeUndefined();
    expect(stderrSpy).not.toHaveBeenCalledWith(expect.stringContaining('POST /register'));
  });

  it('REGRESSION-REGISTER-MASS-ASSIGNMENT: sendWelcome never receives the plaintext password', async () => {
    const sendWelcome = vi.fn().mockResolvedValue(undefined);
    const config: AuthConfig = { ...baseConfig, email: { sendWelcome } };
    const store = new InMemoryUserStore();

    // Built-in handler.
    const first = await request(buildApp(store, { defaultRegister: true }, config))
      .post('/auth/register')
      .send({ email: 'a@x.test', password: 'secret-a', firstName: 'A' });
    expect(first.status).toBe(201);
    expect(sendWelcome).toHaveBeenLastCalledWith('a@x.test', { email: 'a@x.test', firstName: 'A' });

    // Custom onRegister: it still receives the raw body; sendWelcome gets the same data minus `password`.
    const onRegister = vi.fn(async (data: Record<string, unknown>) => store.create({ email: data['email'] as string }));
    const second = await request(buildApp(store, { onRegister }, config))
      .post('/auth/register')
      .send({ email: 'b@x.test', password: 'secret-b', plan: 'pro' });
    expect(second.status).toBe(201);
    expect(onRegister).toHaveBeenCalledWith({ email: 'b@x.test', password: 'secret-b', plan: 'pro' }, config, expect.anything());
    expect(sendWelcome).toHaveBeenLastCalledWith('b@x.test', { email: 'b@x.test', plan: 'pro' });
  });

  it('keeps the 400 INVALID_INPUT answer byte-identical', async () => {
    const store = new InMemoryUserStore();
    const createSpy = vi.spyOn(store, 'create');
    const app = buildApp(store, { defaultRegister: true });

    const bodies: Array<Record<string, unknown>> = [
      { email: 'a@x.test' },
      { password: 'secret' },
      { email: '', password: 'secret' },
      { email: 'a@x.test', password: '' },
      { email: { $ne: null }, password: 'secret' },
    ];
    for (const body of bodies) {
      const res = await request(app).post('/auth/register').send(body);
      expect(res.status).toBe(400);
      expect(res.text).toBe('{"error":"Email and password are required","code":"INVALID_INPUT"}');
    }
    const noBody = await request(app).post('/auth/register');
    expect(noBody.status).toBe(400);
    expect(noBody.text).toBe('{"error":"Email and password are required","code":"INVALID_INPUT"}');
    expect(createSpy).not.toHaveBeenCalled();
  });

  it('onRegister takes precedence over defaultRegister', async () => {
    const store = new InMemoryUserStore();
    const onRegister = vi.fn(async (data: Record<string, unknown>) => store.create({ email: data['email'] as string }));
    const res = await request(buildApp(store, { onRegister, defaultRegister: true }))
      .post('/auth/register')
      .send({ email: 'c@x.test', password: 'secret-c' });
    expect(res.status).toBe(201);
    expect(onRegister).toHaveBeenCalledTimes(1);
    expect(stderrSpy).not.toHaveBeenCalledWith(expect.stringContaining('POST /register'));
  });

  it('writes a WARN line and does not mount the route when defaultRegister is set but userStore.create is missing', async () => {
    const store = new InMemoryUserStore() as unknown as Record<string, unknown>;
    store['create'] = undefined;
    const res = await request(buildApp(store as unknown as IUserStore, { defaultRegister: true }))
      .post('/auth/register')
      .send({ email: 'd@x.test', password: 'secret-d' });
    expect(res.status).toBe(404);
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('defaultRegister is set but userStore.create is unavailable'));
  });
});
