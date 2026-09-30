/**
 * `RouterOptions.issueSessionOnRegister` — `POST /register` may log the new
 * account in, when the instance admin turns it on (family spec, origin
 * awesome-go-auth #21).
 *
 * Off (default): `201 {success, userId}`, no cookie, no token, no session.
 * On: the same `201` and fields plus the session `POST /login` delivers
 * (cookies, or tokens in the body with `X-Auth-Strategy: bearer`).  A refused
 * registration, a blocking email-verification policy or a second factor the
 * login would ask for mean nothing is issued.
 */
import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from 'vitest';
import express from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';
import { createAuthRouter, RouterOptions } from '../src/router/auth.router';
import { AuthConfig } from '../src/models/auth-config.model';
import { AuthError } from '../src/models/errors';
import { SessionInfo } from '../src/models/session.model';
import { ISessionStore } from '../src/interfaces/session-store.interface';
import { AuthEventBus, AuthEventPayload } from '../src/events/auth-event-bus';
import { AuthEventNames } from '../src/events/auth-event-names';
import { PasswordService } from '../src/services/password.service';
import { InMemoryUserStore } from '../examples/in-memory-user-store';

const passwordService = new PasswordService();

const baseConfig: AuthConfig = {
  accessTokenSecret: 'register-session-access-secret-very-long-and-secure',
  refreshTokenSecret: 'register-session-refresh-secret-very-long-and-secure',
  accessTokenExpiresIn: '15m',
  refreshTokenExpiresIn: '7d',
};

function makeSessionStore() {
  const sessions = new Map<string, SessionInfo>();
  let next = 1;
  const store = {
    sessions,
    createSession: vi.fn(async (info: Omit<SessionInfo, 'sessionHandle'>) => {
      const s: SessionInfo = { sessionHandle: `sid-${next++}`, ...info };
      sessions.set(s.sessionHandle, s);
      return s;
    }),
    getSession: vi.fn(async (handle: string) => sessions.get(handle) ?? null),
    getSessionsForUser: vi.fn(async (userId: string) => [...sessions.values()].filter((s) => s.userId === userId)),
    updateSessionLastActive: vi.fn(async () => undefined),
    revokeSession: vi.fn(async (handle: string) => { sessions.delete(handle); }),
    revokeAllSessionsForUser: vi.fn(async () => undefined),
  };
  return store as typeof store & ISessionStore;
}

function buildApp(store: InMemoryUserStore, options: RouterOptions = {}, config: AuthConfig = baseConfig) {
  const app = express();
  app.use(express.json());
  app.use('/auth', createAuthRouter(store, config, options));
  return app;
}

function setCookies(res: request.Response): string[] {
  const raw = res.headers['set-cookie'] as unknown;
  if (!raw) return [];
  return Array.isArray(raw) ? (raw as string[]) : [raw as string];
}

function cookieHeader(cookies: string[]): string {
  return cookies.map((c) => c.split(';')[0]).join('; ');
}

function collect(bus: AuthEventBus): AuthEventPayload[] {
  const seen: AuthEventPayload[] = [];
  bus.onEvent('*', (payload) => seen.push(payload));
  return seen;
}

const signup = { email: 'new@x.test', password: 'new-pass-123' };

describe('POST /register with issueSessionOnRegister', () => {
  let stderrSpy: MockInstance;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  it('off (default): 201 with exactly {success, userId}, no Set-Cookie, no session row', async () => {
    const store = new InMemoryUserStore();
    const sessionStore = makeSessionStore();
    const app = buildApp(store, { defaultRegister: true, sessionStore });

    const res = await request(await listen(app)).post('/auth/register').send(signup);

    expect(res.status).toBe(201);
    expect(res.body).toEqual({ success: true, userId: expect.any(String) });
    expect(setCookies(res)).toEqual([]);
    expect(sessionStore.createSession).not.toHaveBeenCalled();
  });

  it('off (explicit false), bearer client: no tokens, no refresh token stored on the user', async () => {
    const store = new InMemoryUserStore();
    const app = buildApp(store, { defaultRegister: true, issueSessionOnRegister: false });

    const res = await request(await listen(app))
      .post('/auth/register')
      .set('X-Auth-Strategy', 'bearer')
      .send(signup);

    expect(res.status).toBe(201);
    expect(res.body).toEqual({ success: true, userId: expect.any(String) });
    expect(setCookies(res)).toEqual([]);
    const user = await store.findById(res.body.userId);
    expect(user?.refreshToken ?? null).toBeNull();
  });

  it('on (cookie): 201 {success, userId}, access and refresh cookies, GET /me answers on them, one session row', async () => {
    const store = new InMemoryUserStore();
    const sessionStore = makeSessionStore();
    const bus = new AuthEventBus();
    const seen = collect(bus);
    const app = buildApp(store, { defaultRegister: true, issueSessionOnRegister: true, sessionStore, eventBus: bus });

    const res = await request(await listen(app))
      .post('/auth/register')
      .set('User-Agent', 'register-session-test')
      .send(signup);

    expect(res.status).toBe(201);
    expect(res.body).toEqual({ success: true, userId: expect.any(String) });
    const cookies = setCookies(res);
    expect(cookies.some((c) => c.startsWith('accessToken='))).toBe(true);
    expect(cookies.some((c) => c.startsWith('refreshToken='))).toBe(true);

    expect(sessionStore.createSession).toHaveBeenCalledTimes(1);
    expect(sessionStore.createSession.mock.calls[0][0]).toMatchObject({
      userId: res.body.userId,
      userAgent: 'register-session-test',
    });

    const me = await request(await listen(app)).get('/auth/me').set('Cookie', cookieHeader(cookies));
    expect(me.status).toBe(200);
    expect(me.body.email).toBe(signup.email);

    const created = seen.filter((e) => e.event === AuthEventNames.USER_CREATED);
    const logins = seen.filter((e) => e.event === AuthEventNames.AUTH_LOGIN_SUCCESS);
    expect(created).toHaveLength(1);
    expect(logins).toHaveLength(1);
    expect(logins[0].userId).toBe(res.body.userId);
    expect(logins[0].sessionId).toBe('sid-1');
    expect((await store.findById(res.body.userId))?.lastLogin).toBeInstanceOf(Date);
  });

  it('on (bearer): tokens in the body with the login field names, no cookies, GET /me answers with the bearer', async () => {
    const store = new InMemoryUserStore();
    const app = buildApp(store, { defaultRegister: true, issueSessionOnRegister: true });

    const res = await request(await listen(app))
      .post('/auth/register')
      .set('X-Auth-Strategy', 'bearer')
      .send(signup);

    expect(res.status).toBe(201);
    expect(res.body).toEqual({
      success: true,
      userId: expect.any(String),
      accessToken: expect.any(String),
      refreshToken: expect.any(String),
    });
    expect(setCookies(res)).toEqual([]);

    const me = await request(await listen(app))
      .get('/auth/me')
      .set('Authorization', `Bearer ${res.body.accessToken}`);
    expect(me.status).toBe(200);
    expect(me.body.email).toBe(signup.email);
  });

  it('on + session.singleSessionPerUser: the other sessions of the user are revoked, as at login', async () => {
    const store = new InMemoryUserStore();
    const sessionStore = makeSessionStore();
    const config: AuthConfig = { ...baseConfig, session: { singleSessionPerUser: true } };
    const app = buildApp(store, { defaultRegister: true, issueSessionOnRegister: true, sessionStore }, config);

    const res = await request(await listen(app)).post('/auth/register').send(signup);

    expect(res.status).toBe(201);
    expect(sessionStore.revokeAllSessionsForUser).toHaveBeenCalledWith(res.body.userId, undefined);
    expect(sessionStore.createSession).toHaveBeenCalledTimes(1);
  });

  it('on + refused registration (400, 409 USER_EXISTS, throwing onRegister): nothing is issued', async () => {
    const store = new InMemoryUserStore();
    await store.create({ email: 'taken@x.test', password: await passwordService.hash('taken-pass') });
    const sessionStore = makeSessionStore();
    const app = buildApp(store, { defaultRegister: true, issueSessionOnRegister: true, sessionStore });

    const missing = await request(await listen(app))
      .post('/auth/register')
      .set('X-Auth-Strategy', 'bearer')
      .send({ email: 'new@x.test' });
    expect(missing.status).toBe(400);
    expect(missing.body.accessToken).toBeUndefined();
    expect(setCookies(missing)).toEqual([]);

    const taken = await request(await listen(app))
      .post('/auth/register')
      .send({ email: 'taken@x.test', password: 'other-pass-123' });
    expect(taken.status).toBe(409);
    expect(taken.body.code).toBe('USER_EXISTS');
    expect(setCookies(taken)).toEqual([]);

    const hookApp = buildApp(store, {
      issueSessionOnRegister: true,
      sessionStore,
      onRegister: async () => {
        throw new AuthError('Sign-ups are closed', 'REGISTRATION_CLOSED', 403);
      },
    });
    const hook = await request(await listen(hookApp))
      .post('/auth/register')
      .set('X-Auth-Strategy', 'bearer')
      .send(signup);
    expect(hook.status).toBe(403);
    expect(hook.body.accessToken).toBeUndefined();
    expect(setCookies(hook)).toEqual([]);

    expect(sessionStore.createSession).not.toHaveBeenCalled();
  });

  it.each([
    ['emailVerificationMode: strict', { emailVerificationMode: 'strict' } as Partial<AuthConfig>],
    ['requireEmailVerification: true', { requireEmailVerification: true } as Partial<AuthConfig>],
  ])('on + blocking email-verification policy (%s): nothing is issued, logged once at startup', async (_label, policy) => {
    const store = new InMemoryUserStore();
    const sessionStore = makeSessionStore();
    const config: AuthConfig = { ...baseConfig, ...policy };
    const app = buildApp(store, { defaultRegister: true, issueSessionOnRegister: true, sessionStore }, config);

    const logged = stderrSpy.mock.calls.filter((c) => String(c[0]).includes('issueSessionOnRegister'));
    expect(logged).toHaveLength(1);

    const cookie = await request(await listen(app)).post('/auth/register').send(signup);
    expect(cookie.status).toBe(201);
    expect(cookie.body).toEqual({ success: true, userId: expect.any(String) });
    expect(setCookies(cookie)).toEqual([]);

    const bearer = await request(await listen(app))
      .post('/auth/register')
      .set('X-Auth-Strategy', 'bearer')
      .send({ email: 'second@x.test', password: 'second-pass-123' });
    expect(bearer.status).toBe(201);
    expect(bearer.body).toEqual({ success: true, userId: expect.any(String) });

    expect(sessionStore.createSession).not.toHaveBeenCalled();
    expect((await store.findById(cookie.body.userId))?.refreshToken ?? null).toBeNull();
  });

  it('on + strict policy, onRegister returns an already verified account: the session is issued, as the login would', async () => {
    const store = new InMemoryUserStore();
    const config: AuthConfig = { ...baseConfig, emailVerificationMode: 'strict' };
    const app = buildApp(store, {
      issueSessionOnRegister: true,
      onRegister: async (data) => store.create({
        email: data['email'] as string,
        password: await passwordService.hash(data['password'] as string),
        isEmailVerified: true,
      }),
    }, config);

    const res = await request(await listen(app))
      .post('/auth/register')
      .set('X-Auth-Strategy', 'bearer')
      .send(signup);

    expect(res.status).toBe(201);
    expect(res.body.accessToken).toEqual(expect.any(String));
  });

  it('on + the new account needs a second factor at login (require2FA): nothing is issued', async () => {
    const store = new InMemoryUserStore();
    const app = buildApp(store, {
      issueSessionOnRegister: true,
      onRegister: async (data) => store.create({
        email: data['email'] as string,
        password: await passwordService.hash(data['password'] as string),
        require2FA: true,
      }),
    });

    const res = await request(await listen(app))
      .post('/auth/register')
      .set('X-Auth-Strategy', 'bearer')
      .send(signup);

    expect(res.status).toBe(201);
    expect(res.body).toEqual({ success: true, userId: expect.any(String) });
    expect(setCookies(res)).toEqual([]);
  });
});
