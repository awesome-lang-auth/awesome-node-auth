/**
 * POST /logout ends the session for bearer clients too.
 *
 * A bearer client (`X-Auth-Strategy: bearer`) holds its tokens itself and
 * sends no cookie.  Logout identifies the session from the
 * `Authorization: Bearer` access token and/or a `refreshToken` in the body
 * (as for /refresh), revokes the stateful session and clears the stored
 * refresh token, so the refresh token can no longer mint tokens.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createAuthRouter } from '../src/router/auth.router';
import { AuthConfig } from '../src/models/auth-config.model';
import { SessionInfo } from '../src/models/session.model';
import { ISessionStore } from '../src/interfaces/session-store.interface';
import { PasswordService } from '../src/services/password.service';
import { AuthEventBus } from '../src/events/auth-event-bus';
import { AuthEventNames } from '../src/events/auth-event-names';
import { InMemoryUserStore } from '../examples/in-memory-user-store';

const config: AuthConfig = {
  accessTokenSecret: 'logout-bearer-access-secret-very-long',
  refreshTokenSecret: 'logout-bearer-refresh-secret-very-long',
};

function makeSessionStore(): ISessionStore & { sessions: Map<string, SessionInfo> } {
  const sessions = new Map<string, SessionInfo>();
  let next = 1;
  return {
    sessions,
    createSession: async (info) => {
      const s: SessionInfo = { sessionHandle: `sid-${next++}`, ...info };
      sessions.set(s.sessionHandle, s);
      return s;
    },
    getSession: async (handle) => sessions.get(handle) ?? null,
    getSessionsForUser: async (userId) => [...sessions.values()].filter((s) => s.userId === userId),
    updateSessionLastActive: async () => undefined,
    revokeSession: async (handle) => { sessions.delete(handle); },
    revokeAllSessionsForUser: async () => undefined,
  };
}

describe.each([
  ['with a session store', true],
  ['without a session store', false],
])('POST /logout in bearer mode (%s)', (_label, withSessions) => {
  let userStore: InMemoryUserStore;
  let sessionStore: ReturnType<typeof makeSessionStore>;
  let events: Array<{ event: string; userId?: string; sessionId?: string }>;
  let app: express.Application;
  let userId: string;

  beforeEach(async () => {
    userStore = new InMemoryUserStore();
    userId = (await userStore.create({ email: 'user@example.com', password: await new PasswordService().hash('pw') })).id;
    sessionStore = makeSessionStore();
    const eventBus = new AuthEventBus();
    events = [];
    eventBus.onEvent(AuthEventNames.AUTH_LOGOUT, (p) => { events.push({ event: p.event, userId: p.userId, sessionId: p.sessionId }); });
    app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, config, { ...(withSessions ? { sessionStore } : {}), eventBus }));
  });

  async function bearerLogin(): Promise<{ accessToken: string; refreshToken: string }> {
    const res = await request(app)
      .post('/auth/login')
      .set('X-Auth-Strategy', 'bearer')
      .send({ email: 'user@example.com', password: 'pw' });
    expect(res.status).toBe(200);
    return res.body;
  }

  const refresh = (refreshToken: string) => request(app)
    .post('/auth/refresh')
    .set('X-Auth-Strategy', 'bearer')
    .send({ refreshToken });

  it('the Authorization: Bearer access token ends the session: the refresh token is refused afterwards', async () => {
    const { accessToken, refreshToken } = await bearerLogin();

    const logout = await request(app).post('/auth/logout').set('Authorization', `Bearer ${accessToken}`).send({});
    expect(logout.status).toBe(200);
    expect(logout.body).toEqual({ success: true });

    expect((await refresh(refreshToken)).status).toBe(401);
    expect((await userStore.findById(userId))?.refreshToken).toBeNull();
    if (withSessions) expect(sessionStore.sessions.size).toBe(0);
    expect(events).toHaveLength(1);
    expect(events[0].userId).toBe(userId);
  });

  it('a refreshToken in the body alone ends the session', async () => {
    const { refreshToken } = await bearerLogin();

    const logout = await request(app).post('/auth/logout').send({ refreshToken });
    expect(logout.status).toBe(200);

    expect((await refresh(refreshToken)).status).toBe(401);
    expect((await userStore.findById(userId))?.refreshToken).toBeNull();
    if (withSessions) expect(sessionStore.sessions.size).toBe(0);
    expect(events[0].userId).toBe(userId);
  });

  it('a refresh token that was already rotated does not end the current session', async () => {
    const first = await bearerLogin();
    // Without a session id in the token, a rotation within the same second
    // would mint the same token: move the clock (Date only) forward.
    let rotated: request.Response;
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      vi.setSystemTime(Date.now() + 5_000);
      rotated = await refresh(first.refreshToken);
    } finally {
      vi.useRealTimers();
    }
    expect(rotated.status).toBe(200);
    expect(rotated.body.refreshToken).not.toBe(first.refreshToken);

    const logout = await request(app).post('/auth/logout').send({ refreshToken: first.refreshToken });
    expect(logout.status).toBe(200);
    expect(events[0].userId).toBeUndefined();

    expect((await refresh(rotated.body.refreshToken as string)).status).toBe(200);
  });

  it('an invalid bearer token still answers 200 and ends nothing', async () => {
    const { refreshToken } = await bearerLogin();
    const logout = await request(app).post('/auth/logout').set('Authorization', 'Bearer not-a-jwt').send({});
    expect(logout.status).toBe(200);
    expect((await refresh(refreshToken)).status).toBe(200);
  });
});

describe('POST /logout in cookie mode', () => {
  it('still revokes the session named by the accessToken cookie', async () => {
    const userStore = new InMemoryUserStore();
    await userStore.create({ email: 'user@example.com', password: await new PasswordService().hash('pw') });
    const sessionStore = makeSessionStore();
    const revoke = vi.spyOn(sessionStore, 'revokeSession');
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, config, { sessionStore }));

    const login = await request(app).post('/auth/login').send({ email: 'user@example.com', password: 'pw' });
    const cookies = (login.headers['set-cookie'] as unknown as string[]).map((c) => c.split(';')[0]).join('; ');
    const logout = await request(app).post('/auth/logout').set('Cookie', cookies);
    expect(logout.status).toBe(200);
    expect(revoke).toHaveBeenCalledWith('sid-1');
    expect(sessionStore.sessions.size).toBe(0);
  });
});
