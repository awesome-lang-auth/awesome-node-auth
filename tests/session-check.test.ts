/**
 * `session.checkOn: 'allcalls'` on the auth router's own protected routes.
 *
 * The router's routes behind the access-token check (`/me`, `/sessions`,
 * `/change-password`, ...) receive the router's `sessionStore`, so a session
 * revoked server-side is refused on the very next call when `checkOn` is
 * `'allcalls'`, while `'refresh'` keeps the stateless fast path.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createAuthRouter } from '../src/router/auth.router';
import { AuthConfig } from '../src/models/auth-config.model';
import { SessionInfo } from '../src/models/session.model';
import { ISessionStore } from '../src/interfaces/session-store.interface';
import { PasswordService } from '../src/services/password.service';
import { InMemoryUserStore } from '../examples/in-memory-user-store';

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

async function setup(checkOn: 'allcalls' | 'refresh') {
  const config: AuthConfig = {
    accessTokenSecret: 'session-check-access-secret-very-long',
    refreshTokenSecret: 'session-check-refresh-secret-very-long',
    session: { checkOn },
  };
  const userStore = new InMemoryUserStore();
  await userStore.create({ email: 'user@example.com', password: await new PasswordService().hash('pw') });
  const sessionStore = makeSessionStore();
  const app = express();
  app.use(express.json());
  app.use('/auth', createAuthRouter(userStore, config, { sessionStore }));

  const login = await request(app)
    .post('/auth/login')
    .set('X-Auth-Strategy', 'bearer')
    .send({ email: 'user@example.com', password: 'pw' });
  expect(login.status).toBe(200);
  const accessToken = login.body.accessToken as string;
  const [sid] = [...sessionStore.sessions.keys()];
  expect(sid).toBeTruthy();
  return { app, sessionStore, accessToken, sid };
}

describe("auth router: session.checkOn with the router's sessionStore", () => {
  let ctx: Awaited<ReturnType<typeof setup>>;

  describe("checkOn: 'allcalls'", () => {
    beforeEach(async () => { ctx = await setup('allcalls'); });

    it('GET /me with a still-valid access token is 401 SESSION_REVOKED right after the session is revoked', async () => {
      const before = await request(ctx.app).get('/auth/me').set('Authorization', `Bearer ${ctx.accessToken}`);
      expect(before.status).toBe(200);

      await ctx.sessionStore.revokeSession(ctx.sid);

      const after = await request(ctx.app).get('/auth/me').set('Authorization', `Bearer ${ctx.accessToken}`);
      expect(after.status).toBe(401);
      expect(after.body).toEqual({ error: 'Session has been revoked', code: 'SESSION_REVOKED' });

      const sessions = await request(ctx.app).get('/auth/sessions').set('Authorization', `Bearer ${ctx.accessToken}`);
      expect(sessions.status).toBe(401);
    });

    it('updates the session last-active timestamp', async () => {
      await request(ctx.app).get('/auth/me').set('Authorization', `Bearer ${ctx.accessToken}`);
      expect(ctx.sessionStore.getSession).toHaveBeenCalledWith(ctx.sid);
      expect(ctx.sessionStore.updateSessionLastActive).toHaveBeenCalledWith(ctx.sid);
    });
  });

  describe("checkOn: 'refresh'", () => {
    beforeEach(async () => { ctx = await setup('refresh'); });

    it('GET /me still answers 200 until the next refresh (no per-call lookup)', async () => {
      await ctx.sessionStore.revokeSession(ctx.sid);
      const res = await request(ctx.app).get('/auth/me').set('Authorization', `Bearer ${ctx.accessToken}`);
      expect(res.status).toBe(200);
      expect(ctx.sessionStore.getSession).not.toHaveBeenCalled();
    });

    it('updates the session last-active timestamp', async () => {
      await request(ctx.app).get('/auth/me').set('Authorization', `Bearer ${ctx.accessToken}`);
      expect(ctx.sessionStore.updateSessionLastActive).toHaveBeenCalledWith(ctx.sid);
    });
  });
});
