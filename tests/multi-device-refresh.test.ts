import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import * as crypto from 'crypto';
import { createAuthRouter } from '../src/router/auth.router';
import { IUserStore } from '../src/interfaces/user-store.interface';
import { ISessionStore } from '../src/interfaces/session-store.interface';
import { BaseUser } from '../src/models/user.model';
import { AuthConfig } from '../src/models/auth-config.model';
import { SessionInfo } from '../src/models/session.model';
import { PasswordService } from '../src/services/password.service';
import { TokenService } from '../src/services/token.service';

const passwordService = new PasswordService();
const tokenService = new TokenService();

const config: AuthConfig = {
  accessTokenSecret: 'test-access-secret-multi-device-long-enough',
  refreshTokenSecret: 'test-refresh-secret-multi-device-long-enough',
  accessTokenExpiresIn: '15m',
  refreshTokenExpiresIn: '7d',
};

class InMemorySessionStore implements ISessionStore {
  public sessions: Map<string, SessionInfo> = new Map();

  createSession = vi.fn((session: Omit<SessionInfo, 'sessionHandle'>): Promise<SessionInfo> => {
    const handle = 'sess_' + Math.random().toString(36).slice(2);
    const full: SessionInfo = { ...session, sessionHandle: handle };
    this.sessions.set(handle, full);
    return Promise.resolve(full);
  });

  getSession = vi.fn((sessionHandle: string): Promise<SessionInfo | null> => {
    return Promise.resolve(this.sessions.get(sessionHandle) ?? null);
  });

  revokeSession = vi.fn((sessionHandle: string): Promise<boolean> => {
    const deleted = this.sessions.delete(sessionHandle);
    return Promise.resolve(deleted);
  });

  revokeAllSessionsForUser = vi.fn((userId: string): Promise<number> => {
    let count = 0;
    for (const [handle, s] of this.sessions) {
      if (s.userId === userId) {
        this.sessions.delete(handle);
        count++;
      }
    }
    return Promise.resolve(count);
  });

  getSessionsForUser = vi.fn((userId: string): Promise<SessionInfo[]> => {
    return Promise.resolve([...this.sessions.values()].filter(s => s.userId === userId));
  });

  updateSessionRefreshTokenHash = vi.fn((sessionHandle: string, hash: string): Promise<void> => {
    const s = this.sessions.get(sessionHandle);
    if (s) {
      s.refreshTokenHash = hash;
      s.data = { ...s.data, refreshTokenHash: hash };
    }
    return Promise.resolve();
  });
}

function parseCookies(res: request.Response): Record<string, string> {
  const setCookies = (res.headers['set-cookie'] as string[]) ?? [];
  const result: Record<string, string> = {};
  for (const c of setCookies) {
    const [pair] = c.split(';');
    const eqIdx = pair.indexOf('=');
    if (eqIdx !== -1) {
      result[pair.slice(0, eqIdx).trim()] = pair.slice(eqIdx + 1).trim();
    }
  }
  return result;
}

describe('Issue #13: Multi-device sessions and refresh tokens', () => {
  let user: BaseUser;
  let userStore: IUserStore;
  let sessionStore: InMemorySessionStore;

  beforeEach(async () => {
    const passwordHash = await passwordService.hash('secure-password');
    user = {
      id: 'u-device-1',
      email: 'device@test.com',
      password: passwordHash,
      isEmailVerified: true,
    };

    userStore = {
      findByEmail: vi.fn((email: string) => Promise.resolve(email === user.email ? user : null)),
      findById: vi.fn((id: string) => Promise.resolve(id === user.id ? user : null)),
      create: vi.fn(),
      updateRefreshToken: vi.fn((id, token, expiry) => {
        if (id === user.id) {
          user.refreshToken = token;
          user.refreshTokenExpiry = expiry;
        }
        return Promise.resolve();
      }),
      updateLastLogin: vi.fn(() => Promise.resolve()),
      updateResetToken: vi.fn(() => Promise.resolve()),
      updatePassword: vi.fn(() => Promise.resolve()),
    };

    sessionStore = new InMemorySessionStore();
  });

  describe('Concurrent multi-device mode (default / singleSessionPerUser: false)', () => {
    it('allows two devices to log in, refresh independently, and isolate logout', async () => {
      const app = express();
      app.use(express.json());
      app.use('/auth', createAuthRouter(userStore, config, { sessionStore }));

      // 1. Device A logs in
      const resA = await request(app).post('/auth/login').send({ email: 'device@test.com', password: 'secure-password' });
      expect(resA.status).toBe(200);
      const cookiesA = parseCookies(resA);
      const refreshA = cookiesA['refreshToken'];
      expect(refreshA).toBeDefined();

      const payloadA = tokenService.verifyRefreshToken(refreshA, config);
      expect(payloadA.sid).toBeDefined();
      const sessionHandleA = payloadA.sid!;
      const sessionA = await sessionStore.getSession(sessionHandleA);
      expect(sessionA).not.toBeNull();
      const expectedHashA = crypto.createHash('sha256').update(refreshA).digest('hex');
      expect(sessionA?.refreshTokenHash).toBe(expectedHashA);

      // 2. Device B logs in
      const resB = await request(app).post('/auth/login').send({ email: 'device@test.com', password: 'secure-password' });
      expect(resB.status).toBe(200);
      const cookiesB = parseCookies(resB);
      const refreshB = cookiesB['refreshToken'];
      expect(refreshB).toBeDefined();
      expect(refreshB).not.toBe(refreshA);

      const payloadB = tokenService.verifyRefreshToken(refreshB, config);
      expect(payloadB.sid).toBeDefined();
      const sessionHandleB = payloadB.sid!;
      expect(sessionHandleB).not.toBe(sessionHandleA);

      // Both sessions exist concurrently
      expect(sessionStore.sessions.size).toBe(2);

      // 3. Device A refreshes tokens
      const refreshResA = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refreshToken=${refreshA}`);
      expect(refreshResA.status).toBe(200);
      const newCookiesA = parseCookies(refreshResA);
      const newRefreshA = newCookiesA['refreshToken'];
      expect(newRefreshA).toBeDefined();
      expect(newRefreshA).not.toBe(refreshA);

      // Old session A was rotated; new session for device A exists and session B is untouched
      expect(sessionStore.sessions.has(sessionHandleA)).toBe(false);
      expect(sessionStore.sessions.has(sessionHandleB)).toBe(true);
      expect(sessionStore.sessions.size).toBe(2);

      const newPayloadA = tokenService.verifyRefreshToken(newRefreshA, config);
      const newSessionHandleA = newPayloadA.sid!;
      const newSessionA = await sessionStore.getSession(newSessionHandleA);
      expect(newSessionA?.refreshTokenHash).toBe(crypto.createHash('sha256').update(newRefreshA).digest('hex'));

      // 4. Device B refreshes tokens independently
      const refreshResB = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refreshToken=${refreshB}`);
      expect(refreshResB.status).toBe(200);
      const newCookiesB = parseCookies(refreshResB);
      const newRefreshB = newCookiesB['refreshToken'];
      expect(newRefreshB).toBeDefined();
      expect(newRefreshB).not.toBe(refreshB);

      expect(sessionStore.sessions.has(sessionHandleB)).toBe(false);
      expect(sessionStore.sessions.size).toBe(2);

      const newPayloadB = tokenService.verifyRefreshToken(newRefreshB, config);
      const newSessionHandleB = newPayloadB.sid!;

      // 5. Device A logs out
      const logoutResA = await request(app)
        .post('/auth/logout')
        .set('Cookie', `accessToken=${newCookiesA['accessToken']}; refreshToken=${newRefreshA}`);
      expect(logoutResA.status).toBe(200);

      // Session A is revoked
      expect(sessionStore.sessions.has(newSessionHandleA)).toBe(false);
      // Device B's session is STILL active
      expect(sessionStore.sessions.has(newSessionHandleB)).toBe(true);
      // User's refreshToken is NOT wiped out because session B remains
      expect(user.refreshToken).not.toBeNull();

      // 6. Device B can still refresh
      const refreshResB2 = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refreshToken=${newRefreshB}`);
      expect(refreshResB2.status).toBe(200);

      // 7. Device B logs out
      const cookiesB2 = parseCookies(refreshResB2);
      const logoutResB = await request(app)
        .post('/auth/logout')
        .set('Cookie', `accessToken=${cookiesB2['accessToken']}; refreshToken=${cookiesB2['refreshToken']}`);
      expect(logoutResB.status).toBe(200);

      // All sessions are now gone -> user.refreshToken is now null
      expect(sessionStore.sessions.size).toBe(0);
      expect(user.refreshToken).toBeNull();
    });

    it('rejects refresh when refreshToken hash does not match session record (mismatched/tampered token)', async () => {
      const app = express();
      app.use(express.json());
      app.use('/auth', createAuthRouter(userStore, config, { sessionStore }));

      // Device A logs in
      const resA = await request(app).post('/auth/login').send({ email: 'device@test.com', password: 'secure-password' });
      const cookiesA = parseCookies(resA);
      const refreshA = cookiesA['refreshToken'];
      const payloadA = tokenService.verifyRefreshToken(refreshA, config);

      // Tamper with the session's refreshTokenHash in store
      const session = await sessionStore.getSession(payloadA.sid!);
      expect(session).not.toBeNull();
      session!.refreshTokenHash = 'wrong-hash';

      const res = await request(app).post('/auth/refresh').set('Cookie', `refreshToken=${refreshA}`);
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Invalid refresh token');
    });
  });

  describe('Single session mode (singleSessionPerUser: true)', () => {
    it('disconnects previous device session upon new login when singleSessionPerUser is enabled', async () => {
      const singleSessionConfig: AuthConfig = {
        ...config,
        session: { singleSessionPerUser: true },
      };

      const app = express();
      app.use(express.json());
      app.use('/auth', createAuthRouter(userStore, singleSessionConfig, { sessionStore }));

      // 1. Device A logs in
      const resA = await request(app).post('/auth/login').send({ email: 'device@test.com', password: 'secure-password' });
      expect(resA.status).toBe(200);
      const cookiesA = parseCookies(resA);
      const refreshA = cookiesA['refreshToken'];
      const payloadA = tokenService.verifyRefreshToken(refreshA, config);
      const sessionHandleA = payloadA.sid!;
      expect(sessionStore.sessions.has(sessionHandleA)).toBe(true);

      // 2. Device B logs in with same user credentials
      const resB = await request(app).post('/auth/login').send({ email: 'device@test.com', password: 'secure-password' });
      expect(resB.status).toBe(200);
      const cookiesB = parseCookies(resB);
      const refreshB = cookiesB['refreshToken'];
      const payloadB = tokenService.verifyRefreshToken(refreshB, config);
      const sessionHandleB = payloadB.sid!;

      // Previous session A must have been revoked!
      expect(sessionStore.revokeAllSessionsForUser).toHaveBeenCalledWith('u-device-1', undefined);
      expect(sessionStore.sessions.has(sessionHandleA)).toBe(false);
      expect(sessionStore.sessions.has(sessionHandleB)).toBe(true);
      expect(sessionStore.sessions.size).toBe(1);

      // 3. Device A tries to refresh -> rejected because session was revoked
      const refreshResA = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refreshToken=${refreshA}`);
      expect(refreshResA.status).toBe(401);
      expect(refreshResA.body.code).toBe('SESSION_REVOKED');

      // 4. Device B can refresh successfully
      const refreshResB = await request(app)
        .post('/auth/refresh')
        .set('Cookie', `refreshToken=${refreshB}`);
      expect(refreshResB.status).toBe(200);
    });

    it('supports singleSession alias in config.session', async () => {
      const singleSessionAliasConfig: AuthConfig = {
        ...config,
        session: { singleSession: true },
      };

      const app = express();
      app.use(express.json());
      app.use('/auth', createAuthRouter(userStore, singleSessionAliasConfig, { sessionStore }));

      // Device A logs in
      const resA = await request(app).post('/auth/login').send({ email: 'device@test.com', password: 'secure-password' });
      const cookiesA = parseCookies(resA);
      const refreshA = cookiesA['refreshToken'];
      const handleA = tokenService.verifyRefreshToken(refreshA, config).sid!;

      // Device B logs in
      await request(app).post('/auth/login').send({ email: 'device@test.com', password: 'secure-password' });

      // Device A session must be revoked
      expect(sessionStore.sessions.has(handleA)).toBe(false);
      expect(sessionStore.sessions.size).toBe(1);
    });
  });
});
