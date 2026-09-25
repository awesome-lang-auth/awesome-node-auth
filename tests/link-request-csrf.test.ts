/**
 * POST /link-request applies CSRF like auth.middleware() does.
 *
 * With `csrf.enabled`, the double-submit check applies to requests without an
 * `Authorization: Bearer` credential (cookie-authenticated and anonymous
 * conflict-linking calls).  A bearer request is exempt, and its identity comes
 * from the bearer token only: the accessToken cookie is then ignored.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createAuthRouter } from '../src/router/auth.router';
import { AuthConfig } from '../src/models/auth-config.model';
import { IPendingLinkStore } from '../src/interfaces/pending-link-store.interface';
import { PasswordService } from '../src/services/password.service';
import { InMemoryUserStore, InMemoryLinkedAccountsStore } from '../examples/in-memory-user-store';

describe('POST /link-request with csrf.enabled', () => {
  let userStore: InMemoryUserStore;
  let sendVerificationEmail: ReturnType<typeof vi.fn>;
  let app: express.Application;

  beforeEach(async () => {
    sendVerificationEmail = vi.fn().mockResolvedValue(undefined);
    const config: AuthConfig = {
      accessTokenSecret: 'link-request-access-secret-very-long',
      refreshTokenSecret: 'link-request-refresh-secret-very-long',
      csrf: { enabled: true },
      email: { siteUrl: 'http://localhost:3000', sendVerificationEmail },
    };
    userStore = new InMemoryUserStore();
    await userStore.create({ email: 'user@example.com', password: await new PasswordService().hash('pw') });
    const pendingLinkStore: IPendingLinkStore = {
      stash: vi.fn().mockResolvedValue(undefined),
      retrieve: vi.fn().mockResolvedValue({ providerAccountId: 'gh-1' }),
      remove: vi.fn().mockResolvedValue(undefined),
    };
    app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, config, {
      linkedAccountsStore: new InMemoryLinkedAccountsStore(),
      pendingLinkStore,
    }));
  });

  async function cookieLogin(): Promise<{ cookies: string; csrf: string }> {
    const res = await request(app).post('/auth/login').send({ email: 'user@example.com', password: 'pw' });
    expect(res.status).toBe(200);
    // Like a browser: a cookie set twice in one response keeps the last value
    // (login sets csrf-token on arrival and again with the session).
    const jar = new Map<string, string>();
    for (const c of res.headers['set-cookie'] as unknown as string[]) {
      const [pair] = c.split(';');
      const eq = pair.indexOf('=');
      jar.set(pair.slice(0, eq), pair.slice(eq + 1));
    }
    const cookies = [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
    return { cookies, csrf: jar.get('csrf-token')! };
  }

  it('a bearer request needs no CSRF token', async () => {
    const login = await request(app)
      .post('/auth/login')
      .set('X-Auth-Strategy', 'bearer')
      .send({ email: 'user@example.com', password: 'pw' });
    const res = await request(app)
      .post('/auth/link-request')
      .set('Authorization', `Bearer ${login.body.accessToken}`)
      .send({ email: 'second@example.com' });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ success: true });
    expect(sendVerificationEmail).toHaveBeenCalledTimes(1);
    expect((await userStore.findById('1'))?.accountLinkPendingEmail).toBe('second@example.com');
  });

  it('a cookie-authenticated request without the CSRF header is 403 CSRF_INVALID', async () => {
    const { cookies } = await cookieLogin();
    const res = await request(app).post('/auth/link-request').set('Cookie', cookies).send({ email: 'second@example.com' });
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'CSRF validation failed', code: 'CSRF_INVALID' });
    expect(sendVerificationEmail).not.toHaveBeenCalled();
  });

  it('a cookie-authenticated request with the matching CSRF header succeeds', async () => {
    const { cookies, csrf } = await cookieLogin();
    const res = await request(app)
      .post('/auth/link-request')
      .set('Cookie', cookies)
      .set('X-CSRF-Token', csrf)
      .send({ email: 'second@example.com' });
    expect(res.status).toBe(200);
  });

  it('an invalid bearer token with a valid session cookie and no CSRF header does not act on the cookie session', async () => {
    const { cookies } = await cookieLogin();
    const res = await request(app)
      .post('/auth/link-request')
      .set('Cookie', cookies)
      .set('Authorization', 'Bearer not-a-jwt')
      .send({ email: 'second@example.com' });
    expect(res.status).not.toBe(200);
    expect((await userStore.findById('1'))?.accountLinkPendingEmail ?? null).toBeNull();
  });

  it('an anonymous conflict-linking request without the CSRF header is 403 CSRF_INVALID', async () => {
    const res = await request(app).post('/auth/link-request').send({ email: 'user@example.com', provider: 'github' });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('CSRF_INVALID');
  });
});
