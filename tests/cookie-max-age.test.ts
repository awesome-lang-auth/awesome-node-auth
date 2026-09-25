/**
 * Token cookie lifetimes follow the configured token lifetimes.
 *
 * The access and refresh cookies set in cookie mode used to carry fixed
 * `maxAge` values (15 minutes and 7 days) whatever `accessTokenExpiresIn` /
 * `refreshTokenExpiresIn` said.  Each cookie now lives as long as the token it
 * carries (`exp - iat`).
 */
import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { TokenService } from '../src/services/token.service';
import { createAuthRouter } from '../src/router/auth.router';
import { AuthConfig } from '../src/models/auth-config.model';
import { PasswordService } from '../src/services/password.service';
import { InMemoryUserStore } from '../examples/in-memory-user-store';
import { createResponse } from './test-helpers';

const base: AuthConfig = {
  accessTokenSecret: 'cookie-max-age-access-secret-very-long',
  refreshTokenSecret: 'cookie-max-age-refresh-secret-very-long',
};

const tokenService = new TokenService();

function cookieMaxAges(config: AuthConfig) {
  const tokens = tokenService.generateTokenPair({ sub: 'u1', email: 'u@example.com' }, config);
  const res = createResponse();
  tokenService.setTokenCookies(res as never, tokens, config);
  return {
    access: res.cookieOptions['accessToken']['maxAge'],
    refresh: res.cookieOptions['refreshToken']['maxAge'],
    csrf: res.cookieOptions['csrf-token']?.['maxAge'],
    tokens,
  };
}

describe('setTokenCookies: cookie maxAge follows the configured token lifetimes', () => {
  it.each([
    ['15m', '7d', 15 * 60, 7 * 24 * 3600],
    ['1h', '30d', 3600, 30 * 24 * 3600],
    ['30d', '90d', 30 * 24 * 3600, 90 * 24 * 3600],
    ['2 hours', '10 days', 2 * 3600, 10 * 24 * 3600],
    ['90s', '1w', 90, 7 * 24 * 3600],
  ])('access %s / refresh %s', (accessTokenExpiresIn, refreshTokenExpiresIn, accessSeconds, refreshSeconds) => {
    const { access, refresh } = cookieMaxAges({ ...base, accessTokenExpiresIn, refreshTokenExpiresIn });
    expect(access).toBe(accessSeconds * 1000);
    expect(refresh).toBe(refreshSeconds * 1000);
  });

  it('defaults (no lifetimes configured) are unchanged: 15 minutes and 7 days', () => {
    const { access, refresh } = cookieMaxAges(base);
    expect(access).toBe(15 * 60 * 1000);
    expect(refresh).toBe(7 * 24 * 60 * 60 * 1000);
  });

  it('cookie maxAge equals the JWT exp - iat for a non-default lifetime', () => {
    const { access, refresh, tokens } = cookieMaxAges({ ...base, accessTokenExpiresIn: '45m', refreshTokenExpiresIn: '14d' });
    const a = jwt.decode(tokens.accessToken) as { iat: number; exp: number };
    const r = jwt.decode(tokens.refreshToken) as { iat: number; exp: number };
    expect(access).toBe((a.exp - a.iat) * 1000);
    expect(refresh).toBe((r.exp - r.iat) * 1000);
  });

  it('the CSRF cookie keeps its 15-minute lifetime', () => {
    const { csrf } = cookieMaxAges({ ...base, accessTokenExpiresIn: '1h', csrf: { enabled: true } });
    expect(csrf).toBe(15 * 60 * 1000);
  });

  it('tokens without iat/exp fall back to the previous fixed lifetimes', () => {
    const res = createResponse();
    tokenService.setTokenCookies(res as never, { accessToken: 'opaque-a', refreshToken: 'opaque-r' }, base);
    expect(res.cookieOptions['accessToken']['maxAge']).toBe(15 * 60 * 1000);
    expect(res.cookieOptions['refreshToken']['maxAge']).toBe(7 * 24 * 60 * 60 * 1000);
  });

  it('POST /login sets Max-Age from the configured lifetimes on the wire', async () => {
    const config: AuthConfig = { ...base, accessTokenExpiresIn: '1h', refreshTokenExpiresIn: '30d' };
    const userStore = new InMemoryUserStore();
    await userStore.create({ email: 'u@example.com', password: await new PasswordService().hash('pw') });
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, config));

    const res = await request(app).post('/auth/login').send({ email: 'u@example.com', password: 'pw' });
    expect(res.status).toBe(200);
    const setCookie = res.headers['set-cookie'] as unknown as string[];
    const access = setCookie.find((c) => c.startsWith('accessToken='))!;
    const refresh = setCookie.find((c) => c.startsWith('refreshToken='))!;
    expect(access).toContain('Max-Age=3600;');
    expect(refresh).toContain('Max-Age=2592000;');
  });
});
