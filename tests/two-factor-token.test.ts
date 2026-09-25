/**
 * The 2FA step-up token (`tempToken`) is not a session token.
 *
 * After a correct password, a user who must present a second factor gets a
 * short-lived `tempToken`.  It is accepted by the 2FA completion endpoints and
 * by nothing else: the app's auth middleware, the admin guard and the SSE
 * stream all refuse it.  The completion endpoints, in turn, refuse an
 * ordinary access token in its place.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { TOTP, NobleCryptoPlugin, ScureBase32Plugin } from 'otplib';
import { AuthConfigurator } from '../src/auth-configurator';
import { AuthConfig } from '../src/models/auth-config.model';
import { BaseUser } from '../src/models/user.model';
import { PasswordService } from '../src/services/password.service';
import { TokenService } from '../src/services/token.service';
import { GenericOAuthStrategy, GenericOAuthProviderConfig } from '../src/strategies/oauth/generic-oauth.strategy';
import { createAuthRouter } from '../src/router/auth.router';
import { createToolsRouter } from '../src/router/tools.router';
import { AuthTools } from '../src/tools/auth-tools';
import { AuthEventBus } from '../src/events/auth-event-bus';
import { InMemoryUserStore } from '../examples/in-memory-user-store';

const config: AuthConfig = {
  accessTokenSecret: 'two-factor-access-secret-very-long-and-secure',
  refreshTokenSecret: 'two-factor-refresh-secret-very-long-and-secure',
  accessTokenExpiresIn: '15m',
  refreshTokenExpiresIn: '7d',
};

const totp = new TOTP({ crypto: new NobleCryptoPlugin(), base32: new ScureBase32Plugin() });
const tokenService = new TokenService();

/** `name=value; name2=value2` from a response's Set-Cookie headers. */
function cookieHeader(res: request.Response): string {
  const setCookie = (res.headers['set-cookie'] ?? []) as unknown as string[];
  return setCookie.map((c) => c.split(';')[0]).join('; ');
}

describe('2FA step-up token', () => {
  let userStore: InMemoryUserStore;
  let admin: BaseUser;
  let totpSecret: string;
  let app: express.Application;

  beforeEach(async () => {
    userStore = new InMemoryUserStore();
    totpSecret = totp.generateSecret();
    admin = await userStore.create({
      email: 'ops@example.com',
      password: await new PasswordService().hash('correct horse'),
      isAdmin: true,
      isTotpEnabled: true,
      totpSecret,
    });

    const auth = new AuthConfigurator(config, userStore);
    const tools = new AuthTools(new AuthEventBus(), { sse: true });
    app = express();
    app.use(express.json());
    app.use(auth.buildAllRouters({ admin: { accessPolicy: 'is-admin-flag', silent: true } }));
    app.use('/tools', createToolsRouter(tools, { authMiddleware: auth.middleware() }));
  });

  async function passwordOnlyLogin(bearer = false): Promise<string> {
    const req = request(app).post('/auth/login');
    if (bearer) req.set('X-Auth-Strategy', 'bearer');
    const res = await req.send({ email: 'ops@example.com', password: 'correct horse' });
    expect(res.status).toBe(200);
    expect(res.body.requiresTwoFactor).toBe(true);
    expect(res.body.accessToken).toBeUndefined();
    expect(res.headers['set-cookie']).toBeUndefined();
    return res.body.tempToken as string;
  }

  it('REGRESSION-2FA-ADMIN-GUARD: isAdmin user with 2FA, password-only login — the tempToken is refused by the admin console and by protected routes', async () => {
    const tempToken = await passwordOnlyLogin();
    const bearer = `Bearer ${tempToken}`;
    const cookie = `accessToken=${tempToken}`;

    // Admin console, as a bearer token and as the session cookie.
    for (const path of ['/auth/admin/api/ping', '/auth/admin/api/users']) {
      const viaBearer = await request(app).get(path).set('Authorization', bearer);
      expect(viaBearer.status, path).toBe(401);
      const viaCookie = await request(app).get(path).set('Cookie', cookie);
      expect(viaCookie.status, path).toBe(401);
      const viaBrowser = await request(app).get(path).set('Cookie', cookie).set('Accept', 'text/html');
      expect(viaBrowser.status, path).toBe(401);
    }
    const promote = await request(app)
      .post(`/auth/admin/users/${admin.id}/promote`)
      .set('Authorization', bearer)
      .send({});
    expect(promote.status).toBe(401);

    // The panel treats the browser as signed out: it shows the sign-in form.
    const panel = await request(app).get('/auth/admin/').set('Cookie', cookie).set('Accept', 'text/html');
    expect(panel.status).toBe(200);
    expect(panel.text).toContain('id="login"');

    // Protected app routes (auth.middleware()).
    for (const auth of [{ Authorization: bearer }, { Cookie: cookie }]) {
      const me = await request(app).get('/auth/me').set(auth);
      expect(me.status).toBe(403);
      expect(me.body).toEqual({ error: 'Invalid or expired access token' });
      const setup = await request(app).post('/auth/2fa/setup').set(auth).send({});
      expect(setup.status).toBe(403);
    }

    // SSE stream behind the host's auth.middleware() (token in the query string).
    const stream = await request(app).get(`/tools/stream?token=${encodeURIComponent(tempToken)}`);
    expect(stream.status).toBe(403);
  });

  it('the full TOTP flow still works in cookie mode', async () => {
    const tempToken = await passwordOnlyLogin();
    const verify = await request(app)
      .post('/auth/2fa/verify')
      .send({ tempToken, totpCode: await totp.generate({ secret: totpSecret }) });
    expect(verify.status).toBe(200);
    expect(verify.body).toEqual({ success: true });
    const cookies = cookieHeader(verify);
    expect(cookies).toContain('accessToken=');

    const me = await request(app).get('/auth/me').set('Cookie', cookies);
    expect(me.status).toBe(200);
    expect(me.body.email).toBe('ops@example.com');
    const ping = await request(app).get('/auth/admin/api/ping').set('Cookie', cookies);
    expect(ping.status).toBe(200);
  });

  it('the full TOTP flow still works in bearer mode', async () => {
    const tempToken = await passwordOnlyLogin(true);
    const verify = await request(app)
      .post('/auth/2fa/verify')
      .set('X-Auth-Strategy', 'bearer')
      .send({ tempToken, totpCode: await totp.generate({ secret: totpSecret }) });
    expect(verify.status).toBe(200);
    expect(verify.headers['set-cookie']).toBeUndefined();
    const { accessToken, refreshToken } = verify.body as { accessToken: string; refreshToken: string };
    expect(accessToken).toBeTruthy();
    expect(refreshToken).toBeTruthy();

    const me = await request(app).get('/auth/me').set('Authorization', `Bearer ${accessToken}`);
    expect(me.status).toBe(200);
    const ping = await request(app).get('/auth/admin/api/ping').set('Authorization', `Bearer ${accessToken}`);
    expect(ping.status).toBe(200);
  });

  it('the 2FA completion endpoints refuse an ordinary access token in place of the tempToken', async () => {
    const accessToken = tokenService.generateTokenPair({ sub: admin.id, email: admin.email }, config).accessToken;
    const totpCode = await totp.generate({ secret: totpSecret });

    const verify = await request(app).post('/auth/2fa/verify').send({ tempToken: accessToken, totpCode });
    expect(verify.status).toBe(401);
    expect(verify.body).toEqual({ error: 'Invalid or expired access token', code: 'INVALID_ACCESS_TOKEN' });

    const sms = await request(app).post('/auth/sms/verify').send({ mode: '2fa', tempToken: accessToken, code: '123456' });
    expect(sms.status).toBe(401);
    expect(sms.body).toEqual({ error: 'Invalid or expired temp token', code: 'INVALID_TEMP_TOKEN' });

    const magic = await request(app).post('/auth/magic-link/verify').send({ mode: '2fa', tempToken: accessToken, token: 'x' });
    expect(magic.status).toBe(401);
    expect(magic.body).toEqual({ error: 'Invalid or expired temp token', code: 'INVALID_TEMP_TOKEN' });
  });

  it('TokenService: verifyAccessToken refuses the tempToken, verifyTempToken accepts only the tempToken', () => {
    const payload = { sub: admin.id, email: admin.email };
    const tempToken = tokenService.generateTempToken(payload, config);
    const accessToken = tokenService.generateTokenPair(payload, config).accessToken;

    expect(() => tokenService.verifyAccessToken(tempToken, config)).toThrow('Invalid or expired access token');
    expect(tokenService.verifyAccessToken(accessToken, config).sub).toBe(admin.id);
    expect(tokenService.verifyTempToken(tempToken, config).sub).toBe(admin.id);
    expect(() => tokenService.verifyTempToken(accessToken, config)).toThrow('Invalid or expired access token');

    // 5-minute lifetime, as before.
    const decoded = jwt.decode(tempToken) as { iat: number; exp: number };
    expect(decoded.exp - decoded.iat).toBe(300);
  });

  it('a custom token claim cannot turn the tempToken into a session token', () => {
    const tempToken = tokenService.generateTempToken({ sub: admin.id, email: admin.email, purpose: 'session' }, config);
    expect(() => tokenService.verifyAccessToken(tempToken, config)).toThrow('Invalid or expired access token');
  });

  it('the tempToken of an OAuth login that needs 2FA is refused as a session too', async () => {
    const providerConfig: GenericOAuthProviderConfig = {
      name: 'discord',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      callbackUrl: 'https://api.example.com/auth/oauth/discord/callback',
      authorizationUrl: 'https://discord.com/api/oauth2/authorize',
      tokenUrl: 'https://discord.com/api/oauth2/token',
      userInfoUrl: 'https://discord.com/api/users/@me',
      scope: 'identify email',
    };
    class DiscordStrategy extends GenericOAuthStrategy {
      async handleCallback(_code: string): Promise<BaseUser> { return admin; }
      async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
        return { id: p.id, email: p.email };
      }
    }
    const oauthApp = express();
    oauthApp.use(express.json());
    oauthApp.use('/auth', createAuthRouter(userStore, { ...config, email: { siteUrl: 'https://app.example.com' } }, {
      oauthStrategies: [new DiscordStrategy(providerConfig)],
    }));

    const callback = await request(oauthApp).get('/auth/oauth/discord/callback?code=abc&state=xyz');
    expect(callback.status).toBe(302);
    const tempToken = new URL(callback.headers['location'] as string).searchParams.get('tempToken')!;
    expect(tempToken).toBeTruthy();

    const me = await request(oauthApp).get('/auth/me').set('Authorization', `Bearer ${tempToken}`);
    expect(me.status).toBe(403);
  });
});
