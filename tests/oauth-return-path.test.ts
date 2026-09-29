import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';
import {
  createAuthRouter,
  validateReturnPath,
  encodeOAuthState,
  computeOAuthStateSignature,
  OAuthState,
} from '../src/router/auth.router';
import { IUserStore } from '../src/interfaces/user-store.interface';
import { BaseUser } from '../src/models/user.model';
import { AuthConfig } from '../src/models/auth-config.model';
import { GoogleStrategy } from '../src/strategies/oauth/google.strategy';
import { GithubStrategy } from '../src/strategies/oauth/github.strategy';
import { GenericOAuthStrategy, GenericOAuthProviderConfig } from '../src/strategies/oauth/generic-oauth.strategy';

const baseOAuthConfig: AuthConfig = {
  accessTokenSecret: 'test-access-token-secret-for-oauth-state-signing-32chars',
  refreshTokenSecret: 'test-refresh-token-secret-for-oauth-state-signing-32chars',
  email: { siteUrl: 'https://app.example.com' },
  oauth: {
    google: {
      clientId: 'google-client-id',
      clientSecret: 'google-client-secret',
      callbackUrl: 'https://app.example.com/auth/oauth/google/callback',
    },
    github: {
      clientId: 'github-client-id',
      clientSecret: 'github-client-secret',
      callbackUrl: 'https://app.example.com/auth/oauth/github/callback',
    },
  },
};

const discordCfg: GenericOAuthProviderConfig = {
  name: 'discord',
  clientId: 'discord-id',
  clientSecret: 'discord-secret',
  callbackUrl: 'https://app.example.com/auth/oauth/discord/callback',
  authorizationUrl: 'https://discord.com/api/oauth2/authorize',
  tokenUrl: 'https://discord.com/api/oauth2/token',
};

class SpyGoogleStrategy extends GoogleStrategy {
  handleCallbackSpy = vi.fn().mockImplementation(async (_code: string, _state?: string): Promise<BaseUser> => {
    return { id: 'u-google', email: 'google@test.com', loginProvider: 'google' };
  });
  override async handleCallback(code: string, state?: string): Promise<BaseUser> {
    return this.handleCallbackSpy(code, state);
  }
  override async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
    return { id: p.id, email: p.email };
  }
}

class SpyGithubStrategy extends GithubStrategy {
  handleCallbackSpy = vi.fn().mockImplementation(async (_code: string, _state?: string): Promise<BaseUser> => {
    return { id: 'u-github', email: 'github@test.com', loginProvider: 'github' };
  });
  override async handleCallback(code: string, state?: string): Promise<BaseUser> {
    return this.handleCallbackSpy(code, state);
  }
  override async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
    return { id: p.id, email: p.email };
  }
}

class SpyDiscordStrategy extends GenericOAuthStrategy {
  handleCallbackSpy = vi.fn().mockImplementation(async (_code: string): Promise<BaseUser> => {
    return { id: 'u-discord', email: 'discord@test.com', loginProvider: 'discord' };
  });
  override async handleCallback(code: string): Promise<BaseUser> {
    return this.handleCallbackSpy(code);
  }
  override async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
    return { id: p.id, email: p.email };
  }
}

function parseCookieHeader(res: request.Response, cookieName: string): { value?: string; raw?: string } {
  const cookies = (res.headers['set-cookie'] as string[]) ?? [];
  const raw = cookies.find((c) => c.startsWith(`${cookieName}=`));
  if (!raw) return {};
  const value = raw.split(';')[0].split('=')[1];
  return { value, raw };
}

describe('Issue #22: Validate and restrict return_path, bind state to nonce cookie', () => {
  let userStore: IUserStore;

  beforeEach(() => {
    userStore = {
      findByEmail: vi.fn().mockResolvedValue(null),
      findById: vi.fn().mockResolvedValue(null),
      create: vi.fn().mockImplementation((u) => Promise.resolve({ id: 'u-created', ...u })),
      updateRefreshToken: vi.fn().mockResolvedValue(undefined),
      updateLastLogin: vi.fn().mockResolvedValue(undefined),
      updateResetToken: vi.fn().mockResolvedValue(undefined),
      updatePassword: vi.fn().mockResolvedValue(undefined),
    };
  });

  describe('validateReturnPath unit helper', () => {
    it('rejects non-strings, protocol-relative, absolute URLs, backslashes, control chars, and long paths', () => {
      expect(validateReturnPath(undefined)).toBe(false);
      expect(validateReturnPath(null)).toBe(false);
      expect(validateReturnPath(123)).toBe(false);
      expect(validateReturnPath({})).toBe(false);
      expect(validateReturnPath([])).toBe(false);

      // Must start with single /
      expect(validateReturnPath('https://evil.example')).toBe(false);
      expect(validateReturnPath('http://evil.example')).toBe(false);
      expect(validateReturnPath('javascript:alert(1)')).toBe(false);
      expect(validateReturnPath('dashboard')).toBe(false);
      expect(validateReturnPath('')).toBe(false);

      // No protocol-relative //
      expect(validateReturnPath('//evil.example')).toBe(false);
      expect(validateReturnPath('//evil.example/path')).toBe(false);

      // No backslashes
      expect(validateReturnPath('/a\\b')).toBe(false);
      expect(validateReturnPath('/\\evil.example')).toBe(false);

      // No control characters
      expect(validateReturnPath('/oauth/done\x00')).toBe(false);
      expect(validateReturnPath('/oauth/done\n')).toBe(false);
      expect(validateReturnPath('/oauth/done\x1f')).toBe(false);
      expect(validateReturnPath('/oauth/done\x7f')).toBe(false);

      // Max length 512
      expect(validateReturnPath('/' + 'a'.repeat(511))).toBe(true);
      expect(validateReturnPath('/' + 'a'.repeat(512))).toBe(false);
      expect(validateReturnPath('/' + 'a'.repeat(2000))).toBe(false);
    });

    it('accepts well-formed relative paths when no allowedReturnPaths is configured', () => {
      expect(validateReturnPath('/')).toBe(true);
      expect(validateReturnPath('/oauth/done')).toBe(true);
      expect(validateReturnPath('/dashboard/settings?tab=security')).toBe(true);
    });

    it('enforces allowedReturnPaths allowlist with strings and RegExps', () => {
      const allowed = ['/oauth/done', /^\/dashboard(\/.*)?$/];

      expect(validateReturnPath('/oauth/done', allowed)).toBe(true);
      expect(validateReturnPath('/oauth/done?session=1', allowed)).toBe(true);
      expect(validateReturnPath('/dashboard', allowed)).toBe(true);
      expect(validateReturnPath('/dashboard/profile', allowed)).toBe(true);

      expect(validateReturnPath('/altro', allowed)).toBe(false);
      expect(validateReturnPath('/admin', allowed)).toBe(false);
      expect(validateReturnPath('/oauth/other', allowed)).toBe(false);
    });
  });

  describe('OAuth start: return_path validation and cookie prohibition on failure', () => {
    let googleStrategy: SpyGoogleStrategy;
    let githubStrategy: SpyGithubStrategy;
    let discordStrategy: SpyDiscordStrategy;

    beforeEach(() => {
      googleStrategy = new SpyGoogleStrategy(baseOAuthConfig);
      githubStrategy = new SpyGithubStrategy(baseOAuthConfig);
      discordStrategy = new SpyDiscordStrategy(discordCfg);
    });

    it('rejects invalid return_path on Google start with 400 OAUTH_RETURN_PATH_INVALID and sets no cookie', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, baseOAuthConfig, { googleStrategy }));

      const badInputs = [
        'https://evil.example',
        '//evil.example',
        '/a\\b',
        '/' + 'a'.repeat(2000),
      ];

      for (const badPath of badInputs) {
        const res = await request(await listen(app)).get(`/auth/oauth/google?return_path=${encodeURIComponent(badPath)}`);
        expect(res.status).toBe(400);
        expect(res.body.code).toBe('OAUTH_RETURN_PATH_INVALID');
        const { value: cookie } = parseCookieHeader(res, 'oauth_nonce_google');
        expect(cookie).toBeUndefined();
        expect(res.headers['location']).toBeUndefined();
      }
    });

    it('enforces allowedReturnPaths restriction on start (/oauth/done works, /altro returns 400)', async () => {
      const app = express();
      app.use(
        '/auth',
        createAuthRouter(userStore, baseOAuthConfig, {
          googleStrategy,
          allowedReturnPaths: ['/oauth/done'],
        }),
      );

      // /altro -> 400, no cookie
      const badRes = await request(await listen(app)).get('/auth/oauth/google?return_path=/altro');
      expect(badRes.status).toBe(400);
      expect(badRes.body.code).toBe('OAUTH_RETURN_PATH_INVALID');
      const { value: badCookie } = parseCookieHeader(badRes, 'oauth_nonce_google');
      expect(badCookie).toBeUndefined();

      // /oauth/done -> 302, cookie set
      const goodRes = await request(await listen(app)).get('/auth/oauth/google?return_path=/oauth/done');
      expect(goodRes.status).toBe(302);
      const { value: goodCookie } = parseCookieHeader(goodRes, 'oauth_nonce_google');
      expect(goodCookie).toBeDefined();

      const location = new URL(goodRes.headers['location'] as string);
      const stateParam = location.searchParams.get('state')!;
      const statePayload = JSON.parse(Buffer.from(stateParam, 'base64url').toString()) as OAuthState;
      expect(statePayload.n).toBe(goodCookie);
      expect(statePayload.p).toBe('/oauth/done');
      expect(statePayload.exp).toBeGreaterThan(Date.now());
      expect(statePayload.s).toBeDefined();
    });

    it('applies return_path validation to GitHub strategy', async () => {
      const app = express();
      app.use(
        '/auth',
        createAuthRouter(userStore, baseOAuthConfig, {
          githubStrategy,
          allowedReturnPaths: ['/oauth/done'],
        }),
      );

      const badRes = await request(await listen(app)).get('/auth/oauth/github?return_path=//evil.example');
      expect(badRes.status).toBe(400);
      expect(badRes.body.code).toBe('OAUTH_RETURN_PATH_INVALID');
      const { value: badCookie } = parseCookieHeader(badRes, 'oauth_nonce_github');
      expect(badCookie).toBeUndefined();

      const goodRes = await request(await listen(app)).get('/auth/oauth/github?return_path=/oauth/done');
      expect(goodRes.status).toBe(302);
      const { value: goodCookie } = parseCookieHeader(goodRes, 'oauth_nonce_github');
      expect(goodCookie).toBeDefined();
    });

    it('applies return_path validation to generic OAuth strategy', async () => {
      const app = express();
      app.use(
        '/auth',
        createAuthRouter(userStore, baseOAuthConfig, {
          oauthStrategies: [discordStrategy],
          allowedReturnPaths: ['/oauth/done'],
        }),
      );

      const badRes = await request(await listen(app)).get('/auth/oauth/discord?return_path=/altro');
      expect(badRes.status).toBe(400);
      expect(badRes.body.code).toBe('OAUTH_RETURN_PATH_INVALID');
      const { value: badCookie } = parseCookieHeader(badRes, 'oauth_nonce_discord');
      expect(badCookie).toBeUndefined();

      const goodRes = await request(await listen(app)).get('/auth/oauth/discord?return_path=/oauth/done');
      expect(goodRes.status).toBe(302);
      const { value: goodCookie } = parseCookieHeader(goodRes, 'oauth_nonce_discord');
      expect(goodCookie).toBeDefined();
    });
  });

  describe('OAuth callback: state binding, signature verification, and expiry', () => {
    let googleStrategy: SpyGoogleStrategy;

    beforeEach(() => {
      googleStrategy = new SpyGoogleStrategy(baseOAuthConfig);
    });

    it('rejects callback with 400 before token exchange when state p is tampered', async () => {
      const app = express();
      app.use(
        '/auth',
        createAuthRouter(userStore, baseOAuthConfig, {
          googleStrategy,
          allowedReturnPaths: ['/oauth/done', '/attacker'],
        }),
      );

      // 1. Initiate with valid return_path
      const initRes = await request(await listen(app)).get('/auth/oauth/google?return_path=/oauth/done');
      expect(initRes.status).toBe(302);
      const location = new URL(initRes.headers['location'] as string);
      const originalState = location.searchParams.get('state')!;
      const { value: cookieNonce } = parseCookieHeader(initRes, 'oauth_nonce_google');

      // 2. Tamper p in state while keeping the old signature
      const parsed = JSON.parse(Buffer.from(originalState, 'base64url').toString()) as OAuthState;
      parsed.p = '/attacker';
      const tamperedState = Buffer.from(JSON.stringify(parsed)).toString('base64url');

      // 3. Callback with tampered state
      const res = await request(await listen(app))
        .get(`/auth/oauth/google/callback?code=fake-code&state=${encodeURIComponent(tamperedState)}`)
        .set('Cookie', `oauth_nonce_google=${cookieNonce}`);

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OAUTH_STATE');
      // Token exchange / handleCallback must NOT be called!
      expect(googleStrategy.handleCallbackSpy).not.toHaveBeenCalled();
    });

    it('rejects callback with 400 when signature s is omitted from state', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, baseOAuthConfig, { googleStrategy }));

      const initRes = await request(await listen(app)).get('/auth/oauth/google?return_path=/oauth/done');
      const location = new URL(initRes.headers['location'] as string);
      const originalState = location.searchParams.get('state')!;
      const { value: cookieNonce } = parseCookieHeader(initRes, 'oauth_nonce_google');

      // Strip signature
      const parsed = JSON.parse(Buffer.from(originalState, 'base64url').toString()) as OAuthState;
      delete parsed.s;
      const strippedState = Buffer.from(JSON.stringify(parsed)).toString('base64url');

      const res = await request(await listen(app))
        .get(`/auth/oauth/google/callback?code=fake-code&state=${encodeURIComponent(strippedState)}`)
        .set('Cookie', `oauth_nonce_google=${cookieNonce}`);

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OAUTH_STATE');
      expect(googleStrategy.handleCallbackSpy).not.toHaveBeenCalled();
    });

    it('rejects callback with 400 when state has expired', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, baseOAuthConfig, { googleStrategy }));

      const nonce = 'exp-test-nonce-12345';
      const origin = 'https://app.example.com';
      const returnPath = '/oauth/done';
      const expiredTime = Date.now() - 60 * 1000; // 1 minute ago
      const expiredSig = computeOAuthStateSignature(
        nonce,
        origin,
        returnPath,
        expiredTime,
        baseOAuthConfig.accessTokenSecret,
      );

      const expiredState = Buffer.from(
        JSON.stringify({
          n: nonce,
          o: origin,
          p: returnPath,
          exp: expiredTime,
          s: expiredSig,
        }),
      ).toString('base64url');

      const res = await request(await listen(app))
        .get(`/auth/oauth/google/callback?code=fake-code&state=${encodeURIComponent(expiredState)}`)
        .set('Cookie', `oauth_nonce_google=${nonce}`);

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OAUTH_STATE');
      expect(googleStrategy.handleCallbackSpy).not.toHaveBeenCalled();
    });

    it('accepts callback with valid signed state and redirects to origin + return_path', async () => {
      const app = express();
      app.use(
        '/auth',
        createAuthRouter(userStore, baseOAuthConfig, {
          googleStrategy,
          allowedReturnPaths: ['/oauth/done'],
        }),
      );

      const initRes = await request(await listen(app)).get('/auth/oauth/google?return_path=/oauth/done');
      const location = new URL(initRes.headers['location'] as string);
      const state = location.searchParams.get('state')!;
      const { value: cookieNonce } = parseCookieHeader(initRes, 'oauth_nonce_google');

      const res = await request(await listen(app))
        .get(`/auth/oauth/google/callback?code=fake-code&state=${encodeURIComponent(state)}`)
        .set('Cookie', `oauth_nonce_google=${cookieNonce}`);

      expect(res.status).toBe(302);
      expect(res.headers['location']).toBe('https://app.example.com/oauth/done');
      expect(googleStrategy.handleCallbackSpy).toHaveBeenCalled();
    });
  });

  describe('Production origin allowlist protection', () => {
    const origNodeEnv = process.env.NODE_ENV;

    afterEach(() => {
      process.env.NODE_ENV = origNodeEnv;
    });

    it('refuses to start OAuth in production when origin allowlist is empty', async () => {
      process.env.NODE_ENV = 'production';

      const configWithoutOrigins: AuthConfig = {
        accessTokenSecret: 'test-access-token-secret-for-oauth-state-signing-32chars',
        refreshTokenSecret: 'test-refresh-token-secret-for-oauth-state-signing-32chars',
        oauth: {
          google: {
            clientId: 'google-client-id',
            clientSecret: 'google-client-secret',
            callbackUrl: 'https://app.example.com/auth/oauth/google/callback',
          },
        },
        // No email.siteUrl and no cors.origins -> allowedOrigins is empty!
      };

      const googleStrategy = new SpyGoogleStrategy(configWithoutOrigins);
      const app = express();
      app.use('/auth', createAuthRouter(userStore, configWithoutOrigins, { googleStrategy }));

      const res = await request(await listen(app)).get('/auth/oauth/google');
      expect(res.status).toBe(500);
      expect(res.body.code).toBe('OAUTH_ORIGIN_ALLOWLIST_EMPTY');
      const { value: cookie } = parseCookieHeader(res, 'oauth_nonce_google');
      expect(cookie).toBeUndefined();
    });
  });
});
