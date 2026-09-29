import { describe, it, expect, vi, beforeEach } from 'vitest';
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

class SpyDiscordStrategy extends GenericOAuthStrategy {
  handleCallbackSpy = vi.fn().mockImplementation(async (_code: string, _state?: string): Promise<BaseUser> => {
    return { id: 'u-discord', email: 'discord@test.com', loginProvider: 'discord' };
  });
  override async handleCallback(code: string, state?: string): Promise<BaseUser> {
    return this.handleCallbackSpy(code, state);
  }
  override async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
    return { id: p.id, email: p.email };
  }
}

function parseCookieHeaders(res: request.Response, cookieName: string): string[] {
  const cookies = (res.headers['set-cookie'] as string[]) ?? [];
  return cookies.filter(c => c.startsWith(`${cookieName}=`));
}

function parseCookieValue(cookieHeader: string): string {
  return cookieHeader.split(';')[0].split('=')[1];
}

describe('Issue #22 Residuals verification', () => {
  let userStore: IUserStore;
  let googleStrategy: SpyGoogleStrategy;
  let discordStrategy: SpyDiscordStrategy;

  beforeEach(() => {
    userStore = {
      findByEmail: vi.fn().mockResolvedValue(null),
      findById: vi.fn().mockResolvedValue(null),
      create: vi.fn().mockImplementation((u) => Promise.resolve({ id: 'u-1', ...u })),
      updateRefreshToken: vi.fn().mockResolvedValue(undefined),
      updateLastLogin: vi.fn().mockResolvedValue(undefined),
      updateResetToken: vi.fn().mockResolvedValue(undefined),
      updatePassword: vi.fn().mockResolvedValue(undefined),
    };
    googleStrategy = new SpyGoogleStrategy(baseOAuthConfig);
    discordStrategy = new SpyDiscordStrategy(discordCfg);
  });

  describe('Residual 1: Stripping signature or expiry, bare nonces, or origin swapping forbidden', () => {
    it('rejects state reduced to { n, o } (stripped signature and expiry) with 400', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, baseOAuthConfig, { googleStrategy }));

      const initRes = await request(await listen(app)).get('/auth/oauth/google?return_path=/oauth/done');
      expect(initRes.status).toBe(302);
      const location = new URL(initRes.headers['location'] as string);
      const originalState = location.searchParams.get('state')!;
      const parsedOriginal = JSON.parse(Buffer.from(originalState, 'base64url').toString('utf8')) as OAuthState;

      const cookieHeaders = parseCookieHeaders(initRes, 'oauth_nonce_google');
      expect(cookieHeaders.length).toBe(1);
      const cookieNonce = parseCookieValue(cookieHeaders[0]);

      // Strip s and exp, leaving only { n, o }
      const strippedState = Buffer.from(JSON.stringify({ n: parsedOriginal.n, o: parsedOriginal.o })).toString('base64url');

      const res = await request(await listen(app))
        .get(`/auth/oauth/google/callback?code=fake-code&state=${encodeURIComponent(strippedState)}`)
        .set('Cookie', `oauth_nonce_google=${cookieNonce}`);

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OAUTH_STATE');
      expect(googleStrategy.handleCallbackSpy).not.toHaveBeenCalled();
    });

    it('rejects bare nonce string in state with 400', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, baseOAuthConfig, { googleStrategy }));

      const initRes = await request(await listen(app)).get('/auth/oauth/google');
      const cookieHeaders = parseCookieHeaders(initRes, 'oauth_nonce_google');
      const cookieNonce = parseCookieValue(cookieHeaders[0]);

      // Pass bare nonce as state
      const res = await request(await listen(app))
        .get(`/auth/oauth/google/callback?code=fake-code&state=${cookieNonce}`)
        .set('Cookie', `oauth_nonce_google=${cookieNonce}`);

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OAUTH_STATE');
      expect(googleStrategy.handleCallbackSpy).not.toHaveBeenCalled();
    });

    it('rejects state with swapped origin even if target origin is in allowlist when signature is forged/missing', async () => {
      const multiOriginConfig: AuthConfig = {
        ...baseOAuthConfig,
        email: { siteUrl: ['https://app.example.com', 'https://admin.example.com'] },
      };
      const app = express();
      app.use('/auth', createAuthRouter(userStore, multiOriginConfig, { googleStrategy }));

      const initRes = await request(await listen(app)).get('/auth/oauth/google').set('Origin', 'https://app.example.com');
      const cookieHeaders = parseCookieHeaders(initRes, 'oauth_nonce_google');
      const cookieNonce = parseCookieValue(cookieHeaders[0]);

      // Attacker swaps origin to admin origin without valid signature
      const forgedState = Buffer.from(JSON.stringify({ n: cookieNonce, o: 'https://admin.example.com' })).toString('base64url');

      const res = await request(await listen(app))
        .get(`/auth/oauth/google/callback?code=fake-code&state=${encodeURIComponent(forgedState)}`)
        .set('Cookie', `oauth_nonce_google=${cookieNonce}`);

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OAUTH_STATE');
      expect(googleStrategy.handleCallbackSpy).not.toHaveBeenCalled();
    });
  });

  describe('Residual 2: RegExp with g flag resets lastIndex and does not fail on repeated calls', () => {
    it('validateReturnPath resets lastIndex for stateful RegExp', () => {
      const regex = /^\/ok$/g;
      // Repeated evaluations must all succeed
      expect(validateReturnPath('/ok', [regex])).toBe(true);
      expect(validateReturnPath('/ok', [regex])).toBe(true);
      expect(validateReturnPath('/ok', [regex])).toBe(true);
      expect(validateReturnPath('/ok', [regex])).toBe(true);
      expect(regex.lastIndex).toBe(0);
    });

    it('allows 4 consecutive logins and callbacks using RegExp with /g flag without 400 failure', async () => {
      const regex = /^\/ok$/g;
      const app = express();
      app.use('/auth', createAuthRouter(userStore, baseOAuthConfig, {
        googleStrategy,
        allowedReturnPaths: [regex],
      }));

      for (let i = 0; i < 4; i++) {
        const initRes = await request(await listen(app)).get('/auth/oauth/google?return_path=/ok');
        expect(initRes.status).toBe(302);
        const location = new URL(initRes.headers['location'] as string);
        const state = location.searchParams.get('state')!;
        const cookieHeaders = parseCookieHeaders(initRes, 'oauth_nonce_google');
        const cookieNonce = parseCookieValue(cookieHeaders[0]);

        const callbackRes = await request(await listen(app))
          .get(`/auth/oauth/google/callback?code=code-${i}&state=${encodeURIComponent(state)}`)
          .set('Cookie', `oauth_nonce_google=${cookieNonce}`);

        expect(callbackRes.status).toBe(302);
        expect(callbackRes.headers['location']).toBe('https://app.example.com/ok');
      }
      expect(googleStrategy.handleCallbackSpy).toHaveBeenCalledTimes(4);
    });
  });

  describe('Residual 3: Empty array options.allowedReturnPaths falls through to config precedence', () => {
    it('falls through from options.allowedReturnPaths: [] to config.oauth.allowedReturnPaths', async () => {
      const configWithOAuthReturnPaths: AuthConfig = {
        ...baseOAuthConfig,
        oauth: {
          ...baseOAuthConfig.oauth,
          allowedReturnPaths: ['/oauth/done'],
        },
      };

      const app = express();
      app.use('/auth', createAuthRouter(userStore, configWithOAuthReturnPaths, {
        googleStrategy,
        allowedReturnPaths: [], // Empty array must NOT defeat config restriction!
      }));

      // /other should be rejected because config.oauth.allowedReturnPaths = ['/oauth/done']
      const rejectedRes = await request(await listen(app)).get('/auth/oauth/google?return_path=/other');
      expect(rejectedRes.status).toBe(400);
      expect(rejectedRes.body.code).toBe('OAUTH_RETURN_PATH_INVALID');

      // /oauth/done should be accepted
      const acceptedRes = await request(await listen(app)).get('/auth/oauth/google?return_path=/oauth/done');
      expect(acceptedRes.status).toBe(302);
    });
  });

  describe('Residual 4: Nonce cookie is set only on callback path (not duplicated on path=/ )', () => {
    it('sets exactly one cookie header for oauth_nonce_google scoped to callbackPath', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, baseOAuthConfig, { googleStrategy }));

      const res = await request(await listen(app)).get('/auth/oauth/google');
      expect(res.status).toBe(302);

      const cookieHeaders = parseCookieHeaders(res, 'oauth_nonce_google');
      expect(cookieHeaders.length).toBe(1);
      const cookie = cookieHeaders[0];
      expect(cookie).toContain('Path=/auth/oauth/google/callback');
      expect(cookie).not.toContain('Path=/;');
    });

    it('sets exactly one cookie header for generic OAuth provider scoped to callbackPath', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, baseOAuthConfig, {
        oauthStrategies: [discordStrategy],
      }));

      const res = await request(await listen(app)).get('/auth/oauth/discord');
      expect(res.status).toBe(302);

      const cookieHeaders = parseCookieHeaders(res, 'oauth_nonce_discord');
      expect(cookieHeaders.length).toBe(1);
      const cookie = cookieHeaders[0];
      expect(cookie).toContain('Path=/auth/oauth/discord/callback');
      expect(cookie).not.toContain('Path=/;');
    });
  });

  describe('Residual 5: String entry in allowedReturnPaths matches base path and accepts query params', () => {
    it('validateReturnPath matches string entry regardless of query parameters', () => {
      expect(validateReturnPath('/oauth/done?foo=bar&baz=123', ['/oauth/done'])).toBe(true);
      expect(validateReturnPath('/oauth/done?x=//evil', ['/oauth/done'])).toBe(true);
      expect(validateReturnPath('/oauth/done', ['/oauth/done'])).toBe(true);
      expect(validateReturnPath('/oauth/other?foo=bar', ['/oauth/done'])).toBe(false);
    });

    it('end-to-end OAuth flow preserves and allows query params on return_path matching string allowlist', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, baseOAuthConfig, {
        googleStrategy,
        allowedReturnPaths: ['/oauth/done'],
      }));

      const returnPath = '/oauth/done?tab=profile&theme=dark';
      const initRes = await request(await listen(app)).get(`/auth/oauth/google?return_path=${encodeURIComponent(returnPath)}`);
      expect(initRes.status).toBe(302);
      const location = new URL(initRes.headers['location'] as string);
      const state = location.searchParams.get('state')!;
      const cookieHeaders = parseCookieHeaders(initRes, 'oauth_nonce_google');
      const cookieNonce = parseCookieValue(cookieHeaders[0]);

      const callbackRes = await request(await listen(app))
        .get(`/auth/oauth/google/callback?code=test-code&state=${encodeURIComponent(state)}`)
        .set('Cookie', `oauth_nonce_google=${cookieNonce}`);

      expect(callbackRes.status).toBe(302);
      expect(callbackRes.headers['location']).toBe('https://app.example.com/oauth/done?tab=profile&theme=dark');
    });
  });
});
