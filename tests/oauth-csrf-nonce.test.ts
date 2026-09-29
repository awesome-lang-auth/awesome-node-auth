import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';
import { createAuthRouter } from '../src/router/auth.router';
import { IUserStore } from '../src/interfaces/user-store.interface';
import { BaseUser } from '../src/models/user.model';
import { AuthConfig } from '../src/models/auth-config.model';
import { GoogleStrategy } from '../src/strategies/oauth/google.strategy';
import { GithubStrategy } from '../src/strategies/oauth/github.strategy';
import { GenericOAuthStrategy, GenericOAuthProviderConfig } from '../src/strategies/oauth/generic-oauth.strategy';

const oauthConfig: AuthConfig = {
  accessTokenSecret: 'test-access-secret-csrf-nonce-long-enough',
  refreshTokenSecret: 'test-refresh-secret-csrf-nonce-long-enough',
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

class TestGoogleStrategy extends GoogleStrategy {
  async handleCallback(_code: string, _state?: string): Promise<BaseUser> {
    return { id: 'u-google', email: 'google@test.com', loginProvider: 'google' };
  }
  async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
    return { id: p.id, email: p.email };
  }
}

class TestGithubStrategy extends GithubStrategy {
  async handleCallback(_code: string, _state?: string): Promise<BaseUser> {
    return { id: 'u-github', email: 'github@test.com', loginProvider: 'github' };
  }
  async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
    return { id: p.id, email: p.email };
  }
}

class TestDiscordStrategy extends GenericOAuthStrategy {
  async handleCallback(_code: string): Promise<BaseUser> {
    return { id: 'u-discord', email: 'discord@test.com', loginProvider: 'discord' };
  }
  async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
    return { id: p.id, email: p.email };
  }
}

function parseCookieHeader(res: request.Response, cookieName: string): { value?: string; raw?: string } {
  const cookies = (res.headers['set-cookie'] as string[]) ?? [];
  const raw = cookies.find(c => c.startsWith(`${cookieName}=`));
  if (!raw) return {};
  const value = raw.split(';')[0].split('=')[1];
  return { value, raw };
}

function decodeNonceFromState(state: string): string {
  try {
    const parsed = JSON.parse(Buffer.from(state, 'base64url').toString('utf8'));
    return parsed.n ?? state;
  } catch {
    return state;
  }
}

describe('Issue #14: OAuth state nonce CSRF protection', () => {
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

  describe('Google OAuth CSRF protection', () => {
    it('sets HttpOnly Lax oauth_nonce_google cookie on GET /oauth/google matching state nonce', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, oauthConfig, {
        googleStrategy: new TestGoogleStrategy(oauthConfig),
      }));

      const res = await request(await listen(app)).get('/auth/oauth/google');
      expect(res.status).toBe(302);
      const location = new URL(res.headers['location'] as string);
      const state = location.searchParams.get('state')!;
      expect(state).toBeTruthy();

      const { value: cookieNonce, raw } = parseCookieHeader(res, 'oauth_nonce_google');
      expect(cookieNonce).toBeDefined();
      expect(raw?.toLowerCase()).toContain('httponly');
      expect(raw?.toLowerCase()).toContain('samesite=lax');

      const stateNonce = decodeNonceFromState(state);
      expect(stateNonce).toBe(cookieNonce);
    });

    it('rejects callback with 400 INVALID_OAUTH_STATE when cookie is missing', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, oauthConfig, {
        googleStrategy: new TestGoogleStrategy(oauthConfig),
      }));

      // Initiate to get valid state
      const initRes = await request(await listen(app)).get('/auth/oauth/google');
      const location = new URL(initRes.headers['location'] as string);
      const state = location.searchParams.get('state')!;

      // Call callback WITHOUT sending the cookie
      const res = await request(await listen(app)).get(`/auth/oauth/google/callback?code=fake-code&state=${encodeURIComponent(state)}`);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OAUTH_STATE');
    });

    it('rejects callback with 400 INVALID_OAUTH_STATE when cookie nonce does not match state', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, oauthConfig, {
        googleStrategy: new TestGoogleStrategy(oauthConfig),
      }));

      const initRes = await request(await listen(app)).get('/auth/oauth/google');
      const location = new URL(initRes.headers['location'] as string);
      const state = location.searchParams.get('state')!;

      // Call callback with mismatched cookie
      const res = await request(await listen(app))
        .get(`/auth/oauth/google/callback?code=fake-code&state=${encodeURIComponent(state)}`)
        .set('Cookie', 'oauth_nonce_google=tampered_or_attacker_nonce');

      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OAUTH_STATE');
    });

    it('accepts callback when cookie matches state nonce and clears the cookie', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, oauthConfig, {
        googleStrategy: new TestGoogleStrategy(oauthConfig),
      }));

      const initRes = await request(await listen(app)).get('/auth/oauth/google');
      const location = new URL(initRes.headers['location'] as string);
      const state = location.searchParams.get('state')!;
      const { value: cookieNonce } = parseCookieHeader(initRes, 'oauth_nonce_google');

      const res = await request(await listen(app))
        .get(`/auth/oauth/google/callback?code=fake-code&state=${encodeURIComponent(state)}`)
        .set('Cookie', `oauth_nonce_google=${cookieNonce}`);

      // Successful login redirects
      expect(res.status).toBe(302);
      expect(res.headers['location']).toBe('https://app.example.com');

      // Cookie should be cleared
      const setCookies = (res.headers['set-cookie'] as string[]) ?? [];
      const cleared = setCookies.find(c => c.startsWith('oauth_nonce_google='));
      expect(cleared).toBeDefined();
      // Cleared cookie either has empty value or max-age=0 / expires in the past
      expect(cleared).toMatch(/oauth_nonce_google=(;|.*Expires=.*1970|.*Max-Age=0)/i);
    });
  });

  describe('GitHub OAuth CSRF protection', () => {
    it('sets cookie on GET /oauth/github and validates on callback', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, oauthConfig, {
        githubStrategy: new TestGithubStrategy(oauthConfig),
      }));

      // 1. Initiate
      const initRes = await request(await listen(app)).get('/auth/oauth/github');
      expect(initRes.status).toBe(302);
      const location = new URL(initRes.headers['location'] as string);
      const state = location.searchParams.get('state')!;
      const { value: cookieNonce } = parseCookieHeader(initRes, 'oauth_nonce_github');
      expect(cookieNonce).toBeDefined();

      // 2. Mismatched cookie returns 400
      const badRes = await request(await listen(app))
        .get(`/auth/oauth/github/callback?code=fake-code&state=${encodeURIComponent(state)}`)
        .set('Cookie', 'oauth_nonce_github=wrong-nonce');
      expect(badRes.status).toBe(400);
      expect(badRes.body.code).toBe('INVALID_OAUTH_STATE');

      // 3. Matching cookie succeeds and clears cookie
      const goodRes = await request(await listen(app))
        .get(`/auth/oauth/github/callback?code=fake-code&state=${encodeURIComponent(state)}`)
        .set('Cookie', `oauth_nonce_github=${cookieNonce}`);
      expect(goodRes.status).toBe(302);

      const setCookies = (goodRes.headers['set-cookie'] as string[]) ?? [];
      const cleared = setCookies.find(c => c.startsWith('oauth_nonce_github='));
      expect(cleared).toBeDefined();
    });
  });

  describe('Generic OAuth strategy CSRF protection', () => {
    it('sets cookie on GET /oauth/discord and validates on callback', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, oauthConfig, {
        oauthStrategies: [new TestDiscordStrategy(discordCfg)],
      }));

      // 1. Initiate
      const initRes = await request(await listen(app)).get('/auth/oauth/discord');
      expect(initRes.status).toBe(302);
      const location = new URL(initRes.headers['location'] as string);
      const state = location.searchParams.get('state')!;
      const { value: cookieNonce } = parseCookieHeader(initRes, 'oauth_nonce_discord');
      expect(cookieNonce).toBeDefined();

      // 2. Mismatched cookie returns 400
      const badRes = await request(await listen(app))
        .get(`/auth/oauth/discord/callback?code=fake-code&state=${encodeURIComponent(state)}`)
        .set('Cookie', 'oauth_nonce_discord=wrong-nonce');
      expect(badRes.status).toBe(400);
      expect(badRes.body.code).toBe('INVALID_OAUTH_STATE');

      // 3. Matching cookie succeeds
      const goodRes = await request(await listen(app))
        .get(`/auth/oauth/discord/callback?code=fake-code&state=${encodeURIComponent(state)}`)
        .set('Cookie', `oauth_nonce_discord=${cookieNonce}`);
      expect(goodRes.status).toBe(302);
    });

    it('rejects callback with 400 when attacker provides code with no state and victim has no cookie', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, oauthConfig, {
        googleStrategy: new TestGoogleStrategy(oauthConfig),
      }));

      // Attacker crafts callback URL without state; victim never initiated Google flow (no cookie)
      const res = await request(await listen(app)).get('/auth/oauth/google/callback?code=attacker-stolen-code');
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OAUTH_STATE');
    });

    it('rejects generic strategy callback with 400 when cookie is missing', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, oauthConfig, {
        oauthStrategies: [new TestDiscordStrategy(discordCfg)],
      }));

      const res = await request(await listen(app)).get('/auth/oauth/discord/callback?code=fake-code&state=xyz');
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OAUTH_STATE');
    });

    it('rejects generic strategy callback with 400 when both state and cookie are missing', async () => {
      const app = express();
      app.use('/auth', createAuthRouter(userStore, oauthConfig, {
        oauthStrategies: [new TestDiscordStrategy(discordCfg)],
      }));

      const res = await request(await listen(app)).get('/auth/oauth/discord/callback?code=fake-code');
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('INVALID_OAUTH_STATE');
    });
  });
});
