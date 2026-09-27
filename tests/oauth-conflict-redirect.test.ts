import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createAuthRouter } from '../src/router/auth.router';
import { IUserStore } from '../src/interfaces/user-store.interface';
import { BaseUser } from '../src/models/user.model';
import { AuthConfig } from '../src/models/auth-config.model';
import { AuthError } from '../src/models/errors';
import { GoogleStrategy } from '../src/strategies/oauth/google.strategy';
import { GithubStrategy } from '../src/strategies/oauth/github.strategy';
import { GenericOAuthStrategy, GenericOAuthProviderConfig } from '../src/strategies/oauth/generic-oauth.strategy';

const oauthConfig: AuthConfig = {
  accessTokenSecret: 'test-access-secret-conflict-redirect-long',
  refreshTokenSecret: 'test-refresh-secret-conflict-redirect-long',
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

class ConflictGoogleStrategy extends GoogleStrategy {
  async handleCallback(_code: string, _state?: string): Promise<BaseUser> {
    throw new AuthError('Account conflict', 'OAUTH_ACCOUNT_CONFLICT', 409, {
      email: 'conflict@test.com',
      providerAccountId: 'google-conflict-123',
    });
  }
  async findOrCreateUser(): Promise<BaseUser> {
    throw new Error('Not reached');
  }
}

class ConflictGithubStrategy extends GithubStrategy {
  async handleCallback(_code: string, _state?: string): Promise<BaseUser> {
    throw new AuthError('Account conflict', 'OAUTH_ACCOUNT_CONFLICT', 409, {
      email: 'conflict@test.com',
      providerAccountId: 'github-conflict-123',
    });
  }
  async findOrCreateUser(): Promise<BaseUser> {
    throw new Error('Not reached');
  }
}

class ConflictDiscordStrategy extends GenericOAuthStrategy {
  async handleCallback(_code: string): Promise<BaseUser> {
    throw new AuthError('Account conflict', 'OAUTH_ACCOUNT_CONFLICT', 409, {
      email: 'conflict@test.com',
      providerAccountId: 'discord-conflict-123',
    });
  }
  async findOrCreateUser(): Promise<BaseUser> {
    throw new Error('Not reached');
  }
}

function parseCookie(res: request.Response, cookieName: string): string | undefined {
  const cookies = (res.headers['set-cookie'] as string[]) ?? [];
  const raw = cookies.find(c => c.startsWith(`${cookieName}=`));
  if (!raw) return undefined;
  return raw.split(';')[0].split('=')[1];
}

describe('Issue #15: OAuth account conflict redirect path pollution fix', () => {
  let userStore: IUserStore;

  beforeEach(() => {
    userStore = {
      findByEmail: vi.fn().mockResolvedValue(null),
      findById: vi.fn().mockResolvedValue(null),
      create: vi.fn(),
      updateRefreshToken: vi.fn().mockResolvedValue(undefined),
      updateLastLogin: vi.fn().mockResolvedValue(undefined),
      updateResetToken: vi.fn().mockResolvedValue(undefined),
      updatePassword: vi.fn().mockResolvedValue(undefined),
    };
  });

  it('Google OAuth: conflict redirect uses clean origin and does not pollute path with return_path', async () => {
    const app = express();
    app.use('/auth', createAuthRouter(userStore, oauthConfig, {
      googleStrategy: new ConflictGoogleStrategy(oauthConfig),
    }));

    // Initiate OAuth flow with return_path = /dashboard/profile
    const initRes = await request(app).get('/auth/oauth/google?return_path=/dashboard/profile');
    expect(initRes.status).toBe(302);
    const location = new URL(initRes.headers['location'] as string);
    const state = location.searchParams.get('state')!;
    const cookieNonce = parseCookie(initRes, 'oauth_nonce_google');

    // Callback triggers conflict
    const res = await request(app)
      .get(`/auth/oauth/google/callback?code=abc&state=${encodeURIComponent(state)}`)
      .set('Cookie', `oauth_nonce_google=${cookieNonce}`);

    expect(res.status).toBe(302);
    const redirectLocation = res.headers['location'] as string;

    // Verify it redirects to the account conflict page on the base origin
    expect(redirectLocation).toContain('https://app.example.com');
    expect(redirectLocation).toContain('/account-conflict');
    expect(redirectLocation).toContain('provider=google');
    expect(redirectLocation).toContain('code=OAUTH_ACCOUNT_CONFLICT');
    expect(redirectLocation).toContain('email=conflict%40test.com');

    // Crucial: return_path must NOT be prepended to the account conflict path
    expect(redirectLocation).not.toContain('/dashboard/profile');
  });

  it('GitHub OAuth: conflict redirect uses clean origin without return_path pollution', async () => {
    const app = express();
    app.use('/auth', createAuthRouter(userStore, oauthConfig, {
      githubStrategy: new ConflictGithubStrategy(oauthConfig),
    }));

    const initRes = await request(app).get('/auth/oauth/github?return_path=/user/settings');
    expect(initRes.status).toBe(302);
    const location = new URL(initRes.headers['location'] as string);
    const state = location.searchParams.get('state')!;
    const cookieNonce = parseCookie(initRes, 'oauth_nonce_github');

    const res = await request(app)
      .get(`/auth/oauth/github/callback?code=abc&state=${encodeURIComponent(state)}`)
      .set('Cookie', `oauth_nonce_github=${cookieNonce}`);

    expect(res.status).toBe(302);
    const redirectLocation = res.headers['location'] as string;

    expect(redirectLocation).toContain('https://app.example.com');
    expect(redirectLocation).toContain('/account-conflict');
    expect(redirectLocation).toContain('provider=github');
    expect(redirectLocation).not.toContain('/user/settings');
  });

  it('Generic OAuth: conflict redirect uses clean origin without return_path pollution', async () => {
    const app = express();
    app.use('/auth', createAuthRouter(userStore, oauthConfig, {
      oauthStrategies: [new ConflictDiscordStrategy(discordCfg)],
    }));

    const initRes = await request(app).get('/auth/oauth/discord?return_path=/guild/settings');
    expect(initRes.status).toBe(302);
    const location = new URL(initRes.headers['location'] as string);
    const state = location.searchParams.get('state')!;
    const cookieNonce = parseCookie(initRes, 'oauth_nonce_discord');

    const res = await request(app)
      .get(`/auth/oauth/discord/callback?code=abc&state=${encodeURIComponent(state)}`)
      .set('Cookie', `oauth_nonce_discord=${cookieNonce}`);

    expect(res.status).toBe(302);
    const redirectLocation = res.headers['location'] as string;

    expect(redirectLocation).toContain('https://app.example.com');
    expect(redirectLocation).toContain('/account-conflict');
    expect(redirectLocation).toContain('provider=discord');
    expect(redirectLocation).not.toContain('/guild/settings');
  });
});
