/**
 * Tests for the new features from the authentication flow improvements:
 * - Magic link first login counts as email verification
 * - 2FA disable blocked when system/per-user require2FA is set
 * - OAuth login triggers 2FA challenge when required
 * - Linked accounts endpoints
 * - Generic OAuth strategy
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createAuthRouter } from '../src/router/auth.router';
import { IUserStore } from '../src/interfaces/user-store.interface';
import { ILinkedAccountsStore, LinkedAccount } from '../src/interfaces/linked-accounts-store.interface';
import { IPendingLinkStore } from '../src/interfaces/pending-link-store.interface';
import { ISettingsStore, AuthSettings } from '../src/interfaces/settings-store.interface';
import { BaseUser } from '../src/models/user.model';
import { AuthConfig } from '../src/models/auth-config.model';
import { TokenService } from '../src/services/token.service';
import { PasswordService } from '../src/services/password.service';
import { GenericOAuthStrategy, GenericOAuthProviderConfig } from '../src/strategies/oauth/generic-oauth.strategy';
import { AuthEventBus } from '../src/events/auth-event-bus';
import { AuthEventNames } from '../src/events/auth-event-names';

const tokenService = new TokenService();
const passwordService = new PasswordService();

const config: AuthConfig = {
  accessTokenSecret: 'test-access-secret-very-long-and-secure',
  refreshTokenSecret: 'test-refresh-secret-very-long-and-secure',
  email: {
    siteUrl: 'http://localhost:3000',
    sendMagicLink: vi.fn().mockResolvedValue(undefined),
  },
};

function makeToken(userId: string): string {
  return tokenService.generateTokenPair({ sub: userId, email: 'user@test.com' }, config).accessToken;
}

// ---------------------------------------------------------------------------
// Magic link first login = email verification
// ---------------------------------------------------------------------------
describe('POST /auth/magic-link/verify — email verification on first login', () => {
  let userStore: IUserStore & { updateEmailVerified: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    const magicToken = 'valid-magic-token';
    const expiry = new Date(Date.now() + 60_000);
    const user: BaseUser = {
      id: 'u1',
      email: 'user@test.com',
      isEmailVerified: false,
      magicLinkToken: magicToken,
      magicLinkTokenExpiry: expiry,
    };
    userStore = {
      findByEmail: vi.fn().mockResolvedValue(user),
      findById: vi.fn().mockResolvedValue(user),
      create: vi.fn(),
      updateRefreshToken: vi.fn().mockResolvedValue(undefined),
      updateLastLogin: vi.fn().mockResolvedValue(undefined),
      updateResetToken: vi.fn().mockResolvedValue(undefined),
      updatePassword: vi.fn().mockResolvedValue(undefined),
      updateTotpSecret: vi.fn().mockResolvedValue(undefined),
      updateMagicLinkToken: vi.fn().mockResolvedValue(undefined),
      updateSmsCode: vi.fn().mockResolvedValue(undefined),
      findByMagicLinkToken: vi.fn().mockResolvedValue(user),
      updateEmailVerified: vi.fn().mockResolvedValue(undefined),
    };
  });

  it('marks email as verified when user is not yet verified', async () => {
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, config));
    const res = await request(app)
      .post('/auth/magic-link/verify')
      .send({ token: 'valid-magic-token' });
    expect(res.status).toBe(200);
    expect(userStore.updateEmailVerified).toHaveBeenCalledWith('u1', true);
  });

  it('does not call updateEmailVerified when already verified', async () => {
    // Override findByMagicLinkToken to return an already-verified user
    const magicToken = 'valid-magic-token';
    const expiry = new Date(Date.now() + 60_000);
    const verifiedUser: BaseUser = {
      id: 'u1',
      email: 'user@test.com',
      isEmailVerified: true,
      magicLinkToken: magicToken,
      magicLinkTokenExpiry: expiry,
    };
    userStore.findByMagicLinkToken = vi.fn().mockResolvedValue(verifiedUser);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, config));
    const res = await request(app)
      .post('/auth/magic-link/verify')
      .send({ token: 'valid-magic-token' });
    expect(res.status).toBe(200);
    expect(userStore.updateEmailVerified).not.toHaveBeenCalled();
  });

  it('works when userStore does not implement updateEmailVerified', async () => {
    delete (userStore as Partial<typeof userStore>).updateEmailVerified;
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, config));
    const res = await request(app)
      .post('/auth/magic-link/verify')
      .send({ token: 'valid-magic-token' });
    expect(res.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// 2FA disable — system/per-user require2FA check
// ---------------------------------------------------------------------------
describe('POST /auth/2fa/disable', () => {
  function makeUserStore(user: BaseUser): IUserStore {
    return {
      findByEmail: vi.fn().mockResolvedValue(user),
      findById: vi.fn().mockResolvedValue(user),
      create: vi.fn(),
      updateRefreshToken: vi.fn().mockResolvedValue(undefined),
      updateLastLogin: vi.fn().mockResolvedValue(undefined),
      updateResetToken: vi.fn().mockResolvedValue(undefined),
      updatePassword: vi.fn().mockResolvedValue(undefined),
      updateTotpSecret: vi.fn().mockResolvedValue(undefined),
      updateMagicLinkToken: vi.fn().mockResolvedValue(undefined),
      updateSmsCode: vi.fn().mockResolvedValue(undefined),
    };
  }

  it('allows disabling 2FA when not required', async () => {
    const user: BaseUser = { id: 'u1', email: 'user@test.com', isTotpEnabled: true, totpSecret: 'secret', require2FA: false };
    const store = makeUserStore(user);
    store.updateTotpSecret = vi.fn().mockResolvedValue(undefined);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config));
    const token = makeToken('u1');
    const res = await request(app)
      .post('/auth/2fa/disable')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Auth-Strategy', 'bearer');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('blocks disabling 2FA when user.require2FA is true', async () => {
    const user: BaseUser = { id: 'u1', email: 'user@test.com', isTotpEnabled: true, totpSecret: 'secret', require2FA: true };
    const store = makeUserStore(user);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config));
    const token = makeToken('u1');
    const res = await request(app)
      .post('/auth/2fa/disable')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Auth-Strategy', 'bearer');
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('2FA_REQUIRED');
  });

  it('blocks disabling 2FA when system require2FA is true', async () => {
    const user: BaseUser = { id: 'u1', email: 'user@test.com', isTotpEnabled: true, totpSecret: 'secret', require2FA: false };
    const store = makeUserStore(user);
    const settingsStore: ISettingsStore = {
      getSettings: vi.fn().mockResolvedValue({ require2FA: true } as AuthSettings),
      updateSettings: vi.fn().mockResolvedValue(undefined),
    };
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { settingsStore }));
    const token = makeToken('u1');
    const res = await request(app)
      .post('/auth/2fa/disable')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Auth-Strategy', 'bearer');
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('2FA_REQUIRED');
  });

  it('allows disabling 2FA when system require2FA is false', async () => {
    const user: BaseUser = { id: 'u1', email: 'user@test.com', isTotpEnabled: true, totpSecret: 'secret' };
    const store = makeUserStore(user);
    store.updateTotpSecret = vi.fn().mockResolvedValue(undefined);
    const settingsStore: ISettingsStore = {
      getSettings: vi.fn().mockResolvedValue({ require2FA: false } as AuthSettings),
      updateSettings: vi.fn().mockResolvedValue(undefined),
    };
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { settingsStore }));
    const token = makeToken('u1');
    const res = await request(app)
      .post('/auth/2fa/disable')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Auth-Strategy', 'bearer');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Linked accounts endpoints
// ---------------------------------------------------------------------------
describe('Linked accounts endpoints', () => {
  let linkedAccountsStore: ILinkedAccountsStore;
  const linkedAccounts: LinkedAccount[] = [
    { provider: 'google', providerAccountId: 'g123', email: 'user@gmail.com', linkedAt: new Date() },
    { provider: 'github', providerAccountId: 'gh456', email: 'user@github.com', linkedAt: new Date() },
  ];

  beforeEach(() => {
    linkedAccountsStore = {
      getLinkedAccounts: vi.fn().mockResolvedValue(linkedAccounts),
      linkAccount: vi.fn().mockResolvedValue(undefined),
      unlinkAccount: vi.fn().mockResolvedValue(undefined),
      findUserByProviderAccount: vi.fn().mockResolvedValue(null),
    };
  });

  function makeStore(): IUserStore {
    const user: BaseUser = { id: 'u1', email: 'user@test.com' };
    return {
      findByEmail: vi.fn().mockResolvedValue(user),
      findById: vi.fn().mockResolvedValue(user),
      create: vi.fn(),
      updateRefreshToken: vi.fn().mockResolvedValue(undefined),
      updateLastLogin: vi.fn().mockResolvedValue(undefined),
      updateResetToken: vi.fn().mockResolvedValue(undefined),
      updatePassword: vi.fn().mockResolvedValue(undefined),
      updateTotpSecret: vi.fn().mockResolvedValue(undefined),
      updateMagicLinkToken: vi.fn().mockResolvedValue(undefined),
      updateSmsCode: vi.fn().mockResolvedValue(undefined),
    };
  }

  it('GET /linked-accounts returns linked accounts for authenticated user', async () => {
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(makeStore(), config, { linkedAccountsStore }));
    const token = makeToken('u1');
    const res = await request(app)
      .get('/auth/linked-accounts')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Auth-Strategy', 'bearer');
    expect(res.status).toBe(200);
    expect(res.body.linkedAccounts).toHaveLength(2);
    expect(linkedAccountsStore.getLinkedAccounts).toHaveBeenCalledWith('u1');
  });

  it('GET /linked-accounts returns 403 without auth', async () => {
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(makeStore(), config, { linkedAccountsStore }));
    const res = await request(app).get('/auth/linked-accounts');
    expect(res.status).toBe(403);
  });

  it('DELETE /linked-accounts/:provider/:providerAccountId unlinks account', async () => {
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(makeStore(), config, { linkedAccountsStore }));
    const token = makeToken('u1');
    const res = await request(app)
      .delete('/auth/linked-accounts/google/g123')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Auth-Strategy', 'bearer');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(linkedAccountsStore.unlinkAccount).toHaveBeenCalledWith('u1', 'google', 'g123');
  });

  it('linked-accounts endpoints not mounted when store not provided', async () => {
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(makeStore(), config));
    const token = makeToken('u1');
    const res = await request(app)
      .get('/auth/linked-accounts')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Auth-Strategy', 'bearer');
    expect(res.status).toBe(404);
  });
});

// ---------------------------------------------------------------------------
// GenericOAuthStrategy
// ---------------------------------------------------------------------------
describe('GenericOAuthStrategy', () => {
  const cfg: GenericOAuthProviderConfig = {
    name: 'discord',
    clientId: 'client-id',
    clientSecret: 'client-secret',
    callbackUrl: 'https://app.example.com/auth/oauth/discord/callback',
    authorizationUrl: 'https://discord.com/api/oauth2/authorize',
    tokenUrl: 'https://discord.com/api/oauth2/token',
    userInfoUrl: 'https://discord.com/api/users/@me',
    scope: 'identify email',
  };

  class TestDiscordStrategy extends GenericOAuthStrategy {
    async findOrCreateUser(profile: { id: string; email: string }): Promise<BaseUser> {
      return { id: profile.id, email: profile.email };
    }
  }

  it('has the correct name', () => {
    const s = new TestDiscordStrategy(cfg);
    expect(s.name).toBe('discord');
  });

  it('generates authorization URL with correct params', () => {
    const s = new TestDiscordStrategy(cfg);
    const url = s.getAuthorizationUrl('mystate');
    expect(url).toContain('https://discord.com/api/oauth2/authorize');
    expect(url).toContain('client_id=client-id');
    expect(url).toContain('scope=identify+email');
    expect(url).toContain('state=mystate');
    expect(url).toContain('response_type=code');
  });

  it('generates authorization URL without state when omitted', () => {
    const s = new TestDiscordStrategy(cfg);
    const url = s.getAuthorizationUrl();
    expect(url).not.toContain('state=');
  });

  it('supports array scope', () => {
    const cfgArrayScope: GenericOAuthProviderConfig = { ...cfg, scope: ['identify', 'email'] };
    class ArrayScopeStrategy extends GenericOAuthStrategy {
      async findOrCreateUser(profile: { id: string; email: string }): Promise<BaseUser> {
        return { id: profile.id, email: profile.email };
      }
    }
    const s = new ArrayScopeStrategy(cfgArrayScope);
    const url = s.getAuthorizationUrl();
    expect(url).toContain('scope=identify+email');
  });

  it('generic OAuth routes are mounted when oauthStrategies provided', async () => {
    const discordStrategy = new TestDiscordStrategy(cfg);
    const userStore: IUserStore = {
      findByEmail: vi.fn(),
      findById: vi.fn(),
      create: vi.fn(),
      updateRefreshToken: vi.fn(),
      updateLastLogin: vi.fn(),
      updateResetToken: vi.fn(),
      updatePassword: vi.fn(),
      updateTotpSecret: vi.fn(),
      updateMagicLinkToken: vi.fn(),
      updateSmsCode: vi.fn(),
    };
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, config, { oauthStrategies: [discordStrategy] }));
    // The route should exist (redirect to Discord), not 404
    const res = await request(app).get('/auth/oauth/discord');
    expect(res.status).toBe(302);
    expect(res.headers['location']).toContain('discord.com');
  });
});

// ---------------------------------------------------------------------------
// link-request / link-verify endpoints
// ---------------------------------------------------------------------------
describe('POST /auth/link-request and POST /auth/link-verify', () => {
  let linkedAccountsStore: ILinkedAccountsStore;

  function makeStoreWithLinkToken(user: BaseUser): IUserStore {
    return {
      findByEmail: vi.fn().mockResolvedValue(null),
      findById: vi.fn().mockResolvedValue(user),
      create: vi.fn(),
      updateRefreshToken: vi.fn().mockResolvedValue(undefined),
      updateLastLogin: vi.fn().mockResolvedValue(undefined),
      updateResetToken: vi.fn().mockResolvedValue(undefined),
      updatePassword: vi.fn().mockResolvedValue(undefined),
      updateTotpSecret: vi.fn().mockResolvedValue(undefined),
      updateMagicLinkToken: vi.fn().mockResolvedValue(undefined),
      updateSmsCode: vi.fn().mockResolvedValue(undefined),
      updateAccountLinkToken: vi.fn().mockResolvedValue(undefined),
      findByAccountLinkToken: vi.fn().mockImplementation((token: string) =>
        Promise.resolve(token === user.accountLinkToken ? user : null)
      ),
    };
  }

  beforeEach(() => {
    linkedAccountsStore = {
      getLinkedAccounts: vi.fn().mockResolvedValue([]),
      linkAccount: vi.fn().mockResolvedValue(undefined),
      unlinkAccount: vi.fn().mockResolvedValue(undefined),
      findUserByProviderAccount: vi.fn().mockResolvedValue(null),
    };
  });

  it('POST /link-request sends a verification email and stores the token', async () => {
    const sendVerificationEmail = vi.fn().mockResolvedValue(undefined);
    const cfgWithEmail: AuthConfig = {
      ...config,
      email: { ...config.email, siteUrl: 'http://localhost:3000', sendVerificationEmail },
    };
    const user: BaseUser = { id: 'u1', email: 'user@test.com' };
    const store = makeStoreWithLinkToken(user);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, cfgWithEmail, { linkedAccountsStore }));
    const token = makeToken('u1');
    const res = await request(app)
      .post('/auth/link-request')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Auth-Strategy', 'bearer')
      .send({ email: 'secondary@example.com', provider: 'email' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(store.updateAccountLinkToken).toHaveBeenCalledWith(
      'u1', 'secondary@example.com', 'email', expect.any(String), expect.any(Date)
    );
    expect(sendVerificationEmail).toHaveBeenCalledWith(
      'secondary@example.com', expect.any(String), expect.stringContaining('/auth/link-verify?token='), undefined
    );
  });

  it('POST /link-request returns 400 when email is missing', async () => {
    const user: BaseUser = { id: 'u1', email: 'user@test.com' };
    const store = makeStoreWithLinkToken(user);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { linkedAccountsStore }));
    const token = makeToken('u1');
    const res = await request(app)
      .post('/auth/link-request')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Auth-Strategy', 'bearer')
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('EMAIL_REQUIRED');
  });

  it('POST /link-request returns 401 without auth and no pendingLinkStore', async () => {
    const user: BaseUser = { id: 'u1', email: 'user@test.com' };
    const store = makeStoreWithLinkToken(user);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { linkedAccountsStore }));
    const res = await request(app)
      .post('/auth/link-request')
      .send({ email: 'secondary@example.com' });
    expect(res.status).toBe(401);
  });

  it('POST /link-request returns 500 when store does not implement updateAccountLinkToken', async () => {
    const user: BaseUser = { id: 'u1', email: 'user@test.com' };
    // Store without updateAccountLinkToken
    const storeNoLink: IUserStore = {
      findByEmail: vi.fn().mockResolvedValue(null),
      findById: vi.fn().mockResolvedValue(user),
      create: vi.fn(),
      updateRefreshToken: vi.fn().mockResolvedValue(undefined),
      updateLastLogin: vi.fn().mockResolvedValue(undefined),
      updateResetToken: vi.fn().mockResolvedValue(undefined),
      updatePassword: vi.fn().mockResolvedValue(undefined),
      updateTotpSecret: vi.fn().mockResolvedValue(undefined),
      updateMagicLinkToken: vi.fn().mockResolvedValue(undefined),
      updateSmsCode: vi.fn().mockResolvedValue(undefined),
    };
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(storeNoLink, config, { linkedAccountsStore }));
    const token = makeToken('u1');
    const res = await request(app)
      .post('/auth/link-request')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Auth-Strategy', 'bearer')
      .send({ email: 'secondary@example.com' });
    expect(res.status).toBe(500);
    expect(res.body.code).toBe('NOT_IMPLEMENTED');
  });

  it('POST /link-verify links the account using the token', async () => {
    const linkToken = 'valid-link-token';
    const user: BaseUser = {
      id: 'u1',
      email: 'user@test.com',
      accountLinkToken: linkToken,
      accountLinkTokenExpiry: new Date(Date.now() + 60_000),
      accountLinkPendingEmail: 'secondary@example.com',
      accountLinkPendingProvider: 'email',
    };
    const store = makeStoreWithLinkToken(user);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { linkedAccountsStore }));
    const res = await request(app)
      .post('/auth/link-verify')
      .send({ token: linkToken });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(linkedAccountsStore.linkAccount).toHaveBeenCalledWith('u1', {
      provider: 'email',
      providerAccountId: 'secondary@example.com',
      email: 'secondary@example.com',
      linkedAt: expect.any(Date),
    });
    expect(store.updateAccountLinkToken).toHaveBeenCalledWith('u1', null, null, null, null);
  });

  it('POST /link-verify returns 400 for invalid token', async () => {
    const user: BaseUser = {
      id: 'u1',
      email: 'user@test.com',
      accountLinkToken: 'valid-link-token',
      accountLinkTokenExpiry: new Date(Date.now() + 60_000),
      accountLinkPendingEmail: 'secondary@example.com',
    };
    const store = makeStoreWithLinkToken(user);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { linkedAccountsStore }));
    const res = await request(app)
      .post('/auth/link-verify')
      .send({ token: 'wrong-token' });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('INVALID_LINK_TOKEN');
  });

  it('POST /link-verify returns 400 for expired token', async () => {
    const linkToken = 'expired-link-token';
    const user: BaseUser = {
      id: 'u1',
      email: 'user@test.com',
      accountLinkToken: linkToken,
      accountLinkTokenExpiry: new Date(Date.now() - 1000), // already expired
      accountLinkPendingEmail: 'secondary@example.com',
    };
    const store = makeStoreWithLinkToken(user);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { linkedAccountsStore }));
    const res = await request(app)
      .post('/auth/link-verify')
      .send({ token: linkToken });
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('LINK_TOKEN_EXPIRED');
  });

  it('POST /link-verify returns 400 when token is missing from body', async () => {
    const user: BaseUser = { id: 'u1', email: 'user@test.com' };
    const store = makeStoreWithLinkToken(user);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { linkedAccountsStore }));
    const res = await request(app)
      .post('/auth/link-verify')
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.code).toBe('TOKEN_REQUIRED');
  });

  it('link-request/link-verify endpoints not mounted when linkedAccountsStore not provided', async () => {
    const user: BaseUser = { id: 'u1', email: 'user@test.com' };
    const store = makeStoreWithLinkToken(user);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config));
    const token = makeToken('u1');
    const reqRes = await request(app)
      .post('/auth/link-request')
      .set('Authorization', `Bearer ${token}`)
      .set('X-Auth-Strategy', 'bearer')
      .send({ email: 'secondary@example.com' });
    expect(reqRes.status).toBe(404);
    const verRes = await request(app)
      .post('/auth/link-verify')
      .send({ token: 'some-token' });
    expect(verRes.status).toBe(404);
  });

  it('POST /link-request unauthenticated conflict-linking: succeeds when pendingLinkStore has a match', async () => {
    const sendVerificationEmail = vi.fn().mockResolvedValue(undefined);
    const cfgWithEmail: AuthConfig = {
      ...config,
      email: { ...config.email, siteUrl: 'http://localhost:3000', sendVerificationEmail },
    };
    const user: BaseUser = { id: 'u1', email: 'conflict@example.com' };
    const store = makeStoreWithLinkToken(user);
    (store.findByEmail as ReturnType<typeof vi.fn>).mockResolvedValue(user);
    const pendingLinkStore: IPendingLinkStore = {
      stash: vi.fn().mockResolvedValue(undefined),
      retrieve: vi.fn().mockResolvedValue({ providerAccountId: 'github-id-123' }),
      remove: vi.fn().mockResolvedValue(undefined),
    };
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, cfgWithEmail, { linkedAccountsStore, pendingLinkStore }));
    const res = await request(app)
      .post('/auth/link-request')
      .send({ email: 'conflict@example.com', provider: 'github' });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(pendingLinkStore.retrieve).toHaveBeenCalledWith('conflict@example.com', 'github');
    expect(store.updateAccountLinkToken).toHaveBeenCalledWith(
      'u1', 'conflict@example.com', 'github', expect.any(String), expect.any(Date)
    );
  });

  it('POST /link-request returns 401 when pendingLinkStore has no matching entry', async () => {
    const user: BaseUser = { id: 'u1', email: 'conflict@example.com' };
    const store = makeStoreWithLinkToken(user);
    const pendingLinkStore: IPendingLinkStore = {
      stash: vi.fn().mockResolvedValue(undefined),
      retrieve: vi.fn().mockResolvedValue(null),
      remove: vi.fn().mockResolvedValue(undefined),
    };
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config, { linkedAccountsStore, pendingLinkStore }));
    const res = await request(app)
      .post('/auth/link-request')
      .send({ email: 'conflict@example.com', provider: 'github' });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('UNAUTHORIZED');
  });
});

// ---------------------------------------------------------------------------
// OAuth mobile flow — redirect and bearer 2FA completion
// ---------------------------------------------------------------------------
describe('OAuth mobile flow (siteUrl = custom scheme, bearer 2FA completion)', () => {
  const mobileSiteUrl = 'myapp://auth';
  const mobileOAuthConfig: AuthConfig = {
    ...config,
    email: {
      ...config.email,
      siteUrl: mobileSiteUrl,
    },
  };

  const discordCfg: GenericOAuthProviderConfig = {
    name: 'discord',
    clientId: 'client-id',
    clientSecret: 'client-secret',
    callbackUrl: 'https://api.example.com/auth/oauth/discord/callback',
    authorizationUrl: 'https://discord.com/api/oauth2/authorize',
    tokenUrl: 'https://discord.com/api/oauth2/token',
    userInfoUrl: 'https://discord.com/api/users/@me',
    scope: 'identify email',
  };

  function makeOAuthUserStore(user: BaseUser): IUserStore {
    return {
      findByEmail: vi.fn().mockResolvedValue(user),
      findById: vi.fn().mockResolvedValue(user),
      create: vi.fn(),
      updateRefreshToken: vi.fn().mockResolvedValue(undefined),
      updateLastLogin: vi.fn().mockResolvedValue(undefined),
      updateResetToken: vi.fn().mockResolvedValue(undefined),
      updatePassword: vi.fn().mockResolvedValue(undefined),
      updateTotpSecret: vi.fn().mockResolvedValue(undefined),
      updateMagicLinkToken: vi.fn().mockResolvedValue(undefined),
      updateSmsCode: vi.fn().mockResolvedValue(undefined),
    };
  }

  it('GET /auth/oauth/:name redirects to provider authorization URL', async () => {
    class DiscordStrategy extends GenericOAuthStrategy {
      async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
        return { id: p.id, email: p.email };
      }
    }
    const store = makeOAuthUserStore({ id: 'd1', email: 'discord@test.com' });
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, mobileOAuthConfig, {
      oauthStrategies: [new DiscordStrategy(discordCfg)],
    }));
    const res = await request(app).get('/auth/oauth/discord');
    expect(res.status).toBe(302);
    expect(res.headers['location']).toContain('discord.com/api/oauth2/authorize');
    expect(res.headers['location']).toContain('client_id=client-id');
  });

  it('OAuth callback redirects to siteUrl (custom app scheme) on success', async () => {
    const oauthUser: BaseUser = { id: 'd1', email: 'discord@test.com' };
    class DiscordStrategy extends GenericOAuthStrategy {
      async handleCallback(_code: string): Promise<BaseUser> { return oauthUser; }
      async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
        return { id: p.id, email: p.email };
      }
    }
    const store = makeOAuthUserStore(oauthUser);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, mobileOAuthConfig, {
      oauthStrategies: [new DiscordStrategy(discordCfg)],
    }));
    const res = await request(app).get('/auth/oauth/discord/callback?code=abc&state=xyz');
    expect(res.status).toBe(302);
    // Server redirects to the app's custom scheme — mobile can intercept this
    expect(res.headers['location']).toBe(mobileSiteUrl);
  });

  it('OAuth callback redirects to siteUrl/auth/2fa?tempToken=...&methods=... when user has 2FA enabled', async () => {
    const oauthUser: BaseUser = {
      id: 'd1',
      email: 'discord@test.com',
      isTotpEnabled: true,
      totpSecret: 'secret',
    };
    class DiscordStrategy extends GenericOAuthStrategy {
      async handleCallback(_code: string): Promise<BaseUser> { return oauthUser; }
      async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
        return { id: p.id, email: p.email };
      }
    }
    const store = makeOAuthUserStore(oauthUser);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, mobileOAuthConfig, {
      oauthStrategies: [new DiscordStrategy(discordCfg)],
    }));
    const res = await request(app).get('/auth/oauth/discord/callback?code=abc&state=xyz');
    expect(res.status).toBe(302);
    const location = res.headers['location'] as string;
    // Mobile app intercepts this redirect, extracts tempToken + methods from query params
    expect(location).toContain(`${mobileSiteUrl}/auth/2fa`);
    expect(location).toContain('tempToken=');
    expect(location).toContain('methods=totp');
  });

  it('does not emit AUTH_OAUTH_SUCCESS before OAuth login completes when 2FA is required', async () => {
    const oauthUser: BaseUser = {
      id: 'd1',
      email: 'discord@test.com',
      isTotpEnabled: true,
      totpSecret: 'secret',
    };
    class DiscordStrategy extends GenericOAuthStrategy {
      async handleCallback(_code: string): Promise<BaseUser> { return oauthUser; }
      async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
        return { id: p.id, email: p.email };
      }
    }
    const store = makeOAuthUserStore(oauthUser);
    const bus = new AuthEventBus();
    const events: string[] = [];
    bus.onEvent('*', (payload) => events.push(payload.event));
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, mobileOAuthConfig, {
      oauthStrategies: [new DiscordStrategy(discordCfg)],
      eventBus: bus,
    }));

    const res = await request(app).get('/auth/oauth/discord/callback?code=abc&state=xyz');

    expect(res.status).toBe(302);
    expect(res.headers['location']).toContain(`${mobileSiteUrl}/auth/2fa`);
    expect(events).not.toContain(AuthEventNames.AUTH_OAUTH_SUCCESS);
  });

  it('after OAuth 2FA redirect, mobile app can complete login using bearer-mode TOTP verify', async () => {
    const { TOTP, NobleCryptoPlugin, ScureBase32Plugin } = await import('otplib');
    const totp = new TOTP({ crypto: new NobleCryptoPlugin(), base32: new ScureBase32Plugin() });
    const totpSecret = totp.generateSecret();
    const oauthUser: BaseUser = {
      id: 'd1',
      email: 'discord@test.com',
      isTotpEnabled: true,
      totpSecret,
    };
    class DiscordStrategy extends GenericOAuthStrategy {
      async handleCallback(_code: string): Promise<BaseUser> { return oauthUser; }
      async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
        return { id: p.id, email: p.email };
      }
    }
    const store = makeOAuthUserStore(oauthUser);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, mobileOAuthConfig, {
      oauthStrategies: [new DiscordStrategy(discordCfg)],
    }));

    // Step 1: OAuth callback → server redirects to siteUrl/auth/2fa?tempToken=...
    const callbackRes = await request(app).get('/auth/oauth/discord/callback?code=abc&state=xyz');
    expect(callbackRes.status).toBe(302);
    const location = callbackRes.headers['location'] as string;
    const url = new URL(location.replace('myapp://auth', 'https://placeholder'));
    const tempToken = url.searchParams.get('tempToken')!;
    expect(tempToken).toBeTruthy();

    // Step 2: Mobile app extracts tempToken and verifies TOTP via bearer flow
    const totpCode = await totp.generate({ secret: totpSecret });
    const verifyRes = await request(app)
      .post('/auth/2fa/verify')
      .set('X-Auth-Strategy', 'bearer')
      .send({ tempToken, totpCode });
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body.accessToken).toBeDefined();
    expect(verifyRes.body.refreshToken).toBeDefined();
    // No cookies on mobile bearer flow
    expect(verifyRes.headers['set-cookie']).toBeUndefined();
  });

  it('OAuth callback records link in linkedAccountsStore when configured', async () => {
    const oauthUser: BaseUser = { id: 'd1', email: 'discord@test.com', providerAccountId: 'discord-123' };
    class DiscordStrategy extends GenericOAuthStrategy {
      async handleCallback(_code: string): Promise<BaseUser> { return oauthUser; }
      async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
        return { id: p.id, email: p.email };
      }
    }
    const store = makeOAuthUserStore(oauthUser);
    const linkedAccountsStore: ILinkedAccountsStore = {
      getLinkedAccounts: vi.fn().mockResolvedValue([]),
      linkAccount: vi.fn().mockResolvedValue(undefined),
      unlinkAccount: vi.fn().mockResolvedValue(undefined),
      findUserByProviderAccount: vi.fn().mockResolvedValue(null),
    };
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, mobileOAuthConfig, {
      oauthStrategies: [new DiscordStrategy(discordCfg)],
      linkedAccountsStore,
    }));
    const res = await request(app).get('/auth/oauth/discord/callback?code=abc&state=xyz');
    expect(res.status).toBe(302);
    expect(linkedAccountsStore.linkAccount).toHaveBeenCalledWith('d1', {
      provider: 'discord',
      providerAccountId: 'discord-123',
      email: 'discord@test.com',
      linkedAt: expect.any(Date),
    });
  });
});

// ---------------------------------------------------------------------------
// Dynamic CORS & siteUrl resolution
// ---------------------------------------------------------------------------
describe('Dynamic CORS and siteUrl', () => {
  const multiOriginConfig: AuthConfig = {
    ...config,
    email: {
      siteUrl: ['https://app.example.com', 'https://admin.example.com'],
    },
  };

  const discordCfg: GenericOAuthProviderConfig = {
    name: 'discord',
    clientId: 'client-id',
    clientSecret: 'client-secret',
    callbackUrl: 'https://api.example.com/auth/oauth/discord/callback',
    authorizationUrl: 'https://discord.com/api/oauth2/authorize',
    tokenUrl: 'https://discord.com/api/oauth2/token',
    userInfoUrl: 'https://discord.com/api/users/@me',
    scope: 'identify email',
  };

  function makeOAuthUserStore(user: BaseUser): IUserStore {
    return {
      findByEmail: vi.fn().mockResolvedValue(user),
      findById: vi.fn().mockResolvedValue(user),
      create: vi.fn(),
      updateRefreshToken: vi.fn().mockResolvedValue(undefined),
      updateLastLogin: vi.fn().mockResolvedValue(undefined),
      updateResetToken: vi.fn().mockResolvedValue(undefined),
      updatePassword: vi.fn().mockResolvedValue(undefined),
      updateTotpSecret: vi.fn().mockResolvedValue(undefined),
      updateMagicLinkToken: vi.fn().mockResolvedValue(undefined),
      updateSmsCode: vi.fn().mockResolvedValue(undefined),
    };
  }

  it('CORS: OPTIONS preflight returns 204 and correct headers for allowed origin', async () => {
    const store = makeOAuthUserStore({ id: 'u1', email: 'a@test.com' });
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, multiOriginConfig, {
      cors: { origins: ['https://app.example.com', 'https://admin.example.com'] },
    }));
    const res = await request(app)
      .options('/auth/login')
      .set('Origin', 'https://app.example.com');
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe('https://app.example.com');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
  });

  it('CORS: disallowed origin does not receive CORS headers', async () => {
    const store = makeOAuthUserStore({ id: 'u1', email: 'a@test.com' });
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, multiOriginConfig, {
      cors: { origins: ['https://app.example.com'] },
    }));
    const res = await request(app)
      .options('/auth/login')
      .set('Origin', 'https://evil.example.com');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('OAuth initiation: state encodes the origin from the Origin header', async () => {
    class DiscordStrategy extends GenericOAuthStrategy {
      async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
        return { id: p.id, email: p.email };
      }
    }
    const store = makeOAuthUserStore({ id: 'u1', email: 'a@test.com' });
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, multiOriginConfig, {
      oauthStrategies: [new DiscordStrategy(discordCfg)],
    }));
    const res = await request(app)
      .get('/auth/oauth/discord')
      .set('Origin', 'https://app.example.com');
    expect(res.status).toBe(302);
    const location = new URL(res.headers['location'] as string);
    const stateParam = location.searchParams.get('state')!;
    // Decode the state and verify it contains the origin
    const decoded = JSON.parse(Buffer.from(stateParam, 'base64url').toString()) as { n: string; o: string };
    expect(decoded.o).toBe('https://app.example.com');
    expect(decoded.n).toBeTruthy();
  });

  it('OAuth callback: redirects to origin encoded in state (not default siteUrl)', async () => {
    const oauthUser: BaseUser = { id: 'u1', email: 'a@test.com' };
    class DiscordStrategy extends GenericOAuthStrategy {
      async handleCallback(_code: string): Promise<BaseUser> { return oauthUser; }
      async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
        return { id: p.id, email: p.email };
      }
    }
    const store = makeOAuthUserStore(oauthUser);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, multiOriginConfig, {
      oauthStrategies: [new DiscordStrategy(discordCfg)],
    }));
    // Encode state with admin origin (second allowed origin)
    const encodedState = Buffer.from(JSON.stringify({ n: 'abc123', o: 'https://admin.example.com' })).toString('base64url');
    const res = await request(app).get(`/auth/oauth/discord/callback?code=xyz&state=${encodedState}`);
    expect(res.status).toBe(302);
    expect(res.headers['location']).toBe('https://admin.example.com');
  });

  it('OAuth callback: rejects state with non-allowlisted origin, falls back to default', async () => {
    const oauthUser: BaseUser = { id: 'u1', email: 'a@test.com' };
    class DiscordStrategy extends GenericOAuthStrategy {
      async handleCallback(_code: string): Promise<BaseUser> { return oauthUser; }
      async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
        return { id: p.id, email: p.email };
      }
    }
    const store = makeOAuthUserStore(oauthUser);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, multiOriginConfig, {
      oauthStrategies: [new DiscordStrategy(discordCfg)],
    }));
    // State contains an origin NOT in the allowlist
    const maliciousState = Buffer.from(JSON.stringify({ n: 'abc123', o: 'https://evil.example.com' })).toString('base64url');
    const res = await request(app).get(`/auth/oauth/discord/callback?code=xyz&state=${maliciousState}`);
    expect(res.status).toBe(302);
    // Must fall back to the first siteUrl, not the malicious origin
    expect(res.headers['location']).toBe('https://app.example.com');
    expect(res.headers['location']).not.toContain('evil');
  });

  it('siteUrl as string still works (backward compat)', async () => {
    const singleConfig: AuthConfig = { ...config, email: { siteUrl: 'https://single.example.com' } };
    const oauthUser: BaseUser = { id: 'u1', email: 'a@test.com' };
    class DiscordStrategy extends GenericOAuthStrategy {
      async handleCallback(_code: string): Promise<BaseUser> { return oauthUser; }
      async findOrCreateUser(p: { id: string; email: string }): Promise<BaseUser> {
        return { id: p.id, email: p.email };
      }
    }
    const store = makeOAuthUserStore(oauthUser);
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, singleConfig, {
      oauthStrategies: [new DiscordStrategy(discordCfg)],
    }));
    const res = await request(app).get('/auth/oauth/discord/callback?code=xyz&state=plainNonce');
    expect(res.status).toBe(302);
    expect(res.headers['location']).toBe('https://single.example.com');
  });
});
