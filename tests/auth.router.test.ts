import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createAuthRouter } from '../src/router/auth.router';
import { IUserStore } from '../src/interfaces/user-store.interface';
import { BaseUser } from '../src/models/user.model';
import { AuthConfig } from '../src/models/auth-config.model';
import { SessionInfo } from '../src/models/session.model';
import { PasswordService } from '../src/services/password.service';
import { TokenService } from '../src/services/token.service';
import { TOTP, NobleCryptoPlugin, ScureBase32Plugin } from 'otplib';
import { AuthEventBus } from '../src/events/auth-event-bus';
import { AuthEventNames } from '../src/events/auth-event-names';

const passwordService = new PasswordService();
const tokenService = new TokenService();
const totp = new TOTP({ crypto: new NobleCryptoPlugin(), base32: new ScureBase32Plugin() });

const config: AuthConfig = {
  accessTokenSecret: 'test-access-secret-very-long-and-secure',
  refreshTokenSecret: 'test-refresh-secret-very-long-and-secure',
  accessTokenExpiresIn: '15m',
  refreshTokenExpiresIn: '7d',
  email: {
    sendPasswordReset: vi.fn().mockResolvedValue(undefined),
    siteUrl: 'http://localhost:3000',
  },
};

let users: Map<string, BaseUser> = new Map();
let passwordHash: string;

function createStore(): IUserStore & { findByResetToken: (t: string) => Promise<BaseUser | null>; findByMagicLinkToken: (t: string) => Promise<BaseUser | null> } {
  return {
    findByEmail: vi.fn((email: string) => Promise.resolve([...users.values()].find(u => u.email === email) ?? null)),
    findById: vi.fn((id: string) => Promise.resolve(users.get(id) ?? null)),
    create: vi.fn(),
    updateRefreshToken: vi.fn((id, token, expiry) => {
      const u = users.get(id);
      if (u) { u.refreshToken = token; u.refreshTokenExpiry = expiry; }
      return Promise.resolve();
    }),
    updateLastLogin: vi.fn((id) => {
      const u = users.get(id);
      if (u) u.lastLogin = new Date();
      return Promise.resolve();
    }),
    updateResetToken: vi.fn((id, token, expiry) => {
      const u = users.get(id);
      if (u) { u.resetToken = token; u.resetTokenExpiry = expiry; }
      return Promise.resolve();
    }),
    updatePassword: vi.fn((id, hash) => {
      const u = users.get(id);
      if (u) u.password = hash;
      return Promise.resolve();
    }),
    updateTotpSecret: vi.fn((id, secret) => {
      const u = users.get(id);
      if (u) { u.totpSecret = secret; u.isTotpEnabled = secret !== null; }
      return Promise.resolve();
    }),
    updateMagicLinkToken: vi.fn((id, token, expiry) => {
      const u = users.get(id);
      if (u) { u.magicLinkToken = token; u.magicLinkTokenExpiry = expiry; }
      return Promise.resolve();
    }),
    updateSmsCode: vi.fn((id, code, expiry) => {
      const u = users.get(id);
      if (u) { u.smsCode = code; u.smsCodeExpiry = expiry; }
      return Promise.resolve();
    }),
    findByResetToken: vi.fn((token: string) => Promise.resolve([...users.values()].find(u => u.resetToken === token) ?? null)),
    findByMagicLinkToken: vi.fn((token: string) => Promise.resolve([...users.values()].find(u => u.magicLinkToken === token) ?? null)),
  };
}

describe('Auth Router Integration', () => {
  let app: express.Application;
  let store: ReturnType<typeof createStore>;

  beforeAll(async () => {
    passwordHash = await passwordService.hash('password123');
  });

  beforeEach(() => {
    users = new Map();
    users.set('1', { id: '1', email: 'user@test.com', password: passwordHash });
    store = createStore();
    app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, config));
  });

  describe('POST /auth/login', () => {
    it('logs in with valid credentials', async () => {
      const res = await request(app).post('/auth/login').send({ email: 'user@test.com', password: 'password123' });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.headers['set-cookie']).toBeDefined();
    });

    it('returns 401 with wrong password', async () => {
      const res = await request(app).post('/auth/login').send({ email: 'user@test.com', password: 'wrong' });
      expect(res.status).toBe(401);
    });

    it('returns 401 for unknown user', async () => {
      const res = await request(app).post('/auth/login').send({ email: 'no@one.com', password: 'pass' });
      expect(res.status).toBe(401);
    });
  });

  describe('GET /auth/me', () => {
    it('returns user profile when authenticated', async () => {
      const tokens = tokenService.generateTokenPair({ sub: '1', email: 'user@test.com' }, config);
      const res = await request(app).get('/auth/me').set('Cookie', `accessToken=${tokens.accessToken}`);
      expect(res.status).toBe(200);
      expect(res.body.sub).toBe('1');
      expect(res.body.email).toBe('user@test.com');
      // Sensitive fields must not be exposed
      expect(res.body.password).toBeUndefined();
      expect(res.body.refreshToken).toBeUndefined();
      expect(res.body.totpSecret).toBeUndefined();
    });

    it('returns 403 without token', async () => {
      const res = await request(app).get('/auth/me');
      expect(res.status).toBe(403);
    });
  });

  describe('POST /auth/logout', () => {
    it('logs out and clears cookies', async () => {
      const tokens = tokenService.generateTokenPair({ sub: '1', email: 'user@test.com' }, config);
      const res = await request(app).post('/auth/logout').set('Cookie', `accessToken=${tokens.accessToken}`);
      expect(res.status).toBe(200);
    });
  });

  describe('POST /auth/register', () => {
    it('mounts the built-in register handler when defaultRegister is set and onRegister is omitted', async () => {
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
      const create = vi.fn(async (data: Partial<BaseUser>) => ({
        id: '2',
        email: String(data.email),
        password: data.password,
      }));
      store.create = create as unknown as typeof store.create;
      const registerApp = express();
      registerApp.use(express.json());
      registerApp.use('/auth', createAuthRouter(store, config, { defaultRegister: true }));

      const res = await request(registerApp)
        .post('/auth/register')
        .send({ email: 'new@test.com', password: 'new-password', firstName: 'New', isAdmin: true });

      expect(res.status).toBe(201);
      expect(create).toHaveBeenCalledTimes(1);
      const created = create.mock.calls[0][0] as Partial<BaseUser>;
      expect(Object.keys(created).sort()).toEqual(['email', 'firstName', 'password']);
      expect(created.email).toBe('new@test.com');
      expect(created.firstName).toBe('New');
      expect(created.password).not.toBe('new-password');
      expect(await passwordService.compare('new-password', created.password as string)).toBe(true);
      expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('POST /register is enabled with the built-in handler (defaultRegister)'));
      stderrSpy.mockRestore();
    });

    it('does not mount POST /register when neither onRegister nor defaultRegister is set', async () => {
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
      const registerApp = express();
      registerApp.use(express.json());
      registerApp.use('/auth', createAuthRouter(store, config));

      const res = await request(registerApp)
        .post('/auth/register')
        .send({ email: 'new@test.com', password: 'new-password' });

      expect(res.status).toBe(404);
      expect(store.create).not.toHaveBeenCalled();
      expect(stderrSpy).not.toHaveBeenCalledWith(expect.stringContaining('POST /register'));
      stderrSpy.mockRestore();
    });
  });

  describe('auth event bus integration', () => {
    it('publishes login success and failure events', async () => {
      const bus = new AuthEventBus();
      const events: string[] = [];
      bus.onEvent('*', (payload) => events.push(payload.event));

      const eventApp = express();
      eventApp.use(express.json());
      eventApp.use('/auth', createAuthRouter(store, config, { eventBus: bus }));

      const ok = await request(eventApp).post('/auth/login').send({ email: 'user@test.com', password: 'password123' });
      expect(ok.status).toBe(200);

      const bad = await request(eventApp).post('/auth/login').send({ email: 'user@test.com', password: 'wrong' });
      expect(bad.status).toBe(401);

      expect(events).toContain(AuthEventNames.AUTH_LOGIN_SUCCESS);
      expect(events).toContain(AuthEventNames.AUTH_LOGIN_FAILED);
    });

    it('publishes AUTH_LOGIN_SUCCESS for magic-link verify', async () => {
      const bus = new AuthEventBus();
      const events: string[] = [];
      bus.onEvent('*', (payload) => events.push(payload.event));

      const cfgWithMagic: AuthConfig = {
        ...config,
        email: { ...config.email, sendMagicLink: vi.fn().mockResolvedValue(undefined), siteUrl: 'http://localhost' },
      };
      const eventApp = express();
      eventApp.use(express.json());
      eventApp.use('/auth', createAuthRouter(store, cfgWithMagic, { eventBus: bus }));

      const user = users.get('1')!;
      user.magicLinkToken = 'event-magic-token';
      user.magicLinkTokenExpiry = new Date(Date.now() + 60_000);

      const res = await request(eventApp)
        .post('/auth/magic-link/verify')
        .send({ token: 'event-magic-token' });

      expect(res.status).toBe(200);
      expect(events).toContain(AuthEventNames.AUTH_LOGIN_SUCCESS);
    });

    it('publishes AUTH_LOGIN_SUCCESS for sms verify', async () => {
      const bus = new AuthEventBus();
      const events: string[] = [];
      bus.onEvent('*', (payload) => events.push(payload.event));

      const cfgWithSms: AuthConfig = {
        ...config,
        sms: { endpoint: 'http://test', apiKey: 'key', username: 'u', password: 'p' },
      };
      const eventApp = express();
      eventApp.use(express.json());
      eventApp.use('/auth', createAuthRouter(store, cfgWithSms, { eventBus: bus }));

      const user = users.get('1')!;
      user.phoneNumber = '+123456789';
      user.smsCode = await passwordService.hash('123456');
      user.smsCodeExpiry = new Date(Date.now() + 60_000);

      const res = await request(eventApp)
        .post('/auth/sms/verify')
        .send({ userId: '1', code: '123456' });

      expect(res.status).toBe(200);
      expect(events).toContain(AuthEventNames.AUTH_LOGIN_SUCCESS);
    });
  });

  describe('POST /auth/refresh', () => {
    it('refreshes tokens', async () => {
      const tokens = tokenService.generateTokenPair({ sub: '1', email: 'user@test.com' }, config);
      const user = users.get('1')!;
      user.refreshToken = tokens.refreshToken;
      const res = await request(app).post('/auth/refresh').set('Cookie', `refreshToken=${tokens.refreshToken}`);
      expect(res.status).toBe(200);
    });

    it('rejects invalid refresh token', async () => {
      const res = await request(app).post('/auth/refresh').set('Cookie', 'refreshToken=invalid');
      expect(res.status).toBe(401);
    });
  });

  describe('POST /auth/forgot-password', () => {
    it('returns success even for unknown email', async () => {
      const res = await request(app).post('/auth/forgot-password').send({ email: 'nobody@test.com' });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('sends reset email for known user', async () => {
      const res = await request(app).post('/auth/forgot-password').send({ email: 'user@test.com' });
      expect(res.status).toBe(200);
      expect(config.email?.sendPasswordReset).toHaveBeenCalled();
    });
  });

  describe('POST /auth/reset-password', () => {
    it('resets password with valid token', async () => {
      const user = users.get('1')!;
      user.resetToken = 'valid-token';
      user.resetTokenExpiry = new Date(Date.now() + 60000);
      const res = await request(app).post('/auth/reset-password').send({ token: 'valid-token', password: 'newpassword' });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('rejects expired reset token', async () => {
      const user = users.get('1')!;
      user.resetToken = 'expired-token';
      user.resetTokenExpiry = new Date(Date.now() - 1000);
      const res = await request(app).post('/auth/reset-password').send({ token: 'expired-token', password: 'newpassword' });
      expect(res.status).toBe(400);
    });
  });

  describe('2FA flow', () => {
    it('sets up 2FA', async () => {
      const tokens = tokenService.generateTokenPair({ sub: '1', email: 'user@test.com' }, config);
      const res = await request(app).post('/auth/2fa/setup').set('Cookie', `accessToken=${tokens.accessToken}`);
      expect(res.status).toBe(200);
      expect(res.body.secret).toBeTruthy();
      expect(res.body.qrCode).toContain('data:image');
    });

    it('verifies 2FA setup and enables it', async () => {
      const tokens = tokenService.generateTokenPair({ sub: '1', email: 'user@test.com' }, config);
      const setupRes = await request(app).post('/auth/2fa/setup').set('Cookie', `accessToken=${tokens.accessToken}`);
      const { secret } = setupRes.body as { secret: string };
      const totpCode = await totp.generate({ secret });
      const verifyRes = await request(app)
        .post('/auth/2fa/verify-setup')
        .set('Cookie', `accessToken=${tokens.accessToken}`)
        .send({ token: totpCode, secret });
      expect(verifyRes.status).toBe(200);
    });

    it('login with 2FA returns tempToken and available2faMethods', async () => {
      const user = users.get('1')!;
      const secret = totp.generateSecret();
      user.totpSecret = secret;
      user.isTotpEnabled = true;
      const res = await request(app).post('/auth/login').send({ email: 'user@test.com', password: 'password123' });
      expect(res.status).toBe(200);
      expect(res.body.requiresTwoFactor).toBe(true);
      expect(res.body.tempToken).toBeTruthy();
      expect(Array.isArray(res.body.available2faMethods)).toBe(true);
      expect(res.body.available2faMethods).toContain('totp');
    });

    it('login with 2FA includes sms in available2faMethods when phone and sms are set', async () => {
      const user = users.get('1')!;
      const secret = totp.generateSecret();
      user.totpSecret = secret;
      user.isTotpEnabled = true;
      user.phoneNumber = '+1234567890';
      const cfgWithSms: AuthConfig = {
        ...config,
        sms: { endpoint: 'http://test', apiKey: 'key', username: 'u', password: 'p' },
      };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithSms));
      const res = await request(testApp).post('/auth/login').send({ email: 'user@test.com', password: 'password123' });
      expect(res.body.available2faMethods).toContain('sms');
    });

    it('login with 2FA includes magic-link in available2faMethods when email is configured', async () => {
      const user = users.get('1')!;
      const secret = totp.generateSecret();
      user.totpSecret = secret;
      user.isTotpEnabled = true;
      const cfgWithMagic: AuthConfig = {
        ...config,
        email: { ...config.email, sendMagicLink: vi.fn().mockResolvedValue(undefined), siteUrl: 'http://localhost' },
      };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithMagic));
      const res = await request(testApp).post('/auth/login').send({ email: 'user@test.com', password: 'password123' });
      expect(res.body.available2faMethods).toContain('magic-link');
    });

    it('verifies TOTP and issues tokens', async () => {
      const user = users.get('1')!;
      const secret = totp.generateSecret();
      user.totpSecret = secret;
      user.isTotpEnabled = true;
      const loginRes = await request(app).post('/auth/login').send({ email: 'user@test.com', password: 'password123' });
      const { tempToken } = loginRes.body as { tempToken: string };
      const totpCode = await totp.generate({ secret });
      const verifyRes = await request(app).post('/auth/2fa/verify').send({ tempToken, totpCode });
      expect(verifyRes.status).toBe(200);
      expect(verifyRes.headers['set-cookie']).toBeDefined();
    });
  });

  describe('Magic link flow', () => {
    it('sends magic link for existing user', async () => {
      const sendMagicLink = vi.fn().mockResolvedValue(undefined);
      const cfgWithMagic: AuthConfig = { ...config, email: { ...config.email, sendMagicLink, siteUrl: 'http://localhost' } };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithMagic));
      const res = await request(testApp).post('/auth/magic-link/send').send({ email: 'user@test.com' });
      expect(res.status).toBe(200);
      expect(sendMagicLink).toHaveBeenCalled();
    });

    it('verifies magic link and issues tokens', async () => {
      const sendMagicLink = vi.fn().mockResolvedValue(undefined);
      const cfgWithMagic: AuthConfig = { ...config, email: { ...config.email, sendMagicLink, siteUrl: 'http://localhost' } };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithMagic));

      // Manually set a magic link token
      const user = users.get('1')!;
      user.magicLinkToken = 'test-magic-token';
      user.magicLinkTokenExpiry = new Date(Date.now() + 60000);

      const res = await request(testApp).post('/auth/magic-link/verify').send({ token: 'test-magic-token' });
      expect(res.status).toBe(200);
      expect(res.headers['set-cookie']).toBeDefined();
    });

    it('magic-link send in 2FA mode sends link for user identified by tempToken', async () => {
      const sendMagicLink = vi.fn().mockResolvedValue(undefined);
      const cfgWithMagic: AuthConfig = { ...config, email: { ...config.email, sendMagicLink, siteUrl: 'http://localhost' } };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithMagic));
      const tempToken = tokenService.generateTempToken({ sub: '1', email: 'user@test.com' }, cfgWithMagic);
      const res = await request(testApp)
        .post('/auth/magic-link/send')
        .send({ mode: '2fa', tempToken });
      expect(res.status).toBe(200);
      expect(sendMagicLink).toHaveBeenCalled();
    });

    it('magic-link send in 2FA mode rejects missing tempToken', async () => {
      const sendMagicLink = vi.fn().mockResolvedValue(undefined);
      const cfgWithMagic: AuthConfig = { ...config, email: { ...config.email, sendMagicLink, siteUrl: 'http://localhost' } };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithMagic));
      const res = await request(testApp).post('/auth/magic-link/send').send({ mode: '2fa' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('TEMP_TOKEN_REQUIRED');
    });

    it('magic-link verify in 2FA mode issues tokens when both tokens are valid', async () => {
      const sendMagicLink = vi.fn().mockResolvedValue(undefined);
      const cfgWithMagic: AuthConfig = { ...config, email: { ...config.email, sendMagicLink, siteUrl: 'http://localhost' } };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithMagic));

      const user = users.get('1')!;
      user.magicLinkToken = 'ml-2fa-token';
      user.magicLinkTokenExpiry = new Date(Date.now() + 60000);
      const tempToken = tokenService.generateTempToken({ sub: '1', email: 'user@test.com' }, cfgWithMagic);

      const res = await request(testApp)
        .post('/auth/magic-link/verify')
        .send({ token: 'ml-2fa-token', mode: '2fa', tempToken });
      expect(res.status).toBe(200);
      expect(res.headers['set-cookie']).toBeDefined();
    });

    it('magic-link verify in 2FA mode rejects missing tempToken', async () => {
      const sendMagicLink = vi.fn().mockResolvedValue(undefined);
      const cfgWithMagic: AuthConfig = { ...config, email: { ...config.email, sendMagicLink, siteUrl: 'http://localhost' } };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithMagic));
      const res = await request(testApp)
        .post('/auth/magic-link/verify')
        .send({ token: 'some-token', mode: '2fa' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('TEMP_TOKEN_REQUIRED');
    });
  });

  describe('requireEmailVerification', () => {
    it('rejects login when requireEmailVerification is true and email not verified', async () => {
      users.get('1')!.isEmailVerified = false;
      const cfgWithVerification: AuthConfig = { ...config, requireEmailVerification: true };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithVerification));
      const res = await request(testApp).post('/auth/login').send({ email: 'user@test.com', password: 'password123' });
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('EMAIL_NOT_VERIFIED');
    });

    it('allows login when requireEmailVerification is true and email is verified', async () => {
      users.get('1')!.isEmailVerified = true;
      const cfgWithVerification: AuthConfig = { ...config, requireEmailVerification: true };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithVerification));
      const res = await request(testApp).post('/auth/login').send({ email: 'user@test.com', password: 'password123' });
      expect(res.status).toBe(200);
    });
  });

  describe('SMS /sms/send', () => {
    it('returns 400 when user has no phone number', async () => {
      const cfgWithSms: AuthConfig = {
        ...config,
        sms: { endpoint: 'http://test', apiKey: 'key', username: 'u', password: 'p' },
      };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithSms));
      const res = await request(testApp).post('/auth/sms/send').send({ userId: '1' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('PHONE_NOT_SET');
    });

    it('returns 500 when SMS is not configured', async () => {
      const res = await request(app).post('/auth/sms/send').send({ userId: '1' });
      expect(res.status).toBe(500);
    });

    it('returns 404 when user not found', async () => {
      const cfgWithSms: AuthConfig = {
        ...config,
        sms: { endpoint: 'http://test', apiKey: 'key', username: 'u', password: 'p' },
      };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithSms));
      const res = await request(testApp).post('/auth/sms/send').send({ userId: 'nonexistent' });
      expect(res.status).toBe(404);
    });

    it('returns success (silently) when email is provided but user not found', async () => {
      const cfgWithSms: AuthConfig = {
        ...config,
        sms: { endpoint: 'http://test', apiKey: 'key', username: 'u', password: 'p' },
      };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithSms));
      const res = await request(testApp).post('/auth/sms/send').send({ email: 'noone@example.com' });
      // Should silently succeed to prevent email enumeration
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
    });

    it('returns 400 with PHONE_NOT_SET when user found by email has no phone', async () => {
      const cfgWithSms: AuthConfig = {
        ...config,
        sms: { endpoint: 'http://test', apiKey: 'key', username: 'u', password: 'p' },
      };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithSms));
      // user '1' has no phoneNumber in this test (not set in beforeEach)
      const res = await request(testApp).post('/auth/sms/send').send({ email: 'user@test.com' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('PHONE_NOT_SET');
    });

    it('sms send in 2FA mode requires tempToken', async () => {
      const cfgWithSms: AuthConfig = {
        ...config,
        sms: { endpoint: 'http://test', apiKey: 'key', username: 'u', password: 'p' },
      };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithSms));
      const res = await request(testApp).post('/auth/sms/send').send({ mode: '2fa' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('TEMP_TOKEN_REQUIRED');
    });

    it('sms send in 2FA mode rejects invalid tempToken', async () => {
      const cfgWithSms: AuthConfig = {
        ...config,
        sms: { endpoint: 'http://test', apiKey: 'key', username: 'u', password: 'p' },
      };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithSms));
      const res = await request(testApp).post('/auth/sms/send').send({ mode: '2fa', tempToken: 'invalid' });
      expect(res.status).toBe(401);
      expect(res.body.code).toBe('INVALID_TEMP_TOKEN');
    });

    it('sms verify in 2FA mode requires tempToken', async () => {
      const cfgWithSms: AuthConfig = {
        ...config,
        sms: { endpoint: 'http://test', apiKey: 'key', username: 'u', password: 'p' },
      };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithSms));
      const res = await request(testApp).post('/auth/sms/verify').send({ mode: '2fa', code: '123456' });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('TEMP_TOKEN_REQUIRED');
    });
  });

  describe('buildTokenPayload custom claims', () => {
    it('embeds custom claims in the access token on login', async () => {
      const cfgWithCustom: AuthConfig = {
        ...config,
        buildTokenPayload: (user) => ({ tenantId: 'acme', permissions: ['read'] }),
      };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithCustom));

      const loginRes = await request(testApp)
        .post('/auth/login')
        .send({ email: 'user@test.com', password: 'password123' });
      expect(loginRes.status).toBe(200);

      // Decode the access token cookie and verify custom claims
      const cookies: string[] = loginRes.headers['set-cookie'] as unknown as string[];
      const accessCookie = cookies.find((c) => c.startsWith('accessToken='))!;
      const tokenValue = accessCookie.split(';')[0].split('=')[1];
      const payload = tokenService.verifyAccessToken(tokenValue, cfgWithCustom);
      expect(payload.tenantId).toBe('acme');
      expect(payload.permissions).toEqual(['read']);
    });

    it('embeds custom claims on token refresh', async () => {
      const cfgWithCustom: AuthConfig = {
        ...config,
        buildTokenPayload: (user) => ({ tenantId: 'acme' }),
      };
      const testApp = express();
      testApp.use(express.json());
      testApp.use('/auth', createAuthRouter(store, cfgWithCustom));

      // Login first to get a refresh token
      const loginRes = await request(testApp)
        .post('/auth/login')
        .send({ email: 'user@test.com', password: 'password123' });
      const cookies: string[] = loginRes.headers['set-cookie'] as unknown as string[];

      const refreshRes = await request(testApp)
        .post('/auth/refresh')
        .set('Cookie', cookies);
      expect(refreshRes.status).toBe(200);

      const newCookies: string[] = refreshRes.headers['set-cookie'] as unknown as string[];
      const accessCookie = newCookies.find((c) => c.startsWith('accessToken='))!;
      const tokenValue = accessCookie.split(';')[0].split('=')[1];
      const payload = tokenService.verifyAccessToken(tokenValue, cfgWithCustom);
      expect(payload.tenantId).toBe('acme');
    });
  });

  describe('Bearer token strategy (X-Auth-Strategy: bearer)', () => {
    it('login with bearer header returns tokens in body instead of cookies', async () => {
      const res = await request(app)
        .post('/auth/login')
        .set('X-Auth-Strategy', 'bearer')
        .send({ email: 'user@test.com', password: 'password123' });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
      // No cookies should be set
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('login without bearer header sets cookies (default behaviour unchanged)', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({ email: 'user@test.com', password: 'password123' });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.headers['set-cookie']).toBeDefined();
      expect(res.body.accessToken).toBeUndefined();
    });

    it('auth middleware accepts Authorization: Bearer header', async () => {
      const tokens = tokenService.generateTokenPair({ sub: '1', email: 'user@test.com' }, config);
      const res = await request(app)
        .get('/auth/me')
        .set('Authorization', `Bearer ${tokens.accessToken}`);
      expect(res.status).toBe(200);
      expect(res.body.sub).toBe('1');
    });

    it('refresh with refreshToken in body returns new tokens in body', async () => {
      const tokens = tokenService.generateTokenPair({ sub: '1', email: 'user@test.com' }, config);
      users.get('1')!.refreshToken = tokens.refreshToken;
      const res = await request(app)
        .post('/auth/refresh')
        .set('X-Auth-Strategy', 'bearer')
        .send({ refreshToken: tokens.refreshToken });
      expect(res.status).toBe(200);
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
      expect(res.headers['set-cookie']).toBeUndefined();
    });
  });
});

// ---------------------------------------------------------------------------
// Bearer token — mobile/API client flow (link-request + link-verify)
// ---------------------------------------------------------------------------
import { ILinkedAccountsStore, LinkedAccount } from '../src/interfaces/linked-accounts-store.interface';

describe('Bearer token — link-request and link-verify (mobile client flow)', () => {
  const sendVerificationEmail = vi.fn().mockResolvedValue(undefined);
  const mobileConfig: AuthConfig = {
    accessTokenSecret: 'test-access-secret-very-long-and-secure',
    refreshTokenSecret: 'test-refresh-secret-very-long-and-secure',
    email: {
      siteUrl: 'myapp://auth',
      sendVerificationEmail,
    },
  };

  function makeStore() {
    const user: BaseUser = {
      id: 'mobile-u1',
      email: 'mobile@test.com',
      accountLinkToken: null,
      accountLinkTokenExpiry: null,
      accountLinkPendingEmail: null,
      accountLinkPendingProvider: null,
    };
    const store: IUserStore = {
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
      updateAccountLinkToken: vi.fn().mockImplementation(
        (_id, email, provider, token, expiry) => {
          user.accountLinkToken = token;
          user.accountLinkTokenExpiry = expiry;
          user.accountLinkPendingEmail = email;
          user.accountLinkPendingProvider = provider;
          return Promise.resolve();
        },
      ),
      findByAccountLinkToken: vi.fn().mockImplementation((token: string) =>
        Promise.resolve(user.accountLinkToken === token ? user : null),
      ),
    };
    return { store, user };
  }

  function makeLinkedAccountsStore(): ILinkedAccountsStore {
    const links: { userId: string; account: LinkedAccount }[] = [];
    return {
      getLinkedAccounts: vi.fn().mockImplementation((userId: string) =>
        Promise.resolve(links.filter(l => l.userId === userId).map(l => l.account)),
      ),
      linkAccount: vi.fn().mockImplementation((userId: string, account: LinkedAccount) => {
        links.push({ userId, account });
        return Promise.resolve();
      }),
      unlinkAccount: vi.fn().mockResolvedValue(undefined),
      findUserByProviderAccount: vi.fn().mockResolvedValue(null),
    };
  }

  it('mobile client: link-request returns 200 and link in body uses siteUrl scheme', async () => {
    const { store } = makeStore();
    const linkedAccountsStore = makeLinkedAccountsStore();
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, mobileConfig, { linkedAccountsStore }));

    const tokenService = new TokenService();
    const accessToken = tokenService.generateTokenPair(
      { sub: 'mobile-u1', email: 'mobile@test.com' },
      mobileConfig,
    ).accessToken;

    sendVerificationEmail.mockClear();

    const res = await request(app)
      .post('/auth/link-request')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('X-Auth-Strategy', 'bearer')
      .send({ email: 'secondary@mobile.com', provider: 'email' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    // Verify the link in the email uses the mobile siteUrl scheme
    expect(sendVerificationEmail).toHaveBeenCalledWith(
      'secondary@mobile.com',
      expect.any(String),
      expect.stringContaining('myapp://auth/auth/link-verify?token='),
      undefined,
    );
    expect(store.updateAccountLinkToken).toHaveBeenCalledWith(
      'mobile-u1',
      'secondary@mobile.com',
      'email',
      expect.any(String),
      expect.any(Date),
    );
  });

  it('mobile client: full flow — link-request then link-verify', async () => {
    const { store, user } = makeStore();
    const linkedAccountsStore = makeLinkedAccountsStore();
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, mobileConfig, { linkedAccountsStore }));

    const tokenService = new TokenService();
    const accessToken = tokenService.generateTokenPair(
      { sub: 'mobile-u1', email: 'mobile@test.com' },
      mobileConfig,
    ).accessToken;

    sendVerificationEmail.mockClear();

    // Step 1: link-request
    await request(app)
      .post('/auth/link-request')
      .set('Authorization', `Bearer ${accessToken}`)
      .set('X-Auth-Strategy', 'bearer')
      .send({ email: 'secondary@mobile.com', provider: 'email' });

    // Extract the token from the call to sendVerificationEmail
    const linkToken = (sendVerificationEmail.mock.calls[0][1] as string);
    expect(linkToken).toBeTruthy();
    expect(user.accountLinkToken).toBe(linkToken);

    // Step 2: link-verify (no auth required — user opens deep-link)
    const verifyRes = await request(app)
      .post('/auth/link-verify')
      .send({ token: linkToken });

    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body.success).toBe(true);
    expect(linkedAccountsStore.linkAccount).toHaveBeenCalledWith('mobile-u1', {
      provider: 'email',
      providerAccountId: 'secondary@mobile.com',
      email: 'secondary@mobile.com',
      linkedAt: expect.any(Date),
    });
    // Token should be cleared after successful verify
    expect(store.updateAccountLinkToken).toHaveBeenLastCalledWith(
      'mobile-u1', null, null, null, null,
    );
  });

  it('mobile client: link-request without bearer header still works (auth via Authorization header)', async () => {
    const { store } = makeStore();
    const linkedAccountsStore = makeLinkedAccountsStore();
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, mobileConfig, { linkedAccountsStore }));

    const tokenService = new TokenService();
    const accessToken = tokenService.generateTokenPair(
      { sub: 'mobile-u1', email: 'mobile@test.com' },
      mobileConfig,
    ).accessToken;

    // No X-Auth-Strategy header — Authorization: Bearer alone is enough for auth
    const res = await request(app)
      .post('/auth/link-request')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ email: 'another@mobile.com' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// IPendingLinkStore & loginAfterLinking support
// ---------------------------------------------------------------------------
import { IPendingLinkStore } from '../src/interfaces/pending-link-store.interface';
import { AuthError } from '../src/models/errors';

describe('AuthError with data payload', () => {
  it('carries a data payload on construction', () => {
    const data = { email: 'user@test.com', providerAccountId: 'gid123', provider: 'google' };
    const err = new AuthError('conflict', 'OAUTH_ACCOUNT_CONFLICT', 409, data);
    expect(err.code).toBe('OAUTH_ACCOUNT_CONFLICT');
    expect(err.statusCode).toBe(409);
    expect(err.data).toEqual(data);
  });

  it('data is undefined when not provided', () => {
    const err = new AuthError('fail', 'SOME_CODE');
    expect(err.data).toBeUndefined();
  });
});

describe('POST /auth/link-verify — loginAfterLinking', () => {
  const sendVerificationEmail = vi.fn().mockResolvedValue(undefined);
  const loginConfig: AuthConfig = {
    accessTokenSecret: 'test-access-secret-very-long-and-secure',
    refreshTokenSecret: 'test-refresh-secret-very-long-and-secure',
    email: {
      siteUrl: 'http://localhost:3000',
      sendVerificationEmail,
    },
  };

  function makeStoreAndUser() {
    const user: BaseUser = {
      id: 'u-login',
      email: 'login@test.com',
      accountLinkToken: null,
      accountLinkTokenExpiry: null,
      accountLinkPendingEmail: null,
      accountLinkPendingProvider: null,
    };
    const userStore: IUserStore = {
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
      updateAccountLinkToken: vi.fn().mockImplementation(
        (_id: string, email: string | null, provider: string | null, token: string | null, expiry: Date | null) => {
          user.accountLinkToken = token;
          user.accountLinkTokenExpiry = expiry;
          user.accountLinkPendingEmail = email;
          user.accountLinkPendingProvider = provider;
          return Promise.resolve();
        },
      ),
      findByAccountLinkToken: vi.fn().mockImplementation((token: string) =>
        Promise.resolve(user.accountLinkToken === token ? user : null),
      ),
    };
    return { userStore, user };
  }

  function makeLinkedAccountsStore(): ILinkedAccountsStore {
    return {
      getLinkedAccounts: vi.fn().mockResolvedValue([]),
      linkAccount: vi.fn().mockResolvedValue(undefined),
      unlinkAccount: vi.fn().mockResolvedValue(undefined),
      findUserByProviderAccount: vi.fn().mockResolvedValue(null),
    };
  }

  it('link-verify with loginAfterLinking=true issues tokens in cookies', async () => {
    const { userStore, user } = makeStoreAndUser();
    const linkedAccountsStore = makeLinkedAccountsStore();
    const ts = new TokenService();

    // Pre-set a pending link token
    const linkToken = 'lv-token-123';
    user.accountLinkToken = linkToken;
    user.accountLinkTokenExpiry = new Date(Date.now() + 60_000);
    user.accountLinkPendingEmail = 'second@test.com';
    user.accountLinkPendingProvider = 'email';

    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, loginConfig, { linkedAccountsStore }));

    const res = await request(app)
      .post('/auth/link-verify')
      .send({ token: linkToken, loginAfterLinking: true });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    // Tokens should be set as cookies
    expect(res.headers['set-cookie']).toBeDefined();
    const cookies: string[] = res.headers['set-cookie'] as unknown as string[];
    expect(cookies.some((c: string) => c.startsWith('accessToken='))).toBe(true);
    // updateRefreshToken should have been called to persist the refresh token
    expect(userStore.updateRefreshToken).toHaveBeenCalledWith('u-login', expect.any(String), expect.any(Date));
    // The account should have been linked
    expect(linkedAccountsStore.linkAccount).toHaveBeenCalledWith('u-login', expect.objectContaining({
      provider: 'email',
      providerAccountId: 'second@test.com',
    }));
  });

  it('link-verify without loginAfterLinking still returns success without tokens', async () => {
    const { userStore, user } = makeStoreAndUser();
    const linkedAccountsStore = makeLinkedAccountsStore();

    const linkToken = 'lv-token-456';
    user.accountLinkToken = linkToken;
    user.accountLinkTokenExpiry = new Date(Date.now() + 60_000);
    user.accountLinkPendingEmail = 'third@test.com';
    user.accountLinkPendingProvider = 'email';

    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, loginConfig, { linkedAccountsStore }));

    const res = await request(app)
      .post('/auth/link-verify')
      .send({ token: linkToken });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.headers['set-cookie']).toBeUndefined();
    expect(userStore.updateRefreshToken).not.toHaveBeenCalled();
  });
});

describe('IPendingLinkStore — in-memory implementation', () => {
  class InMemoryPendingLinkStore implements IPendingLinkStore {
    private store = new Map<string, { providerAccountId: string }>();
    private key(email: string, provider: string) { return `${email}::${provider}`; }
    async stash(email: string, provider: string, providerAccountId: string) {
      this.store.set(this.key(email, provider), { providerAccountId });
    }
    async retrieve(email: string, provider: string) {
      return this.store.get(this.key(email, provider)) ?? null;
    }
    async remove(email: string, provider: string) {
      this.store.delete(this.key(email, provider));
    }
  }

  it('stash, retrieve, and remove work correctly', async () => {
    const store = new InMemoryPendingLinkStore();
    await store.stash('user@test.com', 'google', 'gid-abc');
    const result = await store.retrieve('user@test.com', 'google');
    expect(result).toEqual({ providerAccountId: 'gid-abc' });
    await store.remove('user@test.com', 'google');
    const afterRemove = await store.retrieve('user@test.com', 'google');
    expect(afterRemove).toBeNull();
  });

  it('returns null when entry does not exist', async () => {
    const store = new InMemoryPendingLinkStore();
    const result = await store.retrieve('noone@test.com', 'github');
    expect(result).toBeNull();
  });
});

describe('OAuth conflict redirect — pendingLinkStore integration', () => {
  const conflictConfig: AuthConfig = {
    accessTokenSecret: 'test-access-secret-very-long-and-secure',
    refreshTokenSecret: 'test-refresh-secret-very-long-and-secure',
    email: { siteUrl: 'http://localhost:3000' },
  };

  const oauthProviderCfg = {
    name: 'fakeprovider',
    clientId: 'c',
    clientSecret: 's',
    callbackUrl: 'http://cb',
    authorizationUrl: 'http://auth',
    tokenUrl: 'http://token',
    userInfoUrl: 'http://userinfo',
    scope: 'email',
  };

  function makeBasicUserStore(): IUserStore {
    return {
      findByEmail: vi.fn().mockResolvedValue(null),
      findById: vi.fn().mockResolvedValue(null),
      create: vi.fn().mockResolvedValue(undefined),
      updateRefreshToken: vi.fn().mockResolvedValue(undefined),
      updateLastLogin: vi.fn().mockResolvedValue(undefined),
      updateResetToken: vi.fn().mockResolvedValue(undefined),
      updatePassword: vi.fn().mockResolvedValue(undefined),
      updateTotpSecret: vi.fn().mockResolvedValue(undefined),
      updateMagicLinkToken: vi.fn().mockResolvedValue(undefined),
      updateSmsCode: vi.fn().mockResolvedValue(undefined),
    };
  }

  it('stashes conflict data and includes email in redirect URL when pendingLinkStore is provided', async () => {
    const { GenericOAuthStrategy } = await import('../src/strategies/oauth/generic-oauth.strategy');

    const pendingStore: IPendingLinkStore = {
      stash: vi.fn().mockResolvedValue(undefined),
      retrieve: vi.fn().mockResolvedValue(null),
      remove: vi.fn().mockResolvedValue(undefined),
    };

    class ConflictStrategy extends GenericOAuthStrategy {
      override async handleCallback(_code: string, _state?: string): Promise<any> {
        throw new AuthError('conflict', 'OAUTH_ACCOUNT_CONFLICT', 409, {
          email: 'conflict@test.com',
          providerAccountId: 'gid-conflict-123',
        });
      }
      async findOrCreateUser(): Promise<any> { return null; }
    }

    const userStore = makeBasicUserStore();
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, conflictConfig, {
      oauthStrategies: [new ConflictStrategy(oauthProviderCfg)],
      pendingLinkStore: pendingStore,
    }));

    const res = await request(app).get('/auth/oauth/fakeprovider/callback?code=fake-code');
    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('account-conflict');
    expect(res.headers.location).toContain('provider=fakeprovider');
    expect(res.headers.location).toContain('email=conflict%40test.com');
    expect(pendingStore.stash).toHaveBeenCalledWith('conflict@test.com', 'fakeprovider', 'gid-conflict-123');
  });

  it('redirects without email param when AuthError has no data', async () => {
    const { GenericOAuthStrategy } = await import('../src/strategies/oauth/generic-oauth.strategy');

    class ConflictStrategyNoData extends GenericOAuthStrategy {
      override async handleCallback(_code: string, _state?: string): Promise<any> {
        throw new AuthError('conflict', 'OAUTH_ACCOUNT_CONFLICT', 409);
      }
      async findOrCreateUser(): Promise<any> { return null; }
    }

    const userStore = makeBasicUserStore();
    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(userStore, conflictConfig, {
      oauthStrategies: [new ConflictStrategyNoData(oauthProviderCfg)],
    }));

    const res = await request(app).get('/auth/oauth/fakeprovider/callback?code=fake-code');
    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('account-conflict');
    expect(res.headers.location).not.toContain('email=');
  });
});

describe('CSRF auto-initialization middleware', () => {
  it('sets csrf-token cookie on any request when csrf.enabled is true and cookie is absent', async () => {
    const csrfConfig: AuthConfig = {
      accessTokenSecret: 'test-access-secret-very-long-and-secure',
      refreshTokenSecret: 'test-refresh-secret-very-long-and-secure',
      csrf: { enabled: true },
    };
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
    app.use('/auth', createAuthRouter(userStore, csrfConfig));
    const res = await request(app).post('/auth/login').send({ email: 'a@a.com', password: 'pass' });
    const setCookieHeader = res.headers['set-cookie'] as string[] | string | undefined;
    const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : setCookieHeader ? [setCookieHeader] : [];
    expect(cookies.some((c: string) => c.startsWith('csrf-token='))).toBe(true);
  });

  it('does not set csrf-token cookie when csrf is disabled', async () => {
    const nocsrfConfig: AuthConfig = {
      accessTokenSecret: 'test-access-secret-very-long-and-secure',
      refreshTokenSecret: 'test-refresh-secret-very-long-and-secure',
    };
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
    app.use('/auth', createAuthRouter(userStore, nocsrfConfig));
    const res = await request(app).post('/auth/login').send({ email: 'a@a.com', password: 'pass' });
    const setCookieHeader = res.headers['set-cookie'] as string[] | string | undefined;
    const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : setCookieHeader ? [setCookieHeader] : [];
    expect(cookies.some((c: string) => c.startsWith('csrf-token='))).toBe(false);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Session Management Integration Tests
// ────────────────────────────────────────────────────────────────────────────
describe('Session Management', () => {
  const sessionConfig: AuthConfig = {
    accessTokenSecret: 'test-access-secret-very-long-and-secure',
    refreshTokenSecret: 'test-refresh-secret-very-long-and-secure',
    accessTokenExpiresIn: '15m',
    refreshTokenExpiresIn: '7d',
    session: { checkOn: 'refresh' },
  };

  function makeSessionStore() {
    const sessions = new Map<string, SessionInfo>();
    return {
      sessions,
      createSession: vi.fn((info: Omit<SessionInfo, 'sessionHandle'>) => {
        const handle = `test-handle-${Math.random().toString(36).slice(2)}`;
        const s: SessionInfo = { sessionHandle: handle, ...info };
        sessions.set(handle, s);
        return Promise.resolve(s);
      }),
      getSession: vi.fn((handle: string) => Promise.resolve(sessions.get(handle) ?? null)),
      getSessionsForUser: vi.fn((userId: string) => Promise.resolve([...sessions.values()].filter(s => s.userId === userId))),
      updateSessionLastActive: vi.fn().mockResolvedValue(undefined),
      revokeSession: vi.fn((handle: string) => { sessions.delete(handle); return Promise.resolve(); }),
      revokeAllSessionsForUser: vi.fn(),
    };
  }

  let sessionStore: ReturnType<typeof makeSessionStore>;
  let sessionUsers: Map<string, BaseUser>;
  let app: express.Application;

  beforeAll(async () => {
    const hash = await new PasswordService().hash('pass');
    sessionUsers = new Map([['u1', { id: 'u1', email: 's@test.com', password: hash }]]);
  });

  beforeEach(() => {
    sessionStore = makeSessionStore();
    const store: IUserStore = {
      findByEmail: vi.fn((email: string) => Promise.resolve([...sessionUsers.values()].find(u => u.email === email) ?? null)),
      findById: vi.fn((id: string) => Promise.resolve(sessionUsers.get(id) ?? null)),
      create: vi.fn(),
      updateRefreshToken: vi.fn((id, token, expiry) => {
        const u = sessionUsers.get(id);
        if (u) { u.refreshToken = token; u.refreshTokenExpiry = expiry; }
        return Promise.resolve();
      }),
      updateLastLogin: vi.fn().mockResolvedValue(undefined),
      updateResetToken: vi.fn(),
      updatePassword: vi.fn(),
      updateTotpSecret: vi.fn(),
      updateMagicLinkToken: vi.fn(),
      updateSmsCode: vi.fn(),
    };
    app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(store, sessionConfig, { sessionStore: sessionStore as any }));
  });

  it('login creates a new session in the store', async () => {
    const res = await request(app).post('/auth/login').send({ email: 's@test.com', password: 'pass' });
    expect(res.status).toBe(200);
    expect(sessionStore.createSession).toHaveBeenCalledOnce();
    expect(sessionStore.sessions.size).toBe(1);
  });

  it('login embeds sid in the access token', async () => {
    const res = await request(app).post('/auth/login').send({ email: 's@test.com', password: 'pass' });
    expect(res.status).toBe(200);
    const cookies = (res.headers['set-cookie'] as string[]) ?? [];
    const atCookie = cookies.find(c => c.startsWith('accessToken='));
    expect(atCookie).toBeDefined();
    const token = atCookie!.split(';')[0].split('=').slice(1).join('=');
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    expect(payload.sid).toBeDefined();
  });

  it('logout revokes the session in the store', async () => {
    await request(app).post('/auth/login').send({ email: 's@test.com', password: 'pass' });
    const handle = [...sessionStore.sessions.keys()][0];
    const loginTokens = new TokenService().generateTokenPair({ sub: 'u1', email: 's@test.com', sid: handle }, sessionConfig);
    await request(app).post('/auth/logout').set('Cookie', `accessToken=${loginTokens.accessToken}`);
    expect(sessionStore.revokeSession).toHaveBeenCalledWith(handle);
    expect(sessionStore.sessions.has(handle)).toBe(false);
  });

  it('refresh rejects when session has been revoked (checkOn=refresh)', async () => {
    const ts = new TokenService();
    const handle = 'old-handle';
    // Simulate a valid refresh token but revoked session
    const tokens = ts.generateTokenPair({ sub: 'u1', email: 's@test.com', sid: handle }, sessionConfig);
    (sessionUsers.get('u1') as BaseUser).refreshToken = tokens.refreshToken;
    // Session does NOT exist in store — revoked
    const res = await request(app).post('/auth/refresh').set('Cookie', `refreshToken=${tokens.refreshToken}`);
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('SESSION_REVOKED');
  });

  it('refresh rotates the session (revokes old, creates new)', async () => {
    // Login to get an initial session
    await request(app).post('/auth/login').send({ email: 's@test.com', password: 'pass' });
    const oldHandle = [...sessionStore.sessions.keys()][0];
    const user = sessionUsers.get('u1')!;
    const oldRefreshToken = user.refreshToken!;
    expect(sessionStore.sessions.size).toBe(1);

    // Refresh
    const res = await request(app).post('/auth/refresh').set('Cookie', `refreshToken=${oldRefreshToken}`);
    expect(res.status).toBe(200);

    // Old session is gone, new one was created
    expect(sessionStore.sessions.has(oldHandle)).toBe(false);
    expect(sessionStore.sessions.size).toBe(1);
    const newHandle = [...sessionStore.sessions.keys()][0];
    expect(newHandle).not.toBe(oldHandle);
  });
});
