import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';
import { JwksService, JwksClient } from '../src/services/jwks.service';
import { TokenService, _resetEphemeralWarning } from '../src/services/token.service';
import { AuthConfig } from '../src/models/auth-config.model';
import { createAuthRouter } from '../src/router/auth.router';
import { IUserStore } from '../src/interfaces/user-store.interface';
import jwt from 'jsonwebtoken';

describe('JwksService', () => {
  describe('generateKeypair', () => {
    it('returns PEM-encoded private and public keys', () => {
      const { privateKey, publicKey } = JwksService.generateKeypair();
      expect(privateKey).toContain('BEGIN PRIVATE KEY');
      expect(publicKey).toContain('BEGIN PUBLIC KEY');
    });

    it('generates unique keypairs on each call', () => {
      const kp1 = JwksService.generateKeypair();
      const kp2 = JwksService.generateKeypair();
      expect(kp1.privateKey).not.toBe(kp2.privateKey);
      expect(kp1.publicKey).not.toBe(kp2.publicKey);
    });
  });

  describe('derivePublicKey', () => {
    it('derives the correct public key from a private key', () => {
      const { privateKey, publicKey } = JwksService.generateKeypair();
      const derived = JwksService.derivePublicKey(privateKey);
      expect(derived.trim()).toBe(publicKey.trim());
    });
  });

  describe('publicKeyToJwk', () => {
    let publicKey: string;

    beforeEach(() => {
      ({ publicKey } = JwksService.generateKeypair());
    });

    it('returns a JWK with correct fields', () => {
      const jwk = JwksService.publicKeyToJwk(publicKey, 'test-kid');
      expect(jwk.kty).toBe('RSA');
      expect(jwk.use).toBe('sig');
      expect(jwk.alg).toBe('RS256');
      expect(jwk.kid).toBe('test-kid');
      expect(typeof jwk.n).toBe('string');
      expect(typeof jwk.e).toBe('string');
    });

    it('uses the provided kid', () => {
      const jwk = JwksService.publicKeyToJwk(publicKey, 'my-custom-kid');
      expect(jwk.kid).toBe('my-custom-kid');
    });
  });

  describe('buildJwksDocument', () => {
    it('returns a document with a keys array containing one JWK', () => {
      const { publicKey } = JwksService.generateKeypair();
      const doc = JwksService.buildJwksDocument(publicKey);
      expect(Array.isArray(doc.keys)).toBe(true);
      expect(doc.keys).toHaveLength(1);
      expect(doc.keys[0].kty).toBe('RSA');
    });

    it('uses the default kid when not specified', () => {
      const { publicKey } = JwksService.generateKeypair();
      const doc = JwksService.buildJwksDocument(publicKey);
      expect(doc.keys[0].kid).toBe('provisioner-key-1');
    });

    it('uses a custom kid when specified', () => {
      const { publicKey } = JwksService.generateKeypair();
      const doc = JwksService.buildJwksDocument(publicKey, 'custom-kid');
      expect(doc.keys[0].kid).toBe('custom-kid');
    });
  });

  describe('jwkToPublicKey', () => {
    it('round-trips: publicKeyToJwk → jwkToPublicKey produces an equivalent key', () => {
      const { publicKey } = JwksService.generateKeypair();
      const jwk = JwksService.publicKeyToJwk(publicKey, 'kid-1');
      const recovered = JwksService.jwkToPublicKey(jwk);
      // Both should be PEM public keys
      expect(recovered).toContain('BEGIN PUBLIC KEY');
      // Normalized comparison
      expect(recovered.trim()).toBe(publicKey.trim());
    });
  });

  describe('createRemoteClient', () => {
    it('returns a JwksClient instance', () => {
      const client = JwksService.createRemoteClient('https://example.com/.well-known/jwks.json');
      expect(client).toBeInstanceOf(JwksClient);
      expect(client.jwksUrl).toBe('https://example.com/.well-known/jwks.json');
    });
  });
});

describe('JwksClient', () => {
  it('invalidateCache resets cached state', () => {
    const client = new JwksClient('https://example.com/.well-known/jwks.json');
    // Should not throw
    client.invalidateCache();
  });
});

describe('TokenService IdP methods', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    _resetEphemeralWarning();
  });

  it('generateIdProviderTokenPair throws when idProvider is not enabled', () => {
    const service = new TokenService();
    const config: AuthConfig = {
      accessTokenSecret: 'x',
      refreshTokenSecret: 'y',
    };
    expect(() =>
      service.generateIdProviderTokenPair({ sub: '1', email: 'a@b.com' }, config),
    ).toThrow();
  });

  it('generateIdProviderTokenPair produces RS256-signed tokens', () => {
    const service = new TokenService();
    const { privateKey } = JwksService.generateKeypair();
    const config: AuthConfig = {
      accessTokenSecret: 'x',
      refreshTokenSecret: 'y',
      idProvider: {
        enabled: true,
        privateKey,
        issuer: 'https://idp.example.com',
        tokenExpiry: '1h',
      },
    };
    const pair = service.generateIdProviderTokenPair(
      { sub: '1', email: 'test@example.com' },
      config,
    );
    expect(pair.accessToken).toBeTruthy();
    expect(pair.refreshToken).toBeTruthy();

    // Header should declare RS256 and contain kid
    const decoded = jwt.decode(pair.accessToken, { complete: true }) as { header: { alg: string; kid: string }; payload: { iss: string } } | null;
    expect(decoded!.header.alg).toBe('RS256');
    expect(decoded!.header.kid).toBe('provisioner-key-1');
    expect(decoded!.payload.iss).toBe('https://idp.example.com');
  });

  it('generateIdProviderTokenPair auto-generates a keypair when privateKey is omitted', () => {
    const service = new TokenService();
    const config: AuthConfig = {
      accessTokenSecret: 'x',
      refreshTokenSecret: 'y',
      idProvider: {
        enabled: true,
        issuer: 'https://idp.example.com',
      },
    };
    const pair = service.generateIdProviderTokenPair(
      { sub: '2', email: 'auto@example.com' },
      config,
    );
    expect(pair.accessToken).toBeTruthy();
    // The auto-generated keypair should be cached on the config object
    expect(config.idProvider!.privateKey).toBeTruthy();
    expect(config.idProvider!.publicKey).toBeTruthy();
  });

  it('verifyWithJwks validates a token signed with the matching keypair', async () => {
    const service = new TokenService();
    const { privateKey, publicKey } = JwksService.generateKeypair();
    const config: AuthConfig = {
      accessTokenSecret: 'x',
      refreshTokenSecret: 'y',
      idProvider: {
        enabled: true,
        privateKey,
        publicKey,
        issuer: 'https://idp.example.com',
        tokenExpiry: '1h',
      },
    };

    const pair = service.generateIdProviderTokenPair(
      { sub: '3', email: 'verify@example.com' },
      config,
    );

    const doc = JwksService.buildJwksDocument(publicKey, 'provisioner-key-1');
    const client = new JwksClient('https://idp.example.com/.well-known/jwks.json');
    vi.spyOn(client, 'getJwks').mockResolvedValue(doc);
    vi.spyOn(client, 'getKey').mockImplementation(async (kid: string) => {
      return doc.keys.find((k) => k.kid === kid) ?? null;
    });

    const payload = await service.verifyWithJwks(
      pair.accessToken,
      client,
      'https://idp.example.com',
    );

    expect(payload.sub).toBe('3');
    expect(payload.email).toBe('verify@example.com');
    expect(payload.iss).toBe('https://idp.example.com');
  });

  it('generateIdProviderTokenPair activates with only privateKey set (no enabled, no issuer)', () => {
    const service = new TokenService();
    const { privateKey } = JwksService.generateKeypair();
    const config: AuthConfig = {
      accessTokenSecret: 'x',
      refreshTokenSecret: 'y',
      idProvider: {
        privateKey,
      },
    };
    const pair = service.generateIdProviderTokenPair(
      { sub: '10', email: 'pkonly@example.com' },
      config,
    );
    expect(pair.accessToken).toBeTruthy();
    expect(pair.refreshToken).toBeTruthy();

    const decoded = jwt.decode(pair.accessToken, { complete: true }) as { header: { alg: string; kid: string }; payload: Record<string, unknown> } | null;
    expect(decoded!.header.alg).toBe('RS256');
    // No issuer set → no iss claim
    expect(decoded!.payload.iss).toBeUndefined();
  });

  it('generateIdProviderTokenPair with enabled:true and no privateKey auto-generates keypair and emits warning', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const service = new TokenService();
    const config: AuthConfig = {
      accessTokenSecret: 'x',
      refreshTokenSecret: 'y',
      idProvider: {
        enabled: true,
      },
    };
    const pair = service.generateIdProviderTokenPair(
      { sub: '11', email: 'ephemeral@example.com' },
      config,
    );
    expect(pair.accessToken).toBeTruthy();
    // Keypair cached on config
    expect(config.idProvider!.privateKey).toBeTruthy();
    expect(config.idProvider!.publicKey).toBeTruthy();
    // Warning emitted
    expect(warnSpy).toHaveBeenCalledOnce();
    expect(warnSpy.mock.calls[0][0]).toContain('ephemeral RSA keypair');
  });

  it('ephemeral keypair warning is emitted only once per process, not on each call', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const service = new TokenService();
    const config: AuthConfig = {
      accessTokenSecret: 'x',
      refreshTokenSecret: 'y',
      idProvider: {
        enabled: true,
      },
    };
    // Call multiple times
    service.generateIdProviderTokenPair({ sub: '12', email: 'once1@example.com' }, config);
    service.generateIdProviderTokenPair({ sub: '12', email: 'once2@example.com' }, config);
    service.generateIdProviderTokenPair({ sub: '12', email: 'once3@example.com' }, config);
    // Warning should only fire once
    expect(warnSpy).toHaveBeenCalledOnce();
  });
});

describe('Auth Router — IdP / Resource Server mode', () => {
  /** Minimal IUserStore stub — enough for the router to boot. */
  function makeStore(): IUserStore {
    return {
      findByEmail: vi.fn().mockResolvedValue(null),
      findById: vi.fn().mockResolvedValue(null),
      create: vi.fn(),
      updateRefreshToken: vi.fn().mockResolvedValue(undefined),
      updateLastLogin: vi.fn().mockResolvedValue(undefined),
      updateResetToken: vi.fn().mockResolvedValue(undefined),
      updatePassword: vi.fn().mockResolvedValue(undefined),
      updateTotpSecret: vi.fn().mockResolvedValue(undefined),
      updateMagicLinkToken: vi.fn().mockResolvedValue(undefined),
      updateSmsCode: vi.fn().mockResolvedValue(undefined),
    } as unknown as IUserStore;
  }

  it('GET /.well-known/jwks.json returns a valid JWKS document when idProvider.enabled', async () => {
    const { privateKey } = JwksService.generateKeypair();
    const config: AuthConfig = {
      accessTokenSecret: 'secret',
      refreshTokenSecret: 'refresh',
      idProvider: {
        enabled: true,
        privateKey,
        issuer: 'https://idp.example.com',
        jwksPath: '/.well-known/jwks.json',
      },
    };

    const app = express();
    app.use(express.json());
    app.use('/', createAuthRouter(makeStore(), config));

    const res = await request(await listen(app)).get('/.well-known/jwks.json');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.keys)).toBe(true);
    expect(res.body.keys[0].kty).toBe('RSA');
    expect(res.body.keys[0].alg).toBe('RS256');
    expect(res.body.keys[0].kid).toBe('provisioner-key-1');
  });

  it('JWKS endpoint respects a custom jwksPath', async () => {
    const { privateKey } = JwksService.generateKeypair();
    const config: AuthConfig = {
      accessTokenSecret: 'secret',
      refreshTokenSecret: 'refresh',
      idProvider: {
        enabled: true,
        privateKey,
        issuer: 'https://idp.example.com',
        jwksPath: '/custom/jwks.json',
      },
    };

    const app = express();
    app.use(express.json());
    app.use('/', createAuthRouter(makeStore(), config));

    const res = await request(await listen(app)).get('/custom/jwks.json');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.keys)).toBe(true);
  });

  it('POST /login returns 404 when resourceServer.enabled = true', async () => {
    const config: AuthConfig = {
      accessTokenSecret: 'secret',
      refreshTokenSecret: 'refresh',
      resourceServer: {
        enabled: true,
        jwksUrl: 'https://idp.example.com/.well-known/jwks.json',
        issuer: 'https://idp.example.com',
      },
    };

    const app = express();
    app.use(express.json());
    app.use('/auth', createAuthRouter(makeStore(), config));

    const res = await request(await listen(app)).post('/auth/login').send({ email: 'a@b.com', password: 'pw' });
    expect(res.status).toBe(404);
  });
});
