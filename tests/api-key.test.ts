/**
 * Tests for the API Key / Service Token plugin:
 *   - ApiKeyService  (create, verify, prefix extraction)
 *   - ApiKeyStrategy (validation, revocation, expiry, IP allowlist, scopes, audit log)
 *   - createApiKeyMiddleware (Express middleware)
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';
import { ApiKeyService } from '../src/services/api-key.service';
import { ApiKeyStrategy } from '../src/strategies/api-key/api-key.strategy';
import { createApiKeyMiddleware } from '../src/middleware/api-key.middleware';
import type { IApiKeyStore } from '../src/interfaces/api-key-store.interface';
import type { ApiKey } from '../src/models/api-key.model';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function makeStore(overrides: Partial<IApiKeyStore> = {}): IApiKeyStore {
  return {
    save: vi.fn().mockResolvedValue(undefined),
    findByPrefix: vi.fn().mockResolvedValue(null),
    findById: vi.fn().mockResolvedValue(null),
    revoke: vi.fn().mockResolvedValue(undefined),
    updateLastUsed: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// ApiKeyService
// ─────────────────────────────────────────────────────────────────────────────
describe('ApiKeyService', () => {
  const service = new ApiKeyService();

  it('generates a raw key with the ak_ prefix', async () => {
    const store = makeStore();
    const { rawKey } = await service.createKey(store, { name: 'test-key' });
    expect(rawKey).toMatch(/^ak_[0-9a-f]{48}$/);
  });

  it('persists the key record via store.save', async () => {
    const store = makeStore();
    const { record } = await service.createKey(store, { name: 'test-key', scopes: ['tools:read'] });
    expect(store.save).toHaveBeenCalledOnce();
    expect(record.name).toBe('test-key');
    expect(record.scopes).toContain('tools:read');
    expect(record.isActive).toBe(true);
    expect(record.keyHash).toBeTruthy();
    expect(record.keyPrefix).toMatch(/^ak_[0-9a-f]{8}$/);
  });

  it('stores only the hash — raw key is not in the record', async () => {
    const store = makeStore();
    const { rawKey, record } = await service.createKey(store, { name: 'test-key' });
    expect(record.keyHash).not.toBe(rawKey);
    expect(JSON.stringify(record)).not.toContain(rawKey);
  });

  it('keyPrefix is 11 chars (ak_ + 8)', async () => {
    const store = makeStore();
    const { rawKey, record } = await service.createKey(store, { name: 'test-key' });
    expect(record.keyPrefix).toHaveLength(11);
    expect(rawKey.startsWith(record.keyPrefix)).toBe(true);
  });

  it('verifyKey returns true for correct key', async () => {
    const store = makeStore();
    const { rawKey, record } = await service.createKey(store, { name: 'test' });
    expect(await service.verifyKey(rawKey, record.keyHash)).toBe(true);
  });

  it('verifyKey returns false for wrong key', async () => {
    const store = makeStore();
    const { record } = await service.createKey(store, { name: 'test' });
    expect(await service.verifyKey('ak_wrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwrong', record.keyHash)).toBe(false);
  });

  it('sets expiresAt when provided', async () => {
    const store = makeStore();
    const exp = new Date(Date.now() + 60_000);
    const { record } = await service.createKey(store, { name: 'test', expiresAt: exp });
    expect(record.expiresAt?.getTime()).toBeCloseTo(exp.getTime(), -2);
  });

  it('sets allowedIps when provided', async () => {
    const store = makeStore();
    const { record } = await service.createKey(store, { name: 'test', allowedIps: ['10.0.0.1'] });
    expect(record.allowedIps).toContain('10.0.0.1');
  });

  it('sets serviceId when provided', async () => {
    const store = makeStore();
    const { record } = await service.createKey(store, { name: 'test', serviceId: 'svc-abc' });
    expect(record.serviceId).toBe('svc-abc');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ApiKeyStrategy
// ─────────────────────────────────────────────────────────────────────────────
describe('ApiKeyStrategy', () => {
  const service = new ApiKeyService();

  async function makeActiveRecord(overrides: Partial<ApiKey> = {}): Promise<{ record: ApiKey; rawKey: string }> {
    const tempStore = makeStore();
    const { rawKey, record } = await service.createKey(tempStore, { name: 'svc', scopes: ['tools:read'] });
    return { rawKey, record: { ...record, ...overrides } };
  }

  it('authenticates with Authorization: ApiKey header', async () => {
    const { rawKey, record } = await makeActiveRecord();
    const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
    const strategy = new ApiKeyStrategy(store);
    const ctx = await strategy.authenticate({ authorization: `ApiKey ${rawKey}` });
    expect(ctx.keyId).toBe(record.id);
    expect(store.updateLastUsed).toHaveBeenCalledWith(record.id, expect.any(Date));
  });

  it('authenticates with X-Api-Key header', async () => {
    const { rawKey, record } = await makeActiveRecord();
    const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
    const strategy = new ApiKeyStrategy(store);
    const ctx = await strategy.authenticate({ 'x-api-key': rawKey });
    expect(ctx.keyId).toBe(record.id);
  });

  it('throws API_KEY_MISSING when no key header is present', async () => {
    const store = makeStore();
    const strategy = new ApiKeyStrategy(store);
    await expect(strategy.authenticate({})).rejects.toMatchObject({ code: 'API_KEY_MISSING' });
  });

  it('throws API_KEY_INVALID for wrong key', async () => {
    const { record } = await makeActiveRecord();
    const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
    const strategy = new ApiKeyStrategy(store);
    // Raw key is 51 chars total (ak_ prefix [3] + 48 hex chars).
    // keyPrefix is 11 chars (ak_ [3] + first 8 hex chars).
    // Padding needed to reach 51 chars: 51 - 11 = 40.
    const fakeKey = record.keyPrefix + 'x'.repeat(40); // same prefix, different tail → bcrypt mismatch
    await expect(strategy.authenticate({ authorization: `ApiKey ${fakeKey}` }))
      .rejects.toMatchObject({ code: 'API_KEY_INVALID' });
  });

  it('throws API_KEY_INVALID when prefix not found in store', async () => {
    const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(null) });
    const strategy = new ApiKeyStrategy(store);
    await expect(strategy.authenticate({ authorization: 'ApiKey ak_00000000xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' }))
      .rejects.toMatchObject({ code: 'API_KEY_INVALID' });
  });

  it('throws API_KEY_REVOKED when isActive=false', async () => {
    const { rawKey, record } = await makeActiveRecord({ isActive: false });
    const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
    const strategy = new ApiKeyStrategy(store);
    await expect(strategy.authenticate({ authorization: `ApiKey ${rawKey}` }))
      .rejects.toMatchObject({ code: 'API_KEY_REVOKED' });
  });

  it('throws API_KEY_EXPIRED when expiresAt is in the past', async () => {
    const past = new Date(Date.now() - 1000);
    const { rawKey, record } = await makeActiveRecord({ expiresAt: past });
    const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
    const strategy = new ApiKeyStrategy(store);
    await expect(strategy.authenticate({ authorization: `ApiKey ${rawKey}` }))
      .rejects.toMatchObject({ code: 'API_KEY_EXPIRED' });
  });

  it('does not expire when expiresAt is in the future', async () => {
    const future = new Date(Date.now() + 60_000);
    const { rawKey, record } = await makeActiveRecord({ expiresAt: future });
    const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
    const strategy = new ApiKeyStrategy(store);
    const ctx = await strategy.authenticate({ authorization: `ApiKey ${rawKey}` });
    expect(ctx.keyId).toBe(record.id);
  });

  describe('IP allowlist', () => {
    it('allows a matching exact IP', async () => {
      const { rawKey, record } = await makeActiveRecord({ allowedIps: ['192.168.1.1'] });
      const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
      const strategy = new ApiKeyStrategy(store);
      const ctx = await strategy.authenticate({ authorization: `ApiKey ${rawKey}` }, '192.168.1.1');
      expect(ctx.keyId).toBe(record.id);
    });

    it('blocks a non-matching IP', async () => {
      const { rawKey, record } = await makeActiveRecord({ allowedIps: ['192.168.1.1'] });
      const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
      const strategy = new ApiKeyStrategy(store);
      await expect(strategy.authenticate({ authorization: `ApiKey ${rawKey}` }, '10.0.0.1'))
        .rejects.toMatchObject({ code: 'API_KEY_IP_BLOCKED' });
    });

    it('allows a CIDR-matched IP', async () => {
      const { rawKey, record } = await makeActiveRecord({ allowedIps: ['10.0.0.0/8'] });
      const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
      const strategy = new ApiKeyStrategy(store);
      const ctx = await strategy.authenticate({ authorization: `ApiKey ${rawKey}` }, '10.42.0.1');
      expect(ctx.keyId).toBe(record.id);
    });

    it('blocks IP outside CIDR', async () => {
      const { rawKey, record } = await makeActiveRecord({ allowedIps: ['10.0.0.0/8'] });
      const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
      const strategy = new ApiKeyStrategy(store);
      await expect(strategy.authenticate({ authorization: `ApiKey ${rawKey}` }, '11.0.0.1'))
        .rejects.toMatchObject({ code: 'API_KEY_IP_BLOCKED' });
    });

    it('skips IP check when enforceIpAllowlist=false', async () => {
      const { rawKey, record } = await makeActiveRecord({ allowedIps: ['192.168.1.1'] });
      const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
      const strategy = new ApiKeyStrategy(store, { enforceIpAllowlist: false });
      const ctx = await strategy.authenticate({ authorization: `ApiKey ${rawKey}` }, '99.99.99.99');
      expect(ctx.keyId).toBe(record.id);
    });

    it('allows IPv4-mapped IPv6 addresses against IPv4 allowlist', async () => {
      const { rawKey, record } = await makeActiveRecord({ allowedIps: ['192.168.1.1'] });
      const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
      const strategy = new ApiKeyStrategy(store);
      const ctx = await strategy.authenticate({ authorization: `ApiKey ${rawKey}` }, '::ffff:192.168.1.1');
      expect(ctx.keyId).toBe(record.id);
    });
  });

  describe('scope enforcement', () => {
    it('allows when key has all required scopes', async () => {
      const { rawKey, record } = await makeActiveRecord({ scopes: ['tools:read', 'tools:write'] });
      const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
      const strategy = new ApiKeyStrategy(store, { requiredScopes: ['tools:read'] });
      const ctx = await strategy.authenticate({ authorization: `ApiKey ${rawKey}` });
      expect(ctx.scopes).toContain('tools:read');
    });

    it('throws API_KEY_INSUFFICIENT_SCOPE when missing scopes', async () => {
      const { rawKey, record } = await makeActiveRecord({ scopes: ['tools:read'] });
      const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
      const strategy = new ApiKeyStrategy(store, { requiredScopes: ['tools:write'] });
      await expect(strategy.authenticate({ authorization: `ApiKey ${rawKey}` }))
        .rejects.toMatchObject({ code: 'API_KEY_INSUFFICIENT_SCOPE' });
    });
  });

  describe('audit log', () => {
    it('calls store.logUsage on success when auditLog=true', async () => {
      const { rawKey, record } = await makeActiveRecord();
      const logUsage = vi.fn().mockResolvedValue(undefined);
      const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record), logUsage });
      const strategy = new ApiKeyStrategy(store, { auditLog: true });
      await strategy.authenticate({ authorization: `ApiKey ${rawKey}` });
      expect(logUsage).toHaveBeenCalledWith(expect.objectContaining({ keyId: record.id, success: true }));
    });

    it('does not call store.logUsage when auditLog=false (default)', async () => {
      const { rawKey, record } = await makeActiveRecord();
      const logUsage = vi.fn().mockResolvedValue(undefined);
      const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record), logUsage });
      const strategy = new ApiKeyStrategy(store);
      await strategy.authenticate({ authorization: `ApiKey ${rawKey}` });
      expect(logUsage).not.toHaveBeenCalled();
    });

    it('logs failed attempts for unknown keys with keyId <unknown>', async () => {
      const logUsage = vi.fn().mockResolvedValue(undefined);
      const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(null), logUsage });
      const strategy = new ApiKeyStrategy(store, { auditLog: true });
      await expect(strategy.authenticate({ authorization: 'ApiKey ak_00000000xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' }))
        .rejects.toMatchObject({ code: 'API_KEY_INVALID' });
      expect(logUsage).toHaveBeenCalledWith(expect.objectContaining({ keyId: '<unknown>', success: false }));
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// createApiKeyMiddleware (Express integration)
// ─────────────────────────────────────────────────────────────────────────────
describe('createApiKeyMiddleware', () => {
  const service = new ApiKeyService();

  async function buildApp(store: IApiKeyStore, options = {}) {
    const app = express();
    app.use(express.json());
    app.use('/protected', createApiKeyMiddleware(store, options), (_req, res) => {
      res.json({ ok: true, apiKey: (_req as express.Request).apiKey });
    });
    return app;
  }

  it('passes through and attaches req.apiKey on valid key (Authorization header)', async () => {
    const tempStore = makeStore();
    const { rawKey, record } = await service.createKey(tempStore, { name: 'svc', scopes: ['r'] });
    const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
    const app = await buildApp(store);
    const res = await request(await listen(app)).get('/protected').set('Authorization', `ApiKey ${rawKey}`);
    expect(res.status).toBe(200);
    expect(res.body.apiKey.keyId).toBe(record.id);
    expect(res.body.apiKey.scopes).toContain('r');
  });

  it('passes through on X-Api-Key header', async () => {
    const tempStore = makeStore();
    const { rawKey, record } = await service.createKey(tempStore, { name: 'svc' });
    const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
    const app = await buildApp(store);
    const res = await request(await listen(app)).get('/protected').set('X-Api-Key', rawKey);
    expect(res.status).toBe(200);
    expect(res.body.apiKey.keyId).toBe(record.id);
  });

  it('returns 401 with JSON error when no API key header is provided', async () => {
    const store = makeStore();
    const app = await buildApp(store);
    const res = await request(await listen(app)).get('/protected');
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('API_KEY_MISSING');
  });

  it('returns 401 when key is invalid', async () => {
    const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(null) });
    const app = await buildApp(store);
    const res = await request(await listen(app)).get('/protected').set('Authorization', 'ApiKey ak_00000000xxxx');
    expect(res.status).toBe(401);
  });

  it('returns 401 for revoked key', async () => {
    const tempStore = makeStore();
    const { rawKey, record } = await service.createKey(tempStore, { name: 'svc' });
    const revokedRecord = { ...record, isActive: false };
    const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(revokedRecord) });
    const app = await buildApp(store);
    const res = await request(await listen(app)).get('/protected').set('Authorization', `ApiKey ${rawKey}`);
    expect(res.status).toBe(401);
    expect(res.body.code).toBe('API_KEY_REVOKED');
  });

  it('returns 403 when required scope is missing', async () => {
    const tempStore = makeStore();
    const { rawKey, record } = await service.createKey(tempStore, { name: 'svc', scopes: ['tools:read'] });
    const store = makeStore({ findByPrefix: vi.fn().mockResolvedValue(record) });
    const app = await buildApp(store, { requiredScopes: ['tools:write'] });
    const res = await request(await listen(app)).get('/protected').set('Authorization', `ApiKey ${rawKey}`);
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('API_KEY_INSUFFICIENT_SCOPE');
  });
});
