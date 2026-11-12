/**
 * POST /auth/register body sanitization (issue #40).
 *
 * The router strips system-managed fields from the request body before a
 * custom `onRegister` callback (and `config.email.sendWelcome`) sees it, so the
 * natural `store.create({ ...data, password: hash })` pattern can no longer be
 * used to register as an administrator.  Tests tagged
 * REGRESSION-REGISTER-CUSTOM-MASS-ASSIGNMENT guard against forwarding the raw
 * body to the callback.
 */
import { describe, it, expect, vi, beforeEach, afterEach, type MockInstance } from 'vitest';
import express from 'express';
import request from 'supertest';
import { listen } from './helpers/listen';
import { createAuthRouter, RouterOptions } from '../src/router/auth.router';
import {
  sanitizeRegisterBody,
  BASE_USER_FIELD_CLASS,
  COMMON_PRIVILEGED_KEYS,
} from '../src/router/register-sanitize';
import type { RegisterInput } from '../src/index';
import { AuthConfig } from '../src/models/auth-config.model';
import { BaseUser } from '../src/models/user.model';
import { PasswordService } from '../src/services/password.service';
import { InMemoryUserStore } from '../examples/in-memory-user-store';

const passwordService = new PasswordService();

const baseConfig: AuthConfig = {
  accessTokenSecret: 'register-sanitize-access-secret-very-long-and-secure',
  refreshTokenSecret: 'register-sanitize-refresh-secret-very-long-and-secure',
  accessTokenExpiresIn: '15m',
  refreshTokenExpiresIn: '7d',
};

const EMAIL = 'eve@x.test';
const PASSWORD = 'Str0ngPass!';

const ATTACK_BODY = {
  email: EMAIL,
  password: PASSWORD,
  firstName: 'A',
  role: 'admin',
  isAdmin: true,
  isEmailVerified: true,
  loginProvider: 'google',
  resetToken: 'r',
  magicLinkToken: 'm',
  phoneNumber: '+390000',
  require2FA: false,
  roles: ['admin'],
  tenantId: 't1',
  metadata: { plan: 'pro' },
  _id: 'x',
  company: 'ACME',
};

const PRIVILEGED_ATTACK_KEYS = [
  'role', 'isAdmin', 'isEmailVerified', 'loginProvider', 'resetToken', 'magicLinkToken',
  'phoneNumber', 'require2FA', 'roles', 'tenantId', 'metadata', '_id',
];

/** The vulnerable pattern, on purpose: the whole body is spread into the user. */
function vulnerableOnRegister(store: InMemoryUserStore, seen: string[][] = []) {
  return vi.fn(async (data: Record<string, unknown>) => {
    // Snapshot at call time: the same object is reused (and may be mutated) afterwards.
    seen.push(Object.keys(data));
    return store.create({ ...data, password: await passwordService.hash(String(data.password)) } as Partial<BaseUser>);
  });
}

function buildApp(store: InMemoryUserStore, options: RouterOptions = {}, config: AuthConfig = baseConfig) {
  const app = express();
  app.use(express.json());
  app.use('/auth', createAuthRouter(store, config, options));
  return app;
}

function stderrLines(spy: MockInstance): string[] {
  return spy.mock.calls.map((c) => String(c[0]));
}

describe('sanitizeRegisterBody', () => {
  it('returns an empty result for a non-object body', () => {
    for (const body of [null, undefined, 'email=a', 42, true, [], [{ role: 'admin' }]]) {
      expect(sanitizeRegisterBody(body)).toEqual({ data: {}, strippedFields: [] });
    }
  });

  it('strips every system BaseUser key and every common privileged key, keeps input keys and unknown keys', () => {
    const body: Record<string, unknown> = {};
    for (const key of Object.keys(BASE_USER_FIELD_CLASS)) body[key] = `v-${key}`;
    for (const key of COMMON_PRIVILEGED_KEYS) body[key] = `v-${key}`;
    body['company'] = 'ACME';
    const { data, strippedFields } = sanitizeRegisterBody(body);
    expect(Object.keys(data).sort()).toEqual(['company', 'email', 'firstName', 'lastName', 'password']);
    const expectedStripped = [
      ...Object.entries(BASE_USER_FIELD_CLASS).filter(([, c]) => c === 'system').map(([k]) => k),
      ...COMMON_PRIVILEGED_KEYS,
    ].sort();
    expect(strippedFields).toEqual(expectedStripped);
  });

  it('compares keys exactly and case-sensitively, and does not confuse Object.prototype names with system fields', () => {
    const { data, strippedFields } = sanitizeRegisterBody({ Role: 'x', ROLE: 'y', ' role': 'z', toString: 't', hasOwnProperty: 'h', valueOf: 'v' });
    expect(Object.keys(data).sort()).toEqual([' role', 'ROLE', 'Role', 'hasOwnProperty', 'toString', 'valueOf']);
    expect(strippedFields).toEqual([]);
  });

  it('copies only own enumerable keys, keeps values by reference and returns a normal mutable object', () => {
    const proto = { role: 'admin', inherited: 'yes' };
    const body = Object.create(proto) as Record<string, unknown>;
    const nested = { role: 'admin' };
    body['profile'] = nested;
    Object.defineProperty(body, 'hidden', { value: 'h', enumerable: false });
    const { data, strippedFields } = sanitizeRegisterBody(body);
    expect(Object.keys(data)).toEqual(['profile']);
    expect(data['profile']).toBe(nested);
    expect(strippedFields).toEqual([]);
    expect(Object.getPrototypeOf(data)).toBe(Object.prototype);
    data['verificationLink'] = 'https://x.test/verify';
    expect(data['verificationLink']).toBe('https://x.test/verify');
    expect(body['verificationLink']).toBeUndefined();
  });

  it('applies allow and extraDeny with the documented precedence', () => {
    const body = JSON.parse('{"role":"r","isAdmin":true,"tenantId":"t","company":"c","__proto__":{"x":1},"constructor":"c","prototype":"p"}');
    const { data, strippedFields } = sanitizeRegisterBody(body, {
      allow: ['role', 'tenantId', '__proto__', 'constructor', 'prototype'],
      extraDeny: ['company', 'tenantId'],
    });
    // allow keeps role; extraDeny beats allow (tenantId); prototype keys are always stripped.
    expect(Object.keys(data)).toEqual(['role']);
    expect(Object.prototype.hasOwnProperty.call(data, '__proto__')).toBe(false);
    expect(strippedFields).toEqual(['__proto__', 'company', 'constructor', 'isAdmin', 'prototype', 'tenantId']);
  });
});

describe('POST /auth/register sanitizes the body before onRegister', () => {
  let stderrSpy: MockInstance;

  beforeEach(() => {
    stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  });

  afterEach(() => {
    stderrSpy.mockRestore();
  });

  it('REGRESSION-REGISTER-CUSTOM-MASS-ASSIGNMENT: the vulnerable spread callback cannot store privileged fields', async () => {
    const store = new InMemoryUserStore();
    const seen: string[][] = [];
    const onRegister = vulnerableOnRegister(store, seen);
    const app = buildApp(store, { onRegister });

    const res = await request(await listen(app)).post('/auth/register').send(ATTACK_BODY);

    // Criterion 1: 201, and the stored user carries only the harmless fields.
    expect(res.status).toBe(201);
    const created = await store.findById(res.body.userId as string);
    expect(created).not.toBeNull();
    const stored = created as unknown as Record<string, unknown>;
    expect(stored['firstName']).toBe('A');
    expect(stored['company']).toBe('ACME');
    for (const key of PRIVILEGED_ATTACK_KEYS) {
      if (key === '_id') continue; // checked below: the store assigns its own `id`
      expect(stored, key).not.toHaveProperty(key);
    }
    expect(stored).not.toHaveProperty('_id');
    expect(created!.role).toBeUndefined();
    expect(created!.isAdmin).toBeUndefined();
    expect(created!.isEmailVerified).not.toBe(true);
    expect(await passwordService.compare(PASSWORD, created!.password as string)).toBe(true);

    // Criterion 2: the callback saw exactly email, password, firstName and company.
    expect(onRegister).toHaveBeenCalledTimes(1);
    expect(seen[0].sort()).toEqual(['company', 'email', 'firstName', 'password']);

    // Criterion 3: one stderr line naming the ignored fields, never values or the address.
    const warnLines = stderrLines(stderrSpy).filter((l) => /POST \/register ignored body fields: /.test(l));
    expect(warnLines).toHaveLength(1);
    expect(warnLines[0]).toMatch(/POST \/register ignored body fields: .*role/);
    expect(warnLines[0]).toBe(
      `[awesome-node-auth] WARN: POST /register ignored body fields: ${[...PRIVILEGED_ATTACK_KEYS].sort().join(', ')}\n`,
    );
    expect(warnLines[0]).not.toContain('admin');
    expect(warnLines[0]).not.toContain(EMAIL);
    expect(warnLines[0]).not.toContain('ACME');
  });

  it('REGRESSION-REGISTER-CUSTOM-MASS-ASSIGNMENT: writes no ignored-fields line when nothing is stripped', async () => {
    const store = new InMemoryUserStore();
    const app = buildApp(store, { onRegister: vulnerableOnRegister(store) });
    const res = await request(await listen(app)).post('/auth/register').send({ email: EMAIL, password: PASSWORD, company: 'ACME' });
    expect(res.status).toBe(201);
    expect(stderrLines(stderrSpy).some((l) => l.includes('ignored body fields'))).toBe(false);
  });

  it('REGRESSION-REGISTER-CUSTOM-MASS-ASSIGNMENT: a JSON "__proto__" key neither reaches the callback nor pollutes Object.prototype', async () => {
    const store = new InMemoryUserStore();
    const captured: Array<Record<string, unknown>> = [];
    const onRegister = vi.fn(async (data: Record<string, unknown>) => {
      captured.push(data);
      return store.create({ ...data, password: await passwordService.hash(String(data.password)) } as Partial<BaseUser>);
    });
    const app = buildApp(store, { onRegister });

    // A raw JSON string: an object literal with __proto__ would set its prototype and JSON.stringify would drop it.
    const raw = `{"email":"${EMAIL}","password":"${PASSWORD}","__proto__":{"isAdmin":true,"role":"admin"}}`;
    const res = await request(await listen(app))
      .post('/auth/register')
      .set('Content-Type', 'application/json')
      .send(raw);

    expect(res.status).toBe(201);
    expect(captured).toHaveLength(1);
    expect(Object.prototype.hasOwnProperty.call(captured[0], '__proto__')).toBe(false);
    expect(Object.keys(captured[0]).sort()).toEqual(['email', 'password']);
    expect((captured[0] as { isAdmin?: unknown }).isAdmin).toBeUndefined();
    expect(({} as Record<string, unknown>).isAdmin).toBeUndefined();
    expect(({} as Record<string, unknown>).role).toBeUndefined();
    const created = await store.findById(res.body.userId as string);
    expect(created!.isAdmin).toBeUndefined();
    expect(created!.role).toBeUndefined();
    expect(stderrLines(stderrSpy).some((l) => l.includes('ignored body fields: __proto__'))).toBe(true);
  });

  it('REGRESSION-REGISTER-CUSTOM-MASS-ASSIGNMENT: registerDenyFields removes extra keys from data and from the stored user', async () => {
    const store = new InMemoryUserStore();
    const seen: string[][] = [];
    const app = buildApp(store, { onRegister: vulnerableOnRegister(store, seen), registerDenyFields: ['company'] });

    const res = await request(await listen(app)).post('/auth/register').send({ email: EMAIL, password: PASSWORD, company: 'ACME', plan: 'pro' });

    expect(res.status).toBe(201);
    expect(seen[0].sort()).toEqual(['email', 'password', 'plan']);
    const created = await store.findById(res.body.userId as string);
    expect(created).not.toHaveProperty('company');
    expect((created as unknown as Record<string, unknown>)['plan']).toBe('pro');
    expect(stderrLines(stderrSpy)).toContain('[awesome-node-auth] WARN: POST /register ignored body fields: company\n');
  });

  it('REGRESSION-REGISTER-CUSTOM-MASS-ASSIGNMENT: registerAllowFields keeps the listed keys, warns at mount, and still strips the rest', async () => {
    const store = new InMemoryUserStore();
    const seen: string[][] = [];
    const captured: Array<Record<string, unknown>> = [];
    const onRegister = vi.fn(async (data: Record<string, unknown>) => {
      seen.push(Object.keys(data));
      captured.push({ ...data });
      return store.create({ email: String(data.email), password: await passwordService.hash(String(data.password)) });
    });
    const app = buildApp(store, { onRegister, registerAllowFields: ['role', 'tenantId'] });

    // One WARN line per allowed field, written at router creation.
    const mountLines = stderrLines(stderrSpy).filter((l) => l.includes('(registerAllowFields)'));
    expect(mountLines).toEqual([
      '[awesome-node-auth] WARN: POST /register accepts the protected field "role" from the request body (registerAllowFields); validate it in onRegister.\n',
      '[awesome-node-auth] WARN: POST /register accepts the protected field "tenantId" from the request body (registerAllowFields); validate it in onRegister.\n',
    ]);

    const res = await request(await listen(app))
      .post('/auth/register')
      .send({ email: EMAIL, password: PASSWORD, role: 'host', tenantId: 't1', isAdmin: true });
    expect(res.status).toBe(201);
    expect(seen[0].sort()).toEqual(['email', 'password', 'role', 'tenantId']);
    expect(captured[0]['role']).toBe('host');
    expect(captured[0]['tenantId']).toBe('t1');
    expect(captured[0]).not.toHaveProperty('isAdmin');
    expect(stderrLines(stderrSpy)).toContain('[awesome-node-auth] WARN: POST /register ignored body fields: isAdmin\n');
    // Mount-time lines are not repeated per request.
    expect(stderrLines(stderrSpy).filter((l) => l.includes('(registerAllowFields)'))).toHaveLength(2);
  });

  it('REGRESSION-REGISTER-CUSTOM-MASS-ASSIGNMENT: registerAllowFields cannot allow a prototype key', async () => {
    const store = new InMemoryUserStore();
    const captured: Array<Record<string, unknown>> = [];
    const onRegister = vi.fn(async (data: Record<string, unknown>) => {
      captured.push(data);
      return store.create({ email: String(data.email) });
    });
    const app = buildApp(store, { onRegister, registerAllowFields: ['__proto__'] });
    expect(stderrLines(stderrSpy).some((l) => l.includes('accepts the protected field'))).toBe(false);
    expect(stderrLines(stderrSpy).some((l) => l.includes('registerAllowFields lists "__proto__"'))).toBe(true);

    const res = await request(await listen(app))
      .post('/auth/register')
      .set('Content-Type', 'application/json')
      .send(`{"email":"${EMAIL}","password":"${PASSWORD}","__proto__":{"isAdmin":true}}`);
    expect(res.status).toBe(201);
    expect(Object.prototype.hasOwnProperty.call(captured[0], '__proto__')).toBe(false);
    expect((captured[0] as { isAdmin?: unknown }).isAdmin).toBeUndefined();
    expect(({} as Record<string, unknown>).isAdmin).toBeUndefined();
  });

  it('REGRESSION-REGISTER-CUSTOM-MASS-ASSIGNMENT: registerAllowFields mount lines do not claim an entry denied or not stripped by default is accepted', async () => {
    const store = new InMemoryUserStore();
    const captured: Array<Record<string, unknown>> = [];
    const onRegister = vi.fn(async (data: Record<string, unknown>) => {
      captured.push({ ...data });
      return store.create({ email: String(data.email) });
    });
    const app = buildApp(store, {
      onRegister,
      registerAllowFields: ['company', 'role', 'email', 'tenantId'],
      registerDenyFields: ['role'],
    });

    const lines = stderrLines(stderrSpy);
    // Only tenantId (stripped by default, not denied) is announced as accepted.
    expect(lines.filter((l) => l.includes('accepts the protected field'))).toEqual([
      '[awesome-node-auth] WARN: POST /register accepts the protected field "tenantId" from the request body (registerAllowFields); validate it in onRegister.\n',
    ]);
    expect(lines).toContain('[awesome-node-auth] WARN: registerAllowFields lists "role", which is also in registerDenyFields; it stays stripped.\n');
    expect(lines).toContain('[awesome-node-auth] INFO: registerAllowFields lists "company", which is not stripped by default; the entry has no effect.\n');
    expect(lines).toContain('[awesome-node-auth] INFO: registerAllowFields lists "email", which is not stripped by default; the entry has no effect.\n');

    const res = await request(await listen(app))
      .post('/auth/register')
      .send({ email: EMAIL, password: PASSWORD, company: 'ACME', role: 'admin', tenantId: 't1' });
    expect(res.status).toBe(201);
    // The mount lines match the request-time behaviour: deny beats allow.
    expect(captured[0]).not.toHaveProperty('role');
    expect(captured[0]['company']).toBe('ACME');
    expect(captured[0]['tenantId']).toBe('t1');
    expect(stderrLines(stderrSpy)).toContain('[awesome-node-auth] WARN: POST /register ignored body fields: role\n');
  });

  it('does not write registerAllowFields mount lines when POST /register is not mounted by onRegister', () => {
    const store = new InMemoryUserStore();
    buildApp(store, { registerAllowFields: ['role'] });
    buildApp(store, { defaultRegister: true, registerAllowFields: ['role'] });
    expect(stderrLines(stderrSpy).some((l) => l.includes('(registerAllowFields)'))).toBe(false);
  });

  it('REGRESSION-REGISTER-CUSTOM-MASS-ASSIGNMENT: sendWelcome gets the sanitized data without password, plus values onRegister attached', async () => {
    const sendWelcome = vi.fn().mockResolvedValue(undefined);
    const config: AuthConfig = { ...baseConfig, email: { sendWelcome } };
    const store = new InMemoryUserStore();
    const onRegister = vi.fn(async (data: RegisterInput) => {
      const user = await store.create({ email: String(data.email), password: await passwordService.hash(String(data.password)) });
      data.verificationLink = 'https://app.x.test/verify-email?token=abc';
      return user;
    });
    const app = buildApp(store, { onRegister }, config);

    const res = await request(await listen(app))
      .post('/auth/register')
      .send({ email: EMAIL, password: PASSWORD, firstName: 'A', role: 'admin', isAdmin: true, company: 'ACME' });

    expect(res.status).toBe(201);
    expect(sendWelcome).toHaveBeenCalledTimes(1);
    const [to, welcomeData] = sendWelcome.mock.calls[0] as [string, Record<string, unknown>];
    expect(to).toBe(EMAIL);
    expect(welcomeData).toEqual({
      email: EMAIL,
      firstName: 'A',
      company: 'ACME',
      verificationLink: 'https://app.x.test/verify-email?token=abc',
    });
    expect(welcomeData).not.toHaveProperty('password');
    expect(welcomeData).not.toHaveProperty('role');
    expect(welcomeData).not.toHaveProperty('isAdmin');
  });

  it('the built-in handler keeps its own allow-list and still stores only email, hash, firstName and lastName', async () => {
    const store = new InMemoryUserStore();
    const app = buildApp(store, { defaultRegister: true });
    const res = await request(await listen(app)).post('/auth/register').send({ ...ATTACK_BODY, lastName: 'B' });
    expect(res.status).toBe(201);
    const created = await store.findById(res.body.userId as string);
    expect(Object.keys(created!).sort()).toEqual(['email', 'firstName', 'id', 'lastName', 'password']);
  });
});
