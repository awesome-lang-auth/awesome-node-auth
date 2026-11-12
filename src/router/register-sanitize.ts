import type { BaseUser } from '../models/user.model';

/**
 * Classification of every `BaseUser` key for `POST /auth/register`.
 *
 * - `'input'`: may come from the sign-up form.
 * - `'system'`: managed by the library or the app, never taken from the request body.
 *
 * The `satisfies Record<keyof BaseUser, ...>` clause is load-bearing: adding a
 * field to `BaseUser` without classifying it here fails `tsc`, so a future
 * privileged field cannot silently become mass-assignable through sign-up.
 *
 * `phoneNumber` is `'system'` on purpose: it is the destination of the SMS
 * second factor and is set only by the authenticated `POST /auth/add-phone`.
 */
export const BASE_USER_FIELD_CLASS = {
  id: 'system',
  email: 'input',
  password: 'input',
  role: 'system',
  firstName: 'input',
  lastName: 'input',
  loginProvider: 'system',
  refreshToken: 'system',
  refreshTokenExpiry: 'system',
  resetToken: 'system',
  resetTokenExpiry: 'system',
  totpSecret: 'system',
  isEmailVerified: 'system',
  isTotpEnabled: 'system',
  magicLinkToken: 'system',
  magicLinkTokenExpiry: 'system',
  smsCode: 'system',
  smsCodeExpiry: 'system',
  phoneNumber: 'system',
  require2FA: 'system',
  emailVerificationToken: 'system',
  emailVerificationTokenExpiry: 'system',
  emailVerificationDeadline: 'system',
  pendingEmail: 'system',
  emailChangeToken: 'system',
  emailChangeTokenExpiry: 'system',
  accountLinkPendingEmail: 'system',
  accountLinkPendingProvider: 'system',
  accountLinkToken: 'system',
  accountLinkTokenExpiry: 'system',
  providerAccountId: 'system',
  lastLogin: 'system',
  isAdmin: 'system',
} as const satisfies Record<keyof BaseUser, 'input' | 'system'>;

/**
 * Privileged keys that are not part of `BaseUser` but that typical user
 * stores define.  They are stripped from the sign-up body by default.
 */
export const COMMON_PRIVILEGED_KEYS = [
  'roles', 'permissions', 'scopes', 'tenantId', 'tenantIds', 'isActive', 'isSuperAdmin',
  'metadata', 'apiKey', 'apiKeys', '_id', '__v', 'createdAt', 'updatedAt', 'deletedAt',
] as const;

/** Keys that are always stripped, even when listed in `registerAllowFields`. */
const PROTOTYPE_KEYS = ['__proto__', 'constructor', 'prototype'] as const;

// Lookups use Sets built from own keys, never `key in obj`, so that body keys
// such as `toString` or `hasOwnProperty` are not mistaken for system fields.
const SYSTEM_KEYS: ReadonlySet<string> = new Set(
  (Object.keys(BASE_USER_FIELD_CLASS) as Array<keyof typeof BASE_USER_FIELD_CLASS>)
    .filter((key) => BASE_USER_FIELD_CLASS[key] === 'system'),
);
const DEFAULT_DENY: ReadonlySet<string> = new Set<string>([...SYSTEM_KEYS, ...COMMON_PRIVILEGED_KEYS]);
const PROTOTYPE_KEY_SET: ReadonlySet<string> = new Set<string>(PROTOTYPE_KEYS);

/**
 * The `data` argument of `RouterOptions.onRegister`: the sign-up request body
 * without system-managed fields.  Values are `unknown` because they come from
 * the client: validate them before use.
 */
export interface RegisterInput {
  email?: unknown;
  password?: unknown;
  firstName?: unknown;
  lastName?: unknown;
  [key: string]: unknown;
}

export interface SanitizedRegisterBody {
  /** The body without the stripped keys (a fresh, mutable plain object). */
  data: Record<string, unknown>;
  /** Names of the stripped keys, sorted.  Never contains values. */
  strippedFields: string[];
}

export interface SanitizeRegisterBodyOptions {
  /** Extra top-level keys to strip (`RouterOptions.registerDenyFields`). */
  extraDeny?: readonly string[];
  /** Default-stripped keys to keep (`RouterOptions.registerAllowFields`). */
  allow?: readonly string[];
}

/**
 * Remove system-managed keys from a `POST /auth/register` body.
 *
 * - A non-object body (`null`, an array, a string, ...) yields `{ data: {}, strippedFields: [] }`.
 * - Only own enumerable string keys are copied; comparison is exact and case-sensitive.
 * - A key is stripped when it is a `'system'` key of {@link BASE_USER_FIELD_CLASS},
 *   one of {@link COMMON_PRIVILEGED_KEYS}, listed in `extraDeny`, or a prototype key
 *   (`__proto__`, `constructor`, `prototype`).
 * - A key listed in `allow` is kept, unless it is in `extraDeny` or is a prototype key.
 * - Kept values are copied by reference; nested objects are not sanitized.
 */
export function sanitizeRegisterBody(
  body: unknown,
  opts: SanitizeRegisterBodyOptions = {},
): SanitizedRegisterBody {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return { data: {}, strippedFields: [] };
  }
  const extraDeny = new Set<string>(opts.extraDeny ?? []);
  const allow = new Set<string>(opts.allow ?? []);
  const source = body as Record<string, unknown>;
  // Collect into a prototype-less object first, so that no key assignment can
  // reach Object.prototype, then spread into a normal (mutable) object.
  const clean = Object.create(null) as Record<string, unknown>;
  const stripped: string[] = [];
  for (const key of Object.keys(source)) {
    let strip: boolean;
    if (PROTOTYPE_KEY_SET.has(key)) strip = true;
    else if (extraDeny.has(key)) strip = true;
    else if (allow.has(key)) strip = false;
    else strip = DEFAULT_DENY.has(key);
    if (strip) stripped.push(key);
    else clean[key] = source[key];
  }
  return { data: { ...clean }, strippedFields: stripped.sort() };
}
