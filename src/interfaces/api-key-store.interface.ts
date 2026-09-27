import { ApiKey } from '../models/api-key.model';

/**
 * Pluggable persistence interface for API Keys / Service Tokens.
 *
 * Implement this interface and pass the instance to `ApiKeyStrategy` and
 * `ApiKeyService`.  All methods are optional except for `findByPrefix` and
 * `findById` — only the features your application actually needs have to be
 * implemented.
 *
 * @example
 * ```ts
 * import { IApiKeyStore } from '@awesome-lang-auth/node';
 *
 * export class MyApiKeyStore implements IApiKeyStore {
 *   async save(key: ApiKey) {
 *     await db('api_keys').insert(key);
 *   }
 *   async findByPrefix(prefix: string) {
 *     return db('api_keys').where({ keyPrefix: prefix, isActive: true }).first() ?? null;
 *   }
 *   async findById(id: string) {
 *     return db('api_keys').where({ id }).first() ?? null;
 *   }
 *   async revoke(id: string) {
 *     await db('api_keys').where({ id }).update({ isActive: false });
 *   }
 *   async updateLastUsed(id: string) {
 *     await db('api_keys').where({ id }).update({ lastUsedAt: new Date() });
 *   }
 * }
 * ```
 */
export interface IApiKeyStore {
  /**
   * Persist a newly created API key record.
   */
  save(key: ApiKey): Promise<void>;

  /**
   * Look up an active key candidate by its prefix.
   *
   * Because bcrypt comparison is expensive, the prefix is used as a fast
   * lookup index.  The caller will then verify the raw key against the hash.
   *
   * Only return records where `isActive = true`.
   */
  findByPrefix(prefix: string): Promise<ApiKey | null>;

  /**
   * Retrieve a key record by its unique ID.
   * Used for revocation, rotation, and admin management.
   */
  findById(id: string): Promise<ApiKey | null>;

  /**
   * Mark a key as inactive (revoke it).
   * After revocation all subsequent requests using this key must be rejected.
   */
  revoke(id: string): Promise<void>;

  /**
   * Update the `lastUsedAt` timestamp after a successful authentication.
   * Also used for audit purposes.
   */
  updateLastUsed(id: string, at?: Date): Promise<void>;

  /**
   * Return all keys belonging to a given service identity.
   * Optional — only needed if you expose a key-listing UI.
   */
  listByServiceId?(serviceId: string): Promise<ApiKey[]>;

  /**
   * Return all key records (paginated).
   * Optional — only needed for admin management screens.
   */
  listAll?(limit: number, offset: number): Promise<ApiKey[]>;

  /**
   * Permanently delete a key record.
   * Optional — prefer `revoke` for audit-trail preservation.
   */
  delete?(id: string): Promise<void>;

  /**
   * Append a usage audit-log entry for the given key.
   * Optional — implement when you need per-key access logs.
   */
  logUsage?(entry: ApiKeyAuditEntry): Promise<void>;
}

/** A single usage audit record for an API key. */
export interface ApiKeyAuditEntry {
  keyId: string;
  timestamp: Date;
  ip?: string;
  userAgent?: string;
  path?: string;
  method?: string;
  success: boolean;
  failureReason?: string;
}
