/**
 * Represents an OAuth account linked to a user.
 */
export interface LinkedAccount {
  /** Provider name, e.g. `'google'`, `'github'`. */
  provider: string;
  /** Unique user identifier returned by the provider. */
  providerAccountId: string;
  /** Email address returned by the provider (optional). */
  email?: string;
  /** Display name returned by the provider (optional). */
  name?: string;
  /** Profile picture URL returned by the provider (optional). */
  picture?: string;
  /** When the account was linked (optional). */
  linkedAt?: Date;
}

/**
 * Store for managing multiple OAuth provider accounts linked to a single user.
 *
 * Implement this interface to support flexible account linking, where a single
 * user can have multiple OAuth providers linked to their account and can
 * selectively unlink individual providers.
 *
 * When provided to `createAuthRouter` via `RouterOptions.linkedAccountsStore`,
 * the following endpoints become available:
 * - `GET  /auth/linked-accounts`                              — list linked accounts (authenticated)
 * - `DELETE /auth/linked-accounts/:provider/:providerAccountId` — unlink an account (authenticated)
 *
 * @example
 * ```typescript
 * import { ILinkedAccountsStore, LinkedAccount } from '@awesome-lang-auth/node';
 *
 * export class MyLinkedAccountsStore implements ILinkedAccountsStore {
 *   async getLinkedAccounts(userId: string): Promise<LinkedAccount[]> {
 *     return db('linked_accounts').where({ userId });
 *   }
 *   async linkAccount(userId: string, account: LinkedAccount): Promise<void> {
 *     await db('linked_accounts').insert({ userId, ...account });
 *   }
 *   async unlinkAccount(userId: string, provider: string, providerAccountId: string): Promise<void> {
 *     await db('linked_accounts').where({ userId, provider, providerAccountId }).delete();
 *   }
 *   async findUserByProviderAccount(provider: string, providerAccountId: string): Promise<{ userId: string } | null> {
 *     const row = await db('linked_accounts').where({ provider, providerAccountId }).first();
 *     return row ? { userId: row.userId } : null;
 *   }
 * }
 * ```
 */
export interface ILinkedAccountsStore {
  /**
   * Return all OAuth accounts linked to the given user.
   */
  getLinkedAccounts(userId: string): Promise<LinkedAccount[]>;

  /**
   * Persist a new linked account for the given user.
   * Implementations should be idempotent: re-linking the same
   * `(provider, providerAccountId)` pair should not create a duplicate.
   */
  linkAccount(userId: string, account: LinkedAccount): Promise<void>;

  /**
   * Remove the link between the given user and the specified provider account.
   */
  unlinkAccount(userId: string, provider: string, providerAccountId: string): Promise<void>;

  /**
   * Look up the user ID that has the given provider account linked.
   * Returns `null` if no match is found.
   */
  findUserByProviderAccount(provider: string, providerAccountId: string): Promise<{ userId: string } | null>;
}
