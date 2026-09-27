/**
 * Base interface for a pending OAuth account-link document stored in a
 * database.  Use this as the foundation for Mongoose schemas or other ORM
 * models so that the exact document shape is known at compile time.
 *
 * @example
 * ```typescript
 * // Mongoose example
 * import { IPendingLink } from '@awesome-lang-auth/node';
 * import { Schema, model, Document } from 'mongoose';
 *
 * interface IPendingLinkDoc extends IPendingLink, Document {}
 *
 * const pendingLinkSchema = new Schema<IPendingLinkDoc>({
 *   email:             { type: String, required: true, index: true },
 *   provider:          { type: String, required: true },
 *   providerAccountId: { type: String, required: true },
 *   createdAt:         { type: Date,   default: Date.now },
 * });
 * ```
 */
export interface IPendingLink {
  email: string;
  provider: string;
  providerAccountId: string;
  createdAt: Date;
}

/**
 * Store for temporarily persisting OAuth account-link data for unauthenticated
 * users who encountered an `OAUTH_ACCOUNT_CONFLICT`.
 *
 * Implement this interface and pass it as `pendingLinkStore` in `RouterOptions`
 * to enable native unauthenticated account linking.  When present, the library
 * will automatically stash the conflicting provider details and include the
 * `email` and `provider` query parameters in the `/auth/account-conflict`
 * redirect so the front-end can drive the verification flow without any
 * custom server-side routes.
 *
 * @example
 * ```typescript
 * import { IPendingLinkStore } from '@awesome-lang-auth/node';
 *
 * export class InMemoryPendingLinkStore implements IPendingLinkStore {
 *   private store = new Map<string, { providerAccountId: string }>();
 *
 *   private key(email: string, provider: string) { return `${email}::${provider}`; }
 *
 *   async stash(email: string, provider: string, providerAccountId: string) {
 *     this.store.set(this.key(email, provider), { providerAccountId });
 *   }
 *   async retrieve(email: string, provider: string) {
 *     return this.store.get(this.key(email, provider)) ?? null;
 *   }
 *   async remove(email: string, provider: string) {
 *     this.store.delete(this.key(email, provider));
 *   }
 * }
 * ```
 */
export interface IPendingLinkStore {
  /**
   * Persist a pending link so it can be retrieved later during `/link-verify`.
   */
  stash(email: string, provider: string, providerAccountId: string): Promise<void>;

  /**
   * Retrieve the stashed `providerAccountId` for the given `email`/`provider`
   * pair, or `null` if no pending link exists.
   */
  retrieve(email: string, provider: string): Promise<{ providerAccountId: string } | null>;

  /**
   * Remove a stashed entry after it has been consumed or invalidated.
   */
  remove(email: string, provider: string): Promise<void>;
}
