/**
 * Optional store for arbitrary per-user metadata.
 *
 * Implement this interface when you need to attach project-specific data to
 * users without extending `BaseUser` (e.g. preferences, profile fields,
 * feature flags, or any other key/value pairs).
 *
 * The interface is intentionally generic — your database schema can store
 * metadata as a JSON column, a separate key-value table, or any other way
 * that suits your project.
 *
 * @example
 * ```typescript
 * import { IUserMetadataStore } from '@awesome-lang-auth/node';
 *
 * export class MyUserMetadataStore implements IUserMetadataStore {
 *   async getMetadata(userId: string) {
 *     const row = await db.from('user_metadata').where({ userId }).first();
 *     return row?.data ?? {};
 *   }
 *   async updateMetadata(userId: string, metadata: Record<string, unknown>) {
 *     await db('user_metadata')
 *       .insert({ userId, data: JSON.stringify(metadata) })
 *       .onConflict('userId')
 *       .merge();
 *   }
 *   async clearMetadata(userId: string) {
 *     await db('user_metadata').where({ userId }).delete();
 *   }
 * }
 * ```
 */
export interface IUserMetadataStore {
  /**
   * Retrieve all metadata for the given user.
   * Returns an empty object when no metadata exists.
   */
  getMetadata(userId: string): Promise<Record<string, unknown>>;

  /**
   * Merge (shallow-patch) the provided key/value pairs into the user's
   * existing metadata.  Fields not present in `metadata` are left untouched.
   */
  updateMetadata(userId: string, metadata: Record<string, unknown>): Promise<void>;

  /**
   * Delete all metadata for the given user.
   * Useful when a user account is deleted.
   */
  clearMetadata(userId: string): Promise<void>;
}
