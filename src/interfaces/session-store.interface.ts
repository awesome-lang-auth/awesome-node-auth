import { SessionInfo } from '../models/session.model';

/**
 * Optional store for device-aware session management.
 *
 * Implement this interface when you need to give users visibility into
 * (and control over) their active sessions — similar to "Manage devices"
 * screens in modern applications.
 *
 * Each session is identified by an opaque `sessionHandle` (e.g. a UUID or a
 * hex token) that is independent of the JWT.  This lets you list, inspect,
 * and revoke individual sessions without invalidating all tokens at once.
 *
 * @example
 * ```typescript
 * import { ISessionStore } from '@awesome-lang-auth/node';
 *
 * export class MySessionStore implements ISessionStore {
 *   async createSession(info) {
 *     const handle = crypto.randomUUID();
 *     await db('sessions').insert({ handle, ...info });
 *     return { sessionHandle: handle, ...info };
 *   }
 *   async getSession(handle) {
 *     return db('sessions').where({ handle }).first() ?? null;
 *   }
 *   async getSessionsForUser(userId) {
 *     return db('sessions').where({ userId });
 *   }
 *   async updateSessionLastActive(handle) {
 *     await db('sessions').where({ handle }).update({ lastActiveAt: new Date() });
 *   }
 *   async revokeSession(handle) {
 *     await db('sessions').where({ handle }).delete();
 *   }
 *   async revokeAllSessionsForUser(userId) {
 *     await db('sessions').where({ userId }).delete();
 *   }
 * }
 * ```
 */
export interface ISessionStore {
  /**
   * Persist a new session and return it with the generated `sessionHandle`.
   */
  createSession(
    info: Omit<SessionInfo, 'sessionHandle'>,
  ): Promise<SessionInfo>;

  /**
   * Retrieve a session by its handle.
   * Returns `null` when the session does not exist or has expired.
   */
  getSession(sessionHandle: string): Promise<SessionInfo | null>;

  /**
   * Return all active sessions for the given user.
   * When `tenantId` is provided only sessions belonging to that tenant are
   * returned.
   */
  getSessionsForUser(userId: string, tenantId?: string): Promise<SessionInfo[]>;

  /**
   * Bump the `lastActiveAt` timestamp for the given session.
   * Call this on every authenticated request to keep session activity up to date.
   */
  updateSessionLastActive(sessionHandle: string): Promise<void>;

  /**
   * Invalidate (delete) a single session.
   *
   * If `AuthConfig.session.checkOn` is set to `'allcalls'`, access is revoked
   * immediately. If set to `'refresh'`, access is revoked at the next token
   * rotation.
   */
  revokeSession(sessionHandle: string): Promise<void>;

  /**
   * Invalidate all sessions for the given user (e.g. "log out everywhere").
   * When `tenantId` is provided only sessions for that tenant are revoked.
   */
  revokeAllSessionsForUser(userId: string, tenantId?: string): Promise<void>;

  /**
   * Return all active sessions across all users.
   * Used by the optional admin router to display the sessions table.
   *
   * @param limit  Maximum number of records to return.
   * @param offset Zero-based offset for pagination.
   */
  getAllSessions?(limit: number, offset: number): Promise<SessionInfo[]>;

  /**
   * Delete all sessions whose `expiresAt` timestamp is in the past.
   * Intended to be called periodically (e.g. from a cron job) via the
   * `POST /auth/sessions/cleanup` endpoint.
   *
   * @returns The number of sessions that were deleted.
   */
  deleteExpiredSessions?(): Promise<number>;
}
