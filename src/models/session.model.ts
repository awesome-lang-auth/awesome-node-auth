/**
 * Represents an active user session with optional device/context metadata.
 *
 * Implementations of `ISessionStore` use this shape to persist and retrieve
 * session records. All fields beyond `sessionHandle`, `userId`, `createdAt`,
 * and `expiresAt` are optional so you only store what you actually need.
 */
export interface SessionInfo {
  /** Unique opaque identifier for this session (e.g. a UUID or a hex token). */
  sessionHandle: string;
  /** ID of the user who owns this session. */
  userId: string;
  /** Tenant ID — set when multi-tenancy is enabled. */
  tenantId?: string;
  /** When the session was created. */
  createdAt: Date;
  /** When the session expires. */
  expiresAt: Date;
  /** When the session was last used (updated on each authenticated request). */
  lastActiveAt?: Date;
  /** User-Agent header from the client that created the session. */
  userAgent?: string;
  /** IP address that created the session. */
  ipAddress?: string;
  /** Arbitrary session-level data (e.g. device name, geo-location, etc.). */
  data?: Record<string, unknown>;
  /** SHA-256 hash of the active refresh token for this session (multi-device support). */
  refreshTokenHash?: string;
}
