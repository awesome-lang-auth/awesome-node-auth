/**
 * A single recorded telemetry event.
 */
export interface TelemetryEvent {
  /** Auto-generated unique identifier. */
  id: string;
  /** The event name (e.g. `identity.auth.login.success`). */
  event: string;
  /** ISO 8601 timestamp. */
  timestamp: string;
  /** Arbitrary event data. */
  data?: unknown;
  /** User ID (optional). */
  userId?: string;
  /** Tenant ID for multi-tenant partitioning (optional). */
  tenantId?: string;
  /** Session ID (optional). */
  sessionId?: string;
  /** Correlation ID (optional). */
  correlationId?: string;
  /** Client IP (optional). */
  ip?: string;
  /** Client User-Agent (optional). */
  userAgent?: string;
}

/**
 * Optional filter for querying telemetry events.
 */
export interface TelemetryFilter {
  event?: string;
  userId?: string;
  tenantId?: string;
  sessionId?: string;
  from?: Date;
  to?: Date;
  limit?: number;
  offset?: number;
}

/**
 * Interface for persisting and querying telemetry events.
 *
 * Implement this interface to store telemetry events in any database.
 * When not provided, telemetry events are only emitted on the `AuthEventBus`
 * and forwarded to configured webhooks without being persisted.
 *
 * @example
 * ```typescript
 * import { ITelemetryStore, TelemetryEvent } from '@awesome-lang-auth/node';
 *
 * export class MyTelemetryStore implements ITelemetryStore {
 *   async save(event: TelemetryEvent): Promise<void> {
 *     await db('telemetry').insert(event);
 *   }
 *   async query(filter: TelemetryFilter): Promise<TelemetryEvent[]> {
 *     return db('telemetry').where(filter).limit(filter.limit ?? 100);
 *   }
 * }
 * ```
 */
export interface ITelemetryStore {
  /**
   * Persist a telemetry event.
   */
  save(event: TelemetryEvent): Promise<void>;

  /**
   * Query persisted events with optional filters.
   * Implementing this method is optional but enables the
   * `GET /tools/telemetry` query endpoint.
   */
  query?(filter: TelemetryFilter): Promise<TelemetryEvent[]>;
}
