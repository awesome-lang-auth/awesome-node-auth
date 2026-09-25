import { EventEmitter } from 'events';

/**
 * Metadata attached to every event emitted on the AuthEventBus.
 */
export interface AuthEventPayload {
  /** The event name (e.g. `identity.auth.login.success`). */
  event: string;
  /** Timestamp when the event was created (ISO 8601). */
  timestamp: string;
  /** Arbitrary event data. */
  data?: unknown;
  /** User ID associated with the event (optional). */
  userId?: string;
  /** Tenant ID for multi-tenant isolation (optional). */
  tenantId?: string;
  /** Session ID (optional). */
  sessionId?: string;
  /** Correlation ID for distributed tracing (optional). */
  correlationId?: string;
  /** Client IP address (optional). */
  ip?: string;
  /** Client User-Agent header value (optional). */
  userAgent?: string;
}

/**
 * Central event bus for all identity-related events.
 *
 * Acts as the backbone of the event-driven tools system.  Auth core
 * components emit standardised events here; downstream handlers (telemetry,
 * SSE, webhooks, analytics) subscribe and react without coupling to each other.
 *
 * The bus is intentionally lightweight — it wraps Node's built-in
 * `EventEmitter` so there is zero runtime overhead when no listeners are
 * registered.
 *
 * @example
 * ```ts
 * import { AuthEventBus, AuthEventNames } from '@awesome-lang-auth/node';
 *
 * const bus = new AuthEventBus();
 * bus.onEvent(AuthEventNames.AUTH_LOGIN_SUCCESS, (payload) => {
 *   console.log('Login:', payload.userId);
 * });
 * ```
 */
export class AuthEventBus extends EventEmitter {
  /**
   * Emit an event onto the bus.
   *
   * @param eventName  Standardised event name (see `AuthEventNames`).
   * @param payload    Event metadata and data.
   */
  publish(eventName: string, payload: Omit<AuthEventPayload, 'event' | 'timestamp'> & { timestamp?: string }): void {
    const full: AuthEventPayload = {
      ...payload,
      event: eventName,
      timestamp: payload.timestamp ?? new Date().toISOString(),
    };
    this.emit(eventName, full);
    // Also emit on a wildcard channel so blanket listeners can subscribe to all events.
    this.emit('*', full);
  }

  /**
   * Subscribe to a specific event.
   *
   * @param eventName  Event name to listen for, or `'*'` for all events.
   * @param handler    Callback invoked with the full event payload.
   */
  onEvent(eventName: string, handler: (payload: AuthEventPayload) => void): this {
    return this.on(eventName, handler);
  }

  /**
   * Remove a previously registered event handler.
   */
  offEvent(eventName: string, handler: (payload: AuthEventPayload) => void): this {
    return this.off(eventName, handler);
  }
}
