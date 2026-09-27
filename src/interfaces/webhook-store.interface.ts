/**
 * Configuration for a single outgoing webhook subscription.
 */
export interface WebhookConfig {
  /** Unique identifier for this webhook registration. */
  id: string;
  /** The URL to POST events to. */
  url: string;
  /**
   * Event name patterns this webhook subscribes to.
   * Use `'*'` to receive all events, or specific names like
   * `'identity.auth.login.success'`.
   */
  events: string[];
  /** Optional HMAC secret for request signing (SHA-256). */
  secret?: string;
  /** Whether this webhook is currently active. Defaults to `true`. */
  isActive?: boolean;
  /**
   * Tenant ID — when set, this webhook only fires for events belonging to
   * that tenant.  Omit for global webhooks.
   */
  tenantId?: string;
  /**
   * Maximum number of delivery attempts before giving up.
   * Defaults to 3.
   */
  maxRetries?: number;
  /**
   * Initial retry delay in milliseconds for exponential back-off.
   * Defaults to 1000 ms.
   */
  retryDelayMs?: number;

  // ---- Inbound webhook (dynamic execution) ----------------------------------

  /**
   * Provider name for inbound webhooks (e.g. `'stripe'`, `'github'`).
   * When set, this config is used by the tools router when it receives
   * `POST /tools/webhook/:provider` with a matching `:provider` param.
   * Outgoing-only configs should leave this unset.
   */
  provider?: string;

  /**
   * Action IDs permitted for this webhook's `vm` sandbox.
   * Only actions that are **also** in `AuthSettings.enabledWebhookActions`
   * will actually be injected (intersection rule).
   *
   * Managed via the Admin UI's Webhooks → edit drawer.
   */
  allowedActions?: string[];

  /**
   * JavaScript that runs inside the `vm` sandbox when this inbound webhook
   * fires.  The sandbox exposes:
   *   - `body`    — the raw request payload (`unknown`)
   *   - `actions` — filtered action functions keyed by ID
   *
   * The script must assign `result` to instruct the router what event to
   * emit, or leave `result` as `null` to silently ack.
   *
   * @example
   * ```js
   * // jsScript
   * if (body.type === 'customer.subscription.deleted') {
   *   await actions['billing.cancelSubscription'](body.data.object.id);
   *   result = { event: 'identity.tenant.user.removed', data: body.data };
   * }
   * ```
   */
  jsScript?: string;
}

/**
 * The JSON body sent to a webhook endpoint.
 */
export interface OutgoingWebhookEvent {
  /** The standardised event name. */
  event: string;
  /** Semantic version of the event schema. */
  version: string;
  /** ISO 8601 timestamp. */
  timestamp: string;
  /** Arbitrary event data. */
  data: unknown;
  /** Optional metadata (tenantId, userId, correlationId, …). */
  metadata?: Record<string, unknown>;
}

/**
 * Store that holds webhook configurations.
 *
 * Implement this interface to persist webhook subscriptions in any database.
 * When not provided, outgoing webhooks are disabled.
 *
 * @example
 * ```typescript
 * import { IWebhookStore, WebhookConfig } from '@awesome-lang-auth/node';
 *
 * export class MyWebhookStore implements IWebhookStore {
 *   async findByEvent(event: string, tenantId?: string): Promise<WebhookConfig[]> {
 *     return db('webhooks')
 *       .where('isActive', true)
 *       .where((q) => q.where('tenantId', tenantId ?? null).orWhereNull('tenantId'))
 *       .where((q) => q.whereJsonContains('events', event).orWhereJsonContains('events', '*'));
 *   }
 * }
 * ```
 */
export interface IWebhookStore {
  /**
   * Return all active webhook configurations that should receive `event`.
   * Multi-tenant: when `tenantId` is provided, return both tenant-scoped
   * and global (no `tenantId`) webhooks.
   */
  findByEvent(event: string, tenantId?: string): Promise<WebhookConfig[]>;

  /**
   * Return all webhook configurations (paginated).
   * Optional — only needed for admin management screens.
   */
  listAll?(limit: number, offset: number): Promise<WebhookConfig[]>;

  /**
   * Persist a new webhook configuration and return it with an assigned `id`.
   * Optional — only needed when webhooks can be managed through the admin UI.
   */
  add?(config: Omit<WebhookConfig, 'id'>): Promise<WebhookConfig>;

  /**
   * Permanently delete a webhook configuration.
   * Optional — only needed for admin management screens.
   */
  remove?(id: string): Promise<void>;

  /**
   * Apply a partial update to an existing webhook configuration.
   * Optional — only needed for admin management screens (e.g. toggling `isActive`).
   */
  update?(id: string, changes: Partial<Omit<WebhookConfig, 'id'>>): Promise<void>;

  /**
   * Find the inbound webhook configuration for the given provider name.
   * Used by the tools router to look up the `jsScript` and `allowedActions`
   * associated with `POST /tools/webhook/:provider`.
   * Optional — only needed when dynamic script execution is required.
   */
  findByProvider?(provider: string): Promise<WebhookConfig | null>;
}
