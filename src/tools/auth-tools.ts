import { randomUUID } from 'crypto';
import { AuthEventBus, AuthEventPayload } from '../events/auth-event-bus';
import { ITelemetryStore, TelemetryEvent } from '../interfaces/telemetry-store.interface';
import { IWebhookStore, OutgoingWebhookEvent } from '../interfaces/webhook-store.interface';
import { ISseDistributor } from '../interfaces/sse-distributor.interface';
import { IUserStore } from '../interfaces/user-store.interface';
import { SseManager, StreamEvent } from './sse-manager';
import { WebhookSender } from './webhook-sender';
import { SseNotifyRegistry } from './sse-notify.decorator';
import { NotificationService, EmailNotificationConfig, SmsNotificationConfig } from '../services/notification.service';

/**
 * Options passed to {@link AuthTools}.
 */
export interface AuthToolsOptions {
  /**
   * Optional telemetry store.  When provided, every tracked event is also
   * persisted via `store.save()`.
   */
  telemetryStore?: ITelemetryStore;

  /**
   * Optional webhook store.  When provided, outgoing webhooks are dispatched
   * whenever an event is tracked.
   */
  webhookStore?: IWebhookStore;

  /**
   * When `true`, SSE streaming is enabled.  A `SseManager` instance will be
   * created and the `/tools/stream` endpoint will be available.
   * @default false
   */
  sse?: boolean;

  /**
   * Options forwarded to the `SseManager` constructor.
   */
  sseOptions?: {
    /** @default 30000 */
    heartbeatIntervalMs?: number;
    /** Distributor for cross-instance event synchronization. */
    distributor?: ISseDistributor;
    /** @default true */
    deduplicate?: boolean;
  };

  /**
   * Optional custom SSE distributor for AuthTools.notify().
   * When provided it is used instead of the internal SseManager broadcaster.
   */
  sseDistributor?: ISseDistributor;

  /**
   * Semantic version string attached to all outgoing webhook payloads.
   * @default '1'
   */
  webhookVersion?: string;

  /**
   * Optional user store.  Required when using `'email'` or `'sms'` channels
   * in {@link AuthTools.notify} so the service can look up the user's contact
   * details by `options.userId`.
   *
   * @since 1.8.0
   */
  userStore?: IUserStore;

  /**
   * Email transport configuration.  When provided, the `'email'` channel in
   * {@link AuthTools.notify} will send emails using the built-in HTTP mailer.
   *
   * Accepts the same shape as `AuthConfig.email.mailer`.
   *
   * @since 1.8.0
   */
  emailConfig?: EmailNotificationConfig;

  /**
   * SMS transport configuration.  When provided, the `'sms'` channel in
   * {@link AuthTools.notify} will send SMS messages using the built-in SMS
   * service.
   *
   * Accepts the same shape as `AuthConfig.sms`.
   *
   * @since 1.8.0
   */
  smsConfig?: SmsNotificationConfig;
}

/**
 * Options for {@link AuthTools.track}.
 */
export interface TrackOptions {
  userId?: string;
  tenantId?: string;
  sessionId?: string;
  correlationId?: string;
  ip?: string;
  userAgent?: string;
}

/**
 * Options for {@link AuthTools.notify}.
 */
export interface NotifyOptions {
  type?: string;
  tenantId?: string;
  userId?: string;
  metadata?: Record<string, unknown>;
  /**
   * Delivery channels.  Defaults to `['sse']` (backward-compatible).
   *
   * - `'sse'`   — broadcast to SSE subscribers on the given `target` topic.
   * - `'email'` — send an email to the user identified by `userId` (requires
   *               `userStore` and `emailConfig` in {@link AuthToolsOptions}).
   * - `'sms'`   — send an SMS to the user identified by `userId` (requires
   *               `userStore` and `smsConfig` in {@link AuthToolsOptions}).
   *
   * When multiple channels are listed, all are attempted; a failure in one
   * channel does **not** abort the others.
   *
   * @since 1.8.0
   * @default ['sse']
   */
  channels?: Array<'sse' | 'email' | 'sms'>;
  /**
   * Email subject override.  Used when `channels` includes `'email'`.
   * Defaults to the stringified `options.type` or `'Notification'`.
   *
   * @since 1.8.0
   */
  emailSubject?: string;
  /**
   * SMS message body override.  Used when `channels` includes `'sms'`.
   * Defaults to the JSON-stringified `data` payload.
   *
   * @since 1.8.0
   */
  smsMessage?: string;
}

/**
 * The main tools module.
 *
 * Provides a unified API for telemetry tracking, real-time SSE notifications,
 * and outgoing webhooks.  All capabilities are optional and have zero overhead
 * when disabled.
 *
 * ```ts
 * import { AuthTools, AuthEventBus } from '@awesome-lang-auth/node';
 *
 * const bus = new AuthEventBus();
 * const tools = new AuthTools(bus, {
 *   telemetryStore: myStore,
 *   webhookStore: myWebhookStore,
 *   sse: true,
 * });
 *
 * // Track an event programmatically
 * await tools.track('identity.auth.login.success', { user }, { userId: user.id });
 *
 * // Notify a topic over SSE
 * await tools.notify('user:123', { message: 'Welcome!' });
 * ```
 */
export class AuthTools {
  readonly eventBus: AuthEventBus;
  readonly sseManager: SseManager | null;
  private readonly telemetryStore?: ITelemetryStore;
  private readonly webhookStore?: IWebhookStore;
  private readonly webhookSender: WebhookSender;
  private readonly webhookVersion: string;
  private readonly userStore?: IUserStore;
  private readonly notificationService?: NotificationService;
  private readonly sseDistributor?: ISseDistributor;

  constructor(eventBus: AuthEventBus, options: AuthToolsOptions = {}) {
    this.eventBus = eventBus;
    this.telemetryStore = options.telemetryStore;
    this.webhookStore = options.webhookStore;
    this.webhookSender = new WebhookSender();
    this.webhookVersion = options.webhookVersion ?? '1';
    this.sseManager = options.sse ? new SseManager(options.sseOptions) : null;
    this.sseDistributor = options.sseDistributor;
    this.userStore = options.userStore;

    if (options.sse && options.sseDistributor) {
      process.stderr.write(
        '[awesome-node-auth] WARN: AuthTools received both sse=true and sseDistributor; notify() will use the custom distributor.\n',
      );
    }

    if (options.emailConfig || options.smsConfig) {
      this.notificationService = new NotificationService({
        email: options.emailConfig,
        sms: options.smsConfig,
      });
    }

    if (this.sseManager) {
      SseNotifyRegistry.setManager(this.sseManager);
    }
  }

  /**
   * Track an event: persist it (optional), emit it on the event bus, broadcast
   * it to SSE subscribers and fire matching outgoing webhooks.
   *
   * @param eventName  Standardised event name (see `AuthEventNames`).
   * @param data       Arbitrary event data.
   * @param options    Metadata (userId, tenantId, …).
   */
  async track(eventName: string, data?: unknown, options: TrackOptions = {}): Promise<void> {
    const id = randomUUID();
    const timestamp = new Date().toISOString();

    const telemetryEvent: TelemetryEvent = {
      id,
      event: eventName,
      timestamp,
      data,
      userId: options.userId,
      tenantId: options.tenantId,
      sessionId: options.sessionId,
      correlationId: options.correlationId,
      ip: options.ip,
      userAgent: options.userAgent,
    };

    // 1. Persist
    if (this.telemetryStore) {
      await this.telemetryStore.save(telemetryEvent).catch(() => {/* best-effort */ });
    }

    // 2. Emit on the event bus
    const busPayload: Omit<AuthEventPayload, 'event' | 'timestamp'> = {
      data,
      userId: options.userId,
      tenantId: options.tenantId,
      sessionId: options.sessionId,
      correlationId: options.correlationId,
      ip: options.ip,
      userAgent: options.userAgent,
    };
    this.eventBus.publish(eventName, busPayload);

    // 3. SSE broadcast (topic per tenant or global)
    if (this.sseManager) {
      const topics = this.resolveTopics(eventName, options);
      const streamEvent: Omit<StreamEvent, 'id' | 'timestamp' | 'topic'> & { id: string; timestamp: string } = {
        id,
        timestamp,
        type: eventName,
        data: telemetryEvent,
        userId: options.userId,
        tenantId: options.tenantId,
      };
      for (const topic of topics) {
        this.sseManager.broadcast(topic, streamEvent);
      }
    }

    // 4. Outgoing webhooks
    if (this.webhookStore) {
      const configs = await this.webhookStore.findByEvent(eventName, options.tenantId).catch(() => []);
      const webhookEvent: OutgoingWebhookEvent = {
        event: eventName,
        version: this.webhookVersion,
        timestamp,
        data: data ?? null,
        metadata: {
          userId: options.userId,
          tenantId: options.tenantId,
          sessionId: options.sessionId,
          correlationId: options.correlationId,
        },
      };
      for (const config of configs) {
        // Fire-and-forget; don't let webhook failures block the caller
        this.webhookSender.send(config, webhookEvent).catch(() => {/* best-effort */ });
      }
    }
  }

  /**
   * Send a notification to one or more delivery channels.
   *
   * By default (or when `channels` is `['sse']`) the behaviour is identical to
   * the original synchronous broadcast.  Pass additional channels to also
   * deliver the notification via email and/or SMS.
   *
   * When `'email'` or `'sms'` is included the method becomes asynchronous and
   * requires:
   *   - `userStore` — to look up the user's contact details by `options.userId`.
   *   - `emailConfig` / `smsConfig` — transport configuration in
   *     {@link AuthToolsOptions}.
   *
   * Channel failures are best-effort and do not reject the returned Promise.
   *
   * @param target   Target SSE topic (e.g. `'user:123'`, `'tenant:acme'`).
   * @param data     Payload to deliver.
   * @param options  Channels, type, tenantId, userId, metadata, etc.
   *
   * @since 1.8.0 (async + multi-channel)
   */
  async notify<T = unknown>(target: string, data: T, options: NotifyOptions = {}): Promise<void> {
    const channels = options.channels ?? ['sse'];

    // ── 1. SSE ──────────────────────────────────────────────────────────────
    if (channels.includes('sse')) {
      const streamEvent = {
        type: options.type ?? 'notification',
        data,
        tenantId: options.tenantId,
        userId: options.userId,
        metadata: options.metadata,
      };
      if (this.sseDistributor) {
        // Publish a complete StreamEvent, as SseManager.broadcast() does:
        // receivers (SseManager included) deduplicate on `id`.
        const fullEvent: StreamEvent<T> = {
          id: randomUUID(),
          timestamp: new Date().toISOString(),
          topic: target,
          ...streamEvent,
        };
        this.sseDistributor.publish(target, fullEvent).catch(() => {/* best-effort */});
      } else if (this.sseManager) {
        this.sseManager.broadcast<T>(target, streamEvent);
      }
    }

    // ── 2. Email / SMS (only when userId is provided and userStore is set) ───
    if ((channels.includes('email') || channels.includes('sms')) && options.userId && this.userStore) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let user: any = null;
      try {
        user = await this.userStore.findById(options.userId);
      } catch {
        user = null;
      }

      if (user) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const u = user as any;

        // ── 2a. Email ─────────────────────────────────────────────────────
        if (channels.includes('email') && u.email && this.notificationService?.hasEmail) {
          const subject = options.emailSubject ?? (options.type ? String(options.type) : 'Notification');
          const body    = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
          this.notificationService.sendEmail({
            to: u.email,
            subject,
            html: `<p>${body.replace(/\n/g, '<br>')}</p>`,
            text: body,
          }).catch(() => {/* best-effort */});
        }

        // ── 2b. SMS ───────────────────────────────────────────────────────
        if (channels.includes('sms') && u.phoneNumber && this.notificationService?.hasSms) {
          const message = options.smsMessage ?? (typeof data === 'string' ? data : JSON.stringify(data));
          this.notificationService.sendSms({
            to: u.phoneNumber,
            message,
          }).catch(() => {/* best-effort */});
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /**
   * Resolve the SSE topics an event should be broadcast to.
   * Always includes `'global'`; additionally adds tenant and user topics when
   * the corresponding IDs are present.
   */
  private resolveTopics(eventName: string, options: TrackOptions): string[] {
    const topics: string[] = ['global'];
    if (options.tenantId) topics.push(`tenant:${options.tenantId}`);
    if (options.userId) topics.push(`user:${options.userId}`);
    if (options.sessionId) topics.push(`session:${options.sessionId}`);
    return topics;
  }
}
