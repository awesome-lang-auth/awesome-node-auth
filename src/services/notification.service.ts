/**
 * Notification service for awesome-node-auth.
 *
 * Provides a thin, transport-agnostic wrapper around the built-in
 * `MailerService` and `SmsService` so that business-level notifications
 * (e.g. "your subscription will expire in 3 days") can be sent over the same
 * transports that are already configured for authentication flows — without
 * passing the entire `AuthConfig` to `AuthTools`.
 *
 * @since 1.8.0
 */

import { MailerService } from './mailer.service';
import { SmsService } from './sms.service';
import { MailerConfig } from '../models/auth-config.model';
import { SmsConfig } from './sms.service';

export { SmsConfig };

/**
 * Configuration for the email notification transport.
 *
 * Uses the same shape as `MailerConfig` so that the same object can be passed
 * to both `AuthConfig.email.mailer` and `NotificationService`.
 *
 * @since 1.8.0
 */
export type EmailNotificationConfig = MailerConfig;

/**
 * Configuration for the SMS notification transport.
 *
 * Uses the same shape as `SmsConfig` so that the same object can be passed to
 * both `AuthConfig.sms` and `NotificationService`.
 *
 * @since 1.8.0
 */
export type SmsNotificationConfig = SmsConfig;

/**
 * Options for {@link NotificationService.sendEmail}.
 *
 * @since 1.8.0
 */
export interface SendEmailOptions {
  /** Recipient email address. */
  to: string;
  /** Email subject line. */
  subject: string;
  /** HTML body. */
  html: string;
  /** Plain-text fallback body. */
  text?: string;
}

/**
 * Options for {@link NotificationService.sendSms}.
 *
 * @since 1.8.0
 */
export interface SendSmsOptions {
  /** Recipient phone number (E.164 format recommended). */
  to: string;
  /** SMS message body. */
  message: string;
}

/**
 * A thin facade that exposes email and SMS sending without requiring the
 * entire `AuthConfig`.  Intended for use with `AuthTools.notify()` when
 * email or SMS channels are requested.
 *
 * @example
 * ```ts
 * import { NotificationService } from '@awesome-lang-auth/node';
 *
 * const notifications = new NotificationService({
 *   email: { endpoint: process.env.MAILER_ENDPOINT!, apiKey: process.env.MAILER_KEY!, from: 'no-reply@example.com' },
 *   sms:   { endpoint: process.env.SMS_ENDPOINT!,    apiKey: process.env.SMS_KEY!,    username: '...', password: '...' },
 * });
 *
 * await notifications.sendEmail({
 *   to: 'alice@example.com',
 *   subject: 'Subscription expiring',
 *   html: '<p>Your subscription expires in 3 days.</p>',
 * });
 * ```
 *
 * @since 1.8.0
 */
export class NotificationService {
  private readonly mailer?: MailerService;
  private readonly sms?: SmsService;

  constructor(opts: {
    email?: EmailNotificationConfig;
    sms?: SmsNotificationConfig;
  } = {}) {
    if (opts.email) this.mailer = new MailerService(opts.email);
    if (opts.sms)   this.sms   = new SmsService(opts.sms);
  }

  /**
   * Send a custom email notification.
   *
   * Throws if no email transport is configured.
   *
   * @since 1.8.0
   */
  async sendEmail(opts: SendEmailOptions): Promise<void> {
    if (!this.mailer) {
      throw new Error('[NotificationService] No email transport configured. Pass `email` config to the constructor.');
    }
    await this.mailer.sendCustom(opts.to, opts.subject, opts.html, opts.text);
  }

  /**
   * Send a custom SMS notification.
   *
   * Throws if no SMS transport is configured.
   *
   * @since 1.8.0
   */
  async sendSms(opts: SendSmsOptions): Promise<void> {
    if (!this.sms) {
      throw new Error('[NotificationService] No SMS transport configured. Pass `sms` config to the constructor.');
    }
    await this.sms.sendSms(opts.to, opts.message);
  }

  /** `true` when an email transport is configured. */
  get hasEmail(): boolean { return !!this.mailer; }
  /** `true` when an SMS transport is configured. */
  get hasSms(): boolean { return !!this.sms; }
}
