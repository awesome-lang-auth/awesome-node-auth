import { Request } from 'express';
import { AuthEventBus, AuthEventPayload } from '../events/auth-event-bus';

/**
 * Internal helpers shared by the auth and admin routers (and `AuthConfigurator`)
 * to publish events on an `AuthEventBus`.  Not part of the public API.
 */

/** `X-Correlation-Id` values accepted into events: 1–128 characters of `[A-Za-z0-9_.:-]`. */
const CORRELATION_ID_PATTERN = /^[\w.:-]{1,128}$/;

/** Longest client-supplied e-mail address copied into an event payload. */
const MAX_EVENT_EMAIL_LENGTH = 320;

type RouterEventPayload = {
  data?: unknown;
  userId?: string;
  tenantId?: string;
  sessionId?: string;
};

/**
 * Request context attached to router events.  A `X-Correlation-Id` header that
 * does not match {@link CORRELATION_ID_PATTERN} is left out.
 */
export function getRequestEventContext(req: Request): {
  correlationId?: string;
  ip?: string;
  userAgent?: string;
} {
  const correlationHeader = req.headers['x-correlation-id'];
  const rawCorrelationId = Array.isArray(correlationHeader) ? correlationHeader[0] : correlationHeader;
  const correlationId = typeof rawCorrelationId === 'string' && CORRELATION_ID_PATTERN.test(rawCorrelationId)
    ? rawCorrelationId
    : undefined;
  const userAgentHeader = req.headers['user-agent'];
  const userAgent = Array.isArray(userAgentHeader) ? userAgentHeader[0] : userAgentHeader;
  return {
    correlationId,
    ip: req.ip || req.socket.remoteAddress,
    userAgent,
  };
}

/** A client-supplied e-mail for an event payload: strings only, cut to 320 characters. */
export function eventEmail(value: unknown): string | undefined {
  return typeof value === 'string' ? value.slice(0, MAX_EVENT_EMAIL_LENGTH) : undefined;
}

/**
 * `AUTH_OAUTH_CONFLICT` data: the provider plus the two conflict fields,
 * picked explicitly from the app-defined `AuthError.data`.
 */
export function oauthConflictEventData(
  provider: string,
  errData: unknown,
): { provider: string; email?: string; providerAccountId?: string } {
  const conflict = (errData && typeof errData === 'object' ? errData : {}) as {
    email?: unknown;
    providerAccountId?: unknown;
  };
  return {
    provider,
    email: eventEmail(conflict.email),
    providerAccountId: typeof conflict.providerAccountId === 'string' ? conflict.providerAccountId : undefined,
  };
}

/**
 * Publish on the bus without letting a listener fail the caller.  Events are
 * published after the operation has completed, so a throwing listener is
 * reported on stderr instead of turning a completed operation into an error.
 */
export function publishSafely(
  eventBus: AuthEventBus | undefined,
  eventName: string,
  payload: Omit<AuthEventPayload, 'event' | 'timestamp'>,
): void {
  if (!eventBus) return;
  try {
    eventBus.publish(eventName, payload);
  } catch (err) {
    process.stderr.write(
      `[awesome-node-auth] WARN: an event listener for ${eventName} threw: ${err instanceof Error ? err.message : String(err)}\n`,
    );
  }
}

/** Publish a router event with the request context (`ip`, `userAgent`, `correlationId`). */
export function publishRequestEvent(
  eventBus: AuthEventBus | undefined,
  eventName: string,
  req: Request,
  payload: RouterEventPayload = {},
): void {
  if (!eventBus) return;
  publishSafely(eventBus, eventName, {
    ...getRequestEventContext(req),
    ...payload,
  });
}
