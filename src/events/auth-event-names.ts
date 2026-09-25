/**
 * Standard identity event names following the `domain.resource.action` naming
 * convention for enterprise-grade event-driven applications.
 */
export const AuthEventNames = {
  // ---- User ----------------------------------------------------------------
  USER_CREATED: 'identity.user.created',
  USER_DELETED: 'identity.user.deleted',
  USER_EMAIL_CHANGED: 'identity.user.email.changed',
  USER_EMAIL_VERIFIED: 'identity.user.email.verified',
  USER_PASSWORD_CHANGED: 'identity.user.password.changed',
  USER_2FA_ENABLED: 'identity.user.2fa.enabled',
  USER_2FA_DISABLED: 'identity.user.2fa.disabled',
  USER_LINKED: 'identity.user.linked',
  USER_UNLINKED: 'identity.user.unlinked',

  // ---- Session -------------------------------------------------------------
  SESSION_CREATED: 'identity.session.created',
  SESSION_REVOKED: 'identity.session.revoked',
  SESSION_EXPIRED: 'identity.session.expired',
  SESSION_ROTATED: 'identity.session.rotated',

  // ---- Authentication ------------------------------------------------------
  AUTH_LOGIN_SUCCESS: 'identity.auth.login.success',
  AUTH_LOGIN_FAILED: 'identity.auth.login.failed',
  AUTH_LOGOUT: 'identity.auth.logout',
  AUTH_OAUTH_SUCCESS: 'identity.auth.oauth.success',
  AUTH_OAUTH_CONFLICT: 'identity.auth.oauth.conflict',

  // ---- Tenant --------------------------------------------------------------
  TENANT_CREATED: 'identity.tenant.created',
  TENANT_DELETED: 'identity.tenant.deleted',
  TENANT_USER_ADDED: 'identity.tenant.user.added',
  TENANT_USER_REMOVED: 'identity.tenant.user.removed',

  // ---- Authorization -------------------------------------------------------
  ROLE_ASSIGNED: 'identity.role.assigned',
  ROLE_REVOKED: 'identity.role.revoked',
  PERMISSION_GRANTED: 'identity.permission.granted',
  PERMISSION_REVOKED: 'identity.permission.revoked',
} as const;

export type AuthEventName = (typeof AuthEventNames)[keyof typeof AuthEventNames];
