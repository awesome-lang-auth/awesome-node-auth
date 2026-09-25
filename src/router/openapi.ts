/**
 * Lightweight OpenAPI 3.0 spec builders for all awesome-node-auth routers.
 *
 * No external dependencies — specs are assembled in-memory from the
 * feature flags passed to each router.
 *
 * Exported builders:
 *   - `buildOpenApiSpec`      — tools router (`/tools/*`)
 *   - `buildAuthOpenApiSpec`  — auth router (`/auth/*`)
 *   - `buildAdminOpenApiSpec` — admin router (`/admin/api/*`)
 */

import type { ToolsRouterOptions } from './tools.router';

/** Minimal OpenAPI 3.0 document structure (subset used by this builder). */
export interface OpenApiDocument {
  openapi: string;
  info: { title: string; version: string; description?: string };
  paths: Record<string, Record<string, unknown>>;
  components?: {
    schemas?: Record<string, unknown>;
    securitySchemes?: Record<string, unknown>;
  };
  security?: Array<Record<string, unknown>>;
  tags?: Array<{ name: string; description?: string }>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

const BEARER_SCHEME = {
  BearerAuth: {
    type: 'http',
    scheme: 'bearer',
    bearerFormat: 'JWT',
  },
};

const bearer = { BearerAuth: [] as string[] };

// ─────────────────────────────────────────────────────────────────────────────
// Auth router spec
// ─────────────────────────────────────────────────────────────────────────────

/** Feature flags that control which optional auth endpoints appear in the spec. */
export interface AuthOpenApiOptions {
  /** Include `POST /register`. @default false */
  hasRegister?: boolean;
  /** Include `POST /sessions/cleanup`. @default false */
  hasSessionsCleanup?: boolean;
  /** Include Google OAuth endpoints. @default false */
  hasGoogleOAuth?: boolean;
  /** Include GitHub OAuth endpoints. @default false */
  hasGithubOAuth?: boolean;
  /** Additional generic OAuth provider names (e.g. `['facebook', 'twitter']`). */
  oauthProviders?: string[];
  /** Include linked-accounts endpoints. @default false */
  hasLinkedAccounts?: boolean;
}

/**
 * Build an OpenAPI 3.0 document for the auth router.
 *
 * @param options  Feature flags controlling optional endpoint visibility.
 * @param basePath Base path where the auth router is mounted (default `'/auth'`).
 */
export function buildAuthOpenApiSpec(
  options: AuthOpenApiOptions = {},
  basePath = '/auth',
): OpenApiDocument {
  const {
    hasRegister = false,
    hasSessionsCleanup = false,
    hasGoogleOAuth = false,
    hasGithubOAuth = false,
    oauthProviders = [],
    hasLinkedAccounts = false,
  } = options;

  const paths: OpenApiDocument['paths'] = {};

  // ── POST /login ────────────────────────────────────────────────────────────
  paths[`${basePath}/login`] = {
    post: {
      summary: 'Authenticate with email and password',
      operationId: 'login',
      tags: ['Authentication'],
      requestBody: {
        required: true,
        content: { 'application/json': { schema: { $ref: '#/components/schemas/LoginRequest' } } },
      },
      parameters: [
        { name: 'X-Auth-Strategy', in: 'header', required: false, schema: { type: 'string', enum: ['bearer'] }, description: 'Pass `bearer` to receive tokens in the response body instead of cookies' },
      ],
      responses: {
        200: { description: 'Login successful', content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthResponse' } } } },
        400: { description: '2FA challenge required', content: { 'application/json': { schema: { $ref: '#/components/schemas/TwoFAChallenge' } } } },
        401: { description: 'Invalid credentials' },
      },
    },
  };

  // ── POST /logout ───────────────────────────────────────────────────────────
  paths[`${basePath}/logout`] = {
    post: {
      summary: 'Log out and revoke the refresh token',
      operationId: 'logout',
      tags: ['Authentication'],
      security: [bearer],
      requestBody: { required: false, content: { 'application/json': { schema: { type: 'object', properties: { refreshToken: { type: 'string', description: 'Bearer clients: the current refresh token, revoked with its session' } } } } } },
      responses: {
        200: { description: 'Logged out', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
        401: { description: 'Unauthorized' },
      },
    },
  };

  // ── POST /refresh ──────────────────────────────────────────────────────────
  paths[`${basePath}/refresh`] = {
    post: {
      summary: 'Refresh access token using a valid refresh token',
      operationId: 'refreshToken',
      tags: ['Authentication'],
      parameters: [
        { name: 'X-Auth-Strategy', in: 'header', required: false, schema: { type: 'string', enum: ['bearer'] } },
      ],
      requestBody: {
        required: false,
        description: 'Required when using bearer strategy; omit when using cookies',
        content: { 'application/json': { schema: { type: 'object', properties: { refreshToken: { type: 'string' } }, required: ['refreshToken'] } } },
      },
      responses: {
        200: { description: 'New token pair issued', content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthResponse' } } } },
        401: { description: 'Invalid or expired refresh token' },
      },
    },
  };

  // ── GET /me ────────────────────────────────────────────────────────────────
  paths[`${basePath}/me`] = {
    get: {
      summary: 'Get the authenticated user profile',
      operationId: 'getMe',
      tags: ['Authentication'],
      security: [bearer],
      responses: {
        200: { description: 'User profile', content: { 'application/json': { schema: { $ref: '#/components/schemas/UserProfile' } } } },
        401: { description: 'Unauthorized' },
      },
    },
  };

  // ── POST /register (optional) ──────────────────────────────────────────────
  if (hasRegister) {
    paths[`${basePath}/register`] = {
      post: {
        summary: 'Register a new user account',
        operationId: 'register',
        tags: ['Authentication'],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/RegisterRequest' } } },
        },
        responses: {
          201: { description: 'Account created', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, userId: { type: 'string' } }, required: ['success', 'userId'] } } } },
          400: { description: 'Validation error' },
        },
      },
    };
  }

  // ── POST /forgot-password ──────────────────────────────────────────────────
  paths[`${basePath}/forgot-password`] = {
    post: {
      summary: 'Request a password-reset email',
      operationId: 'forgotPassword',
      tags: ['Password'],
      requestBody: {
        required: true,
        content: { 'application/json': { schema: { type: 'object', required: ['email'], properties: { email: { type: 'string', format: 'email' }, emailLang: { type: 'string' } } } } },
      },
      responses: {
        200: { description: 'Reset email sent (or silently ignored if email not found)', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
      },
    },
  };

  // ── POST /reset-password ───────────────────────────────────────────────────
  paths[`${basePath}/reset-password`] = {
    post: {
      summary: 'Reset password using a reset token',
      operationId: 'resetPassword',
      tags: ['Password'],
      requestBody: {
        required: true,
        content: { 'application/json': { schema: { type: 'object', required: ['token', 'newPassword'], properties: { token: { type: 'string' }, newPassword: { type: 'string', format: 'password', minLength: 8 } } } } },
      },
      responses: {
        200: { description: 'Password reset', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
        400: { description: 'Invalid or expired token' },
      },
    },
  };

  // ── POST /change-password ──────────────────────────────────────────────────
  paths[`${basePath}/change-password`] = {
    post: {
      summary: 'Change password (authenticated)',
      operationId: 'changePassword',
      tags: ['Password'],
      security: [bearer],
      requestBody: {
        required: true,
        content: { 'application/json': { schema: { type: 'object', required: ['currentPassword', 'newPassword'], properties: { currentPassword: { type: 'string', format: 'password' }, newPassword: { type: 'string', format: 'password', minLength: 8 } } } } },
      },
      responses: {
        200: { description: 'Password changed', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
        401: { description: 'Unauthorized or wrong current password' },
      },
    },
  };

  // ── 2FA ───────────────────────────────────────────────────────────────────
  paths[`${basePath}/2fa/setup`] = {
    post: {
      summary: 'Begin TOTP 2FA setup — returns QR code and secret',
      operationId: 'setup2fa',
      tags: ['Two-Factor Auth'],
      security: [bearer],
      responses: {
        200: { description: 'TOTP setup info', content: { 'application/json': { schema: { type: 'object', properties: { secret: { type: 'string' }, qrCode: { type: 'string', description: 'Data-URL PNG of the QR code' } } } } } },
        401: { description: 'Unauthorized' },
      },
    },
  };

  paths[`${basePath}/2fa/verify-setup`] = {
    post: {
      summary: 'Complete TOTP 2FA setup by verifying the first code',
      operationId: 'verifySetup2fa',
      tags: ['Two-Factor Auth'],
      security: [bearer],
      requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['token', 'secret'], properties: { token: { type: 'string', minLength: 6, maxLength: 6 }, secret: { type: 'string' } } } } } },
      responses: {
        200: { description: '2FA enabled', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
        400: { description: 'Invalid TOTP token' },
        401: { description: 'Unauthorized' },
      },
    },
  };

  paths[`${basePath}/2fa/verify`] = {
    post: {
      summary: 'Verify TOTP code during login',
      operationId: 'verify2fa',
      tags: ['Two-Factor Auth'],
      requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['userId', 'token'], properties: { userId: { type: 'string' }, token: { type: 'string', minLength: 6, maxLength: 6 } } } } } },
      parameters: [{ name: 'X-Auth-Strategy', in: 'header', required: false, schema: { type: 'string', enum: ['bearer'] } }],
      responses: {
        200: { description: 'Login completed', content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthResponse' } } } },
        401: { description: 'Invalid code' },
      },
    },
  };

  paths[`${basePath}/2fa/disable`] = {
    post: {
      summary: 'Disable TOTP 2FA (authenticated)',
      operationId: 'disable2fa',
      tags: ['Two-Factor Auth'],
      security: [bearer],
      requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['token'], properties: { token: { type: 'string', minLength: 6, maxLength: 6 } } } } } },
      responses: {
        200: { description: '2FA disabled', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
        401: { description: 'Unauthorized or invalid TOTP code' },
        403: { description: '2FA is mandatory and cannot be disabled' },
      },
    },
  };

  // ── Email verification ─────────────────────────────────────────────────────
  paths[`${basePath}/send-verification-email`] = {
    post: {
      summary: 'Send (or resend) a verification email',
      operationId: 'sendVerificationEmail',
      tags: ['Email'],
      security: [bearer],
      requestBody: { required: false, content: { 'application/json': { schema: { type: 'object', properties: { emailLang: { type: 'string' } } } } } },
      responses: {
        200: { description: 'Email sent', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
        401: { description: 'Unauthorized' },
      },
    },
  };

  paths[`${basePath}/verify-email`] = {
    get: {
      summary: 'Verify email address using a token from the verification link',
      operationId: 'verifyEmail',
      tags: ['Email'],
      parameters: [{ name: 'token', in: 'query', required: true, schema: { type: 'string' } }],
      responses: {
        200: { description: 'Email verified', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
        400: { description: 'Invalid or expired token' },
      },
    },
  };

  paths[`${basePath}/change-email/request`] = {
    post: {
      summary: 'Request an email address change (sends verification to new address)',
      operationId: 'changeEmailRequest',
      tags: ['Email'],
      security: [bearer],
      requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['newEmail'], properties: { newEmail: { type: 'string', format: 'email' }, emailLang: { type: 'string' } } } } } },
      responses: {
        200: { description: 'Verification email sent to new address', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
        401: { description: 'Unauthorized' },
      },
    },
  };

  paths[`${basePath}/change-email/confirm`] = {
    post: {
      summary: 'Confirm email change using the token from the verification link',
      operationId: 'changeEmailConfirm',
      tags: ['Email'],
      requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['token'], properties: { token: { type: 'string' } } } } } },
      responses: {
        200: { description: 'Email changed', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
        400: { description: 'Invalid or expired token' },
      },
    },
  };

  // ── Magic link ─────────────────────────────────────────────────────────────
  paths[`${basePath}/magic-link/send`] = {
    post: {
      summary: 'Send a magic-link login email',
      operationId: 'magicLinkSend',
      tags: ['Magic Link'],
      requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['email'], properties: { email: { type: 'string', format: 'email' }, emailLang: { type: 'string' } } } } } },
      responses: {
        200: { description: 'Magic link sent', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
      },
    },
  };

  paths[`${basePath}/magic-link/verify`] = {
    post: {
      summary: 'Verify a magic-link token and complete login',
      operationId: 'magicLinkVerify',
      tags: ['Magic Link'],
      requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['token'], properties: { token: { type: 'string' } } } } } },
      parameters: [{ name: 'X-Auth-Strategy', in: 'header', required: false, schema: { type: 'string', enum: ['bearer'] } }],
      responses: {
        200: { description: 'Login successful', content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthResponse' } } } },
        401: { description: 'Invalid or expired magic link' },
      },
    },
  };

  // ── SMS OTP ────────────────────────────────────────────────────────────────
  paths[`${basePath}/sms/send`] = {
    post: {
      summary: 'Send an SMS OTP code',
      operationId: 'smsSend',
      tags: ['SMS'],
      requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['phoneNumber'], properties: { phoneNumber: { type: 'string' } } } } } },
      responses: {
        200: { description: 'SMS sent', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
      },
    },
  };

  paths[`${basePath}/sms/verify`] = {
    post: {
      summary: 'Verify an SMS OTP code and complete login',
      operationId: 'smsVerify',
      tags: ['SMS'],
      requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['phoneNumber', 'code'], properties: { phoneNumber: { type: 'string' }, code: { type: 'string' } } } } } },
      parameters: [{ name: 'X-Auth-Strategy', in: 'header', required: false, schema: { type: 'string', enum: ['bearer'] } }],
      responses: {
        200: { description: 'Login successful', content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthResponse' } } } },
        401: { description: 'Invalid or expired code' },
      },
    },
  };

  // ── OAuth — Google (optional) ──────────────────────────────────────────────
  if (hasGoogleOAuth) {
    paths[`${basePath}/oauth/google`] = {
      get: {
        summary: 'Redirect to Google OAuth consent screen',
        operationId: 'oauthGoogleRedirect',
        tags: ['OAuth'],
        responses: { 302: { description: 'Redirect to Google' } },
      },
    };
    paths[`${basePath}/oauth/google/callback`] = {
      get: {
        summary: 'Handle Google OAuth callback',
        operationId: 'oauthGoogleCallback',
        tags: ['OAuth'],
        parameters: [{ name: 'code', in: 'query', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Login successful', content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthResponse' } } } },
          302: { description: 'Redirect after login (cookie strategy)' },
          401: { description: 'OAuth failed' },
        },
      },
    };
  }

  // ── OAuth — GitHub (optional) ──────────────────────────────────────────────
  if (hasGithubOAuth) {
    paths[`${basePath}/oauth/github`] = {
      get: {
        summary: 'Redirect to GitHub OAuth consent screen',
        operationId: 'oauthGithubRedirect',
        tags: ['OAuth'],
        responses: { 302: { description: 'Redirect to GitHub' } },
      },
    };
    paths[`${basePath}/oauth/github/callback`] = {
      get: {
        summary: 'Handle GitHub OAuth callback',
        operationId: 'oauthGithubCallback',
        tags: ['OAuth'],
        parameters: [{ name: 'code', in: 'query', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Login successful', content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthResponse' } } } },
          302: { description: 'Redirect after login (cookie strategy)' },
          401: { description: 'OAuth failed' },
        },
      },
    };
  }

  // ── OAuth — Generic providers (optional) ───────────────────────────────────
  for (const providerName of oauthProviders) {
    paths[`${basePath}/oauth/${providerName}`] = {
      get: {
        summary: `Redirect to ${providerName} OAuth consent screen`,
        operationId: `oauth${providerName.charAt(0).toUpperCase() + providerName.slice(1)}Redirect`,
        tags: ['OAuth'],
        responses: { 302: { description: `Redirect to ${providerName}` } },
      },
    };
    paths[`${basePath}/oauth/${providerName}/callback`] = {
      get: {
        summary: `Handle ${providerName} OAuth callback`,
        operationId: `oauth${providerName.charAt(0).toUpperCase() + providerName.slice(1)}Callback`,
        tags: ['OAuth'],
        parameters: [{ name: 'code', in: 'query', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Login successful', content: { 'application/json': { schema: { $ref: '#/components/schemas/AuthResponse' } } } },
          302: { description: 'Redirect after login (cookie strategy)' },
          401: { description: 'OAuth failed' },
        },
      },
    };
  }

  // ── Sessions cleanup (optional) ─────────────────────────────────────────────
  if (hasSessionsCleanup) {
    paths[`${basePath}/sessions/cleanup`] = {
      post: {
        summary: 'Delete all expired sessions (cron-callable)',
        operationId: 'sessionsCleanup',
        tags: ['Sessions'],
        responses: {
          200: { description: 'Sessions cleaned', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, deleted: { type: 'integer' } } } } } },
        },
      },
    };
  }

  // ── Linked accounts (optional) ─────────────────────────────────────────────
  if (hasLinkedAccounts) {
    paths[`${basePath}/linked-accounts`] = {
      get: {
        summary: 'List OAuth accounts linked to the authenticated user',
        operationId: 'getLinkedAccounts',
        tags: ['Linked Accounts'],
        security: [bearer],
        responses: {
          200: { description: 'Linked accounts', content: { 'application/json': { schema: { type: 'object', properties: { linkedAccounts: { type: 'array', items: { $ref: '#/components/schemas/LinkedAccount' } } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
    paths[`${basePath}/linked-accounts/{provider}/{providerAccountId}`] = {
      delete: {
        summary: 'Unlink an OAuth provider account',
        operationId: 'unlinkAccount',
        tags: ['Linked Accounts'],
        security: [bearer],
        parameters: [
          { name: 'provider', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'providerAccountId', in: 'path', required: true, schema: { type: 'string' } },
        ],
        responses: {
          200: { description: 'Account unlinked', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
    paths[`${basePath}/link-request`] = {
      post: {
        summary: 'Request to link a new email / provider account',
        operationId: 'linkRequest',
        tags: ['Linked Accounts'],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['email'], properties: { email: { type: 'string', format: 'email' }, provider: { type: 'string' }, emailLang: { type: 'string' } } } } } },
        responses: {
          200: { description: 'Verification email sent', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          400: { description: 'Validation error' },
        },
      },
    };
    paths[`${basePath}/link-verify`] = {
      post: {
        summary: 'Verify a pending account link token',
        operationId: 'linkVerify',
        tags: ['Linked Accounts'],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['token'], properties: { token: { type: 'string' }, loginAfterLinking: { type: 'boolean' } } } } } },
        responses: {
          200: { description: 'Account linked', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          400: { description: 'Invalid or expired token' },
        },
      },
    };
  }

  // ── DELETE /account ────────────────────────────────────────────────────────
  paths[`${basePath}/account`] = {
    delete: {
      summary: 'Delete the authenticated user\'s account permanently',
      operationId: 'deleteAccount',
      tags: ['Authentication'],
      security: [bearer],
      responses: {
        200: { description: 'Account deleted', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
        401: { description: 'Unauthorized' },
      },
    },
  };

  // ── Schemas ────────────────────────────────────────────────────────────────
  const schemas: Record<string, unknown> = {
    LoginRequest: {
      type: 'object',
      required: ['email', 'password'],
      properties: {
        email: { type: 'string', format: 'email', example: 'user@example.com' },
        password: { type: 'string', format: 'password', example: 'secret123' },
      },
    },
    RegisterRequest: {
      type: 'object',
      required: ['email', 'password'],
      properties: {
        email: { type: 'string', format: 'email' },
        password: { type: 'string', format: 'password', minLength: 8 },
      },
      additionalProperties: true,
    },
    AuthResponse: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        accessToken: { type: 'string', description: 'Present only when using bearer strategy' },
        refreshToken: { type: 'string', description: 'Present only when using bearer strategy' },
      },
      required: ['success'],
    },
    TwoFAChallenge: {
      type: 'object',
      properties: {
        twoFactorRequired: { type: 'boolean', example: true },
        userId: { type: 'string' },
      },
    },
    SuccessResponse: {
      type: 'object',
      properties: { success: { type: 'boolean', example: true } },
      required: ['success'],
    },
    UserProfile: {
      type: 'object',
      properties: {
        sub: { type: 'string' },
        email: { type: 'string', format: 'email' },
        role: { type: 'string' },
        loginProvider: { type: 'string' },
        isEmailVerified: { type: 'boolean' },
        isTotpEnabled: { type: 'boolean' },
        roles: { type: 'array', items: { type: 'string' } },
        permissions: { type: 'array', items: { type: 'string' } },
        metadata: { type: 'object', additionalProperties: true },
      },
    },
    LinkedAccount: {
      type: 'object',
      properties: {
        provider: { type: 'string' },
        providerAccountId: { type: 'string' },
      },
    },
  };

  const tags = [
    { name: 'Authentication', description: 'Login, logout, token refresh, and account management' },
    { name: 'Password', description: 'Password reset and change' },
    { name: 'Two-Factor Auth', description: 'TOTP 2FA setup and verification' },
    { name: 'Email', description: 'Email verification and change' },
    { name: 'Magic Link', description: 'Passwordless login via email magic link' },
    { name: 'SMS', description: 'Passwordless login via SMS OTP' },
    ...(hasGoogleOAuth || hasGithubOAuth || oauthProviders.length > 0 ? [{ name: 'OAuth', description: 'Social login via OAuth 2.0 providers' }] : []),
    ...(hasSessionsCleanup ? [{ name: 'Sessions', description: 'Session management' }] : []),
    ...(hasLinkedAccounts ? [{ name: 'Linked Accounts', description: 'Link and unlink OAuth provider accounts' }] : []),
  ];

  return {
    openapi: '3.0.3',
    info: {
      title: 'awesome-node-auth API',
      version: '1.0.0',
      description: 'Authentication and authorization endpoints.',
    },
    tags,
    paths,
    components: {
      securitySchemes: { BearerAuth: BEARER_SCHEME.BearerAuth },
      schemas,
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin router spec
// ─────────────────────────────────────────────────────────────────────────────

/** Feature flags that control which optional admin endpoints appear in the spec. */
export interface AdminOpenApiOptions {
  /** Include session endpoints. @default false */
  hasSessions?: boolean;
  /** Include RBAC roles endpoints. @default false */
  hasRoles?: boolean;
  /** Include tenant endpoints. @default false */
  hasTenants?: boolean;
  /** Include user-metadata endpoints. @default false */
  hasMetadata?: boolean;
  /** Include settings endpoints. @default false */
  hasSettings?: boolean;
  /** Include linked-accounts column in user detail. @default false */
  hasLinkedAccounts?: boolean;
  /** Include API key management endpoints. @default false */
  hasApiKeys?: boolean;
  /** Include webhook management endpoints. @default false */
  hasWebhooks?: boolean;
  /** Include UI customization endpoints. @default false */
  hasUi?: boolean;
}

/**
 * Build an OpenAPI 3.0 document for the admin router.
 *
 * @param options  Feature flags controlling optional endpoint visibility.
 * @param basePath Base path where the admin router is mounted (default `'/admin'`).
 */
export function buildAdminOpenApiSpec(
  options: AdminOpenApiOptions = {},
  basePath = '/admin',
): OpenApiDocument {
  const {
    hasSessions = false,
    hasRoles = false,
    hasTenants = false,
    hasMetadata = false,
    hasSettings = false,
    hasLinkedAccounts = false,
    hasApiKeys = false,
    hasWebhooks = false,
    hasUi = false,
  } = options;

  const paths: OpenApiDocument['paths'] = {};
  const adminAuth = { AdminAuth: [] as string[] };

  // ── GET /api/ping ──────────────────────────────────────────────────────────
  paths[`${basePath}/api/ping`] = {
    get: {
      summary: 'Health check',
      operationId: 'adminPing',
      tags: ['Admin'],
      security: [adminAuth],
      responses: { 200: { description: 'pong', content: { 'application/json': { schema: { type: 'object', properties: { ok: { type: 'boolean' } } } } } } },
    },
  };

  // ── Users ──────────────────────────────────────────────────────────────────
  paths[`${basePath}/api/users`] = {
    get: {
      summary: 'List users (paginated)',
      operationId: 'adminListUsers',
      tags: ['Admin — Users'],
      security: [adminAuth],
      parameters: [
        { name: 'limit', in: 'query', schema: { type: 'integer', default: 20 } },
        { name: 'offset', in: 'query', schema: { type: 'integer', default: 0 } },
        { name: 'filter', in: 'query', schema: { type: 'string' }, description: 'Filter by email or ID (case-insensitive substring)' },
      ],
      responses: {
        200: { description: 'User list', content: { 'application/json': { schema: { type: 'object', properties: { users: { type: 'array', items: { $ref: '#/components/schemas/AdminUser' } }, total: { type: 'integer' } } } } } },
        401: { description: 'Unauthorized' },
      },
    },
  };

  paths[`${basePath}/api/users/{id}`] = {
    get: {
      summary: 'Get a specific user by ID',
      operationId: 'adminGetUser',
      tags: ['Admin — Users'],
      security: [adminAuth],
      parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
      responses: {
        200: { description: 'User detail', content: { 'application/json': { schema: { type: 'object', properties: { user: { $ref: '#/components/schemas/AdminUser' } } } } } },
        401: { description: 'Unauthorized' },
        404: { description: 'User not found' },
      },
    },
    delete: {
      summary: 'Delete a user',
      operationId: 'adminDeleteUser',
      tags: ['Admin — Users'],
      security: [adminAuth],
      parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
      responses: {
        200: { description: 'User deleted', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
        401: { description: 'Unauthorized' },
      },
    },
  };

  // ── 2FA policy ─────────────────────────────────────────────────────────────
  paths[`${basePath}/api/2fa-policy`] = {
    post: {
      summary: 'Enforce or revoke TOTP 2FA for a user',
      operationId: 'admin2faPolicy',
      tags: ['Admin — Users'],
      security: [adminAuth],
      requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['userId', 'require2FA'], properties: { userId: { type: 'string' }, require2FA: { type: 'boolean' } } } } } },
      responses: {
        200: { description: '2FA policy applied', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
        401: { description: 'Unauthorized' },
      },
    },
  };

  // ── User metadata (optional) ───────────────────────────────────────────────
  if (hasMetadata) {
    paths[`${basePath}/api/users/{id}/metadata`] = {
      get: {
        summary: 'Get user metadata',
        operationId: 'adminGetUserMetadata',
        tags: ['Admin — Users'],
        security: [adminAuth],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Metadata key/value pairs', content: { 'application/json': { schema: { type: 'object', properties: { metadata: { type: 'object', additionalProperties: true } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
      put: {
        summary: 'Update user metadata',
        operationId: 'adminUpdateUserMetadata',
        tags: ['Admin — Users'],
        security: [adminAuth],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', additionalProperties: true } } } },
        responses: {
          200: { description: 'Metadata updated', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── User linked accounts (optional) ────────────────────────────────────────
  if (hasLinkedAccounts) {
    paths[`${basePath}/api/users/{id}/linked-accounts`] = {
      get: {
        summary: 'Get linked OAuth accounts for a user',
        operationId: 'adminGetUserLinkedAccounts',
        tags: ['Admin — Users'],
        security: [adminAuth],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Linked accounts', content: { 'application/json': { schema: { type: 'object', properties: { linkedAccounts: { type: 'array', items: { type: 'object' } } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── User roles (optional) ──────────────────────────────────────────────────
  if (hasRoles) {
    paths[`${basePath}/api/users/{id}/roles`] = {
      get: {
        summary: 'Get roles assigned to a user',
        operationId: 'adminGetUserRoles',
        tags: ['Admin — Roles'],
        security: [adminAuth],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'User roles', content: { 'application/json': { schema: { type: 'object', properties: { roles: { type: 'array', items: { type: 'string' } } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
      post: {
        summary: 'Assign a role to a user',
        operationId: 'adminAssignUserRole',
        tags: ['Admin — Roles'],
        security: [adminAuth],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['role'], properties: { role: { type: 'string' } } } } } },
        responses: {
          200: { description: 'Role assigned', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
    paths[`${basePath}/api/users/{id}/roles/{role}`] = {
      delete: {
        summary: 'Remove a role from a user',
        operationId: 'adminRemoveUserRole',
        tags: ['Admin — Roles'],
        security: [adminAuth],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'role', in: 'path', required: true, schema: { type: 'string' } },
        ],
        responses: {
          200: { description: 'Role removed', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── User tenants (optional) ────────────────────────────────────────────────
  if (hasTenants) {
    paths[`${basePath}/api/users/{id}/tenants`] = {
      get: {
        summary: 'Get tenants the user belongs to',
        operationId: 'adminGetUserTenants',
        tags: ['Admin — Tenants'],
        security: [adminAuth],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Tenant list', content: { 'application/json': { schema: { type: 'object', properties: { tenants: { type: 'array', items: { $ref: '#/components/schemas/AdminTenant' } } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── Settings (optional) ────────────────────────────────────────────────────
  if (hasSettings) {
    paths[`${basePath}/api/settings`] = {
      get: {
        summary: 'Get global auth settings',
        operationId: 'adminGetSettings',
        tags: ['Admin — Settings'],
        security: [adminAuth],
        responses: {
          200: { description: 'Settings', content: { 'application/json': { schema: { type: 'object', properties: { settings: { $ref: '#/components/schemas/AdminSettings' } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
      put: {
        summary: 'Update global auth settings',
        operationId: 'adminUpdateSettings',
        tags: ['Admin — Settings'],
        security: [adminAuth],
        requestBody: { required: true, content: { 'application/json': { schema: { $ref: '#/components/schemas/AdminSettings' } } } },
        responses: {
          200: { description: 'Settings updated', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── Sessions (optional) ────────────────────────────────────────────────────
  if (hasSessions) {
    paths[`${basePath}/api/sessions`] = {
      get: {
        summary: 'List active sessions',
        operationId: 'adminListSessions',
        tags: ['Admin — Sessions'],
        security: [adminAuth],
        parameters: [
          { name: 'userId', in: 'query', schema: { type: 'string' } },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 20 } },
          { name: 'offset', in: 'query', schema: { type: 'integer', default: 0 } },
          { name: 'filter', in: 'query', schema: { type: 'string' } },
        ],
        responses: {
          200: { description: 'Session list', content: { 'application/json': { schema: { type: 'object', properties: { sessions: { type: 'array', items: { $ref: '#/components/schemas/AdminSession' } }, total: { type: 'integer' } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
    paths[`${basePath}/api/sessions/{handle}`] = {
      delete: {
        summary: 'Revoke a session by handle',
        operationId: 'adminRevokeSession',
        tags: ['Admin — Sessions'],
        security: [adminAuth],
        parameters: [{ name: 'handle', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Session revoked', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── Roles (optional) ───────────────────────────────────────────────────────
  if (hasRoles) {
    paths[`${basePath}/api/roles`] = {
      get: {
        summary: 'List all roles',
        operationId: 'adminListRoles',
        tags: ['Admin — Roles'],
        security: [adminAuth],
        responses: {
          200: { description: 'Role list', content: { 'application/json': { schema: { type: 'object', properties: { roles: { type: 'array', items: { type: 'object' } } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
      post: {
        summary: 'Create a role',
        operationId: 'adminCreateRole',
        tags: ['Admin — Roles'],
        security: [adminAuth],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['name'], properties: { name: { type: 'string' }, permissions: { type: 'array', items: { type: 'string' } } } } } } },
        responses: {
          200: { description: 'Role created', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
    paths[`${basePath}/api/roles/{name}`] = {
      delete: {
        summary: 'Delete a role',
        operationId: 'adminDeleteRole',
        tags: ['Admin — Roles'],
        security: [adminAuth],
        parameters: [{ name: 'name', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Role deleted', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── Tenants (optional) ─────────────────────────────────────────────────────
  if (hasTenants) {
    paths[`${basePath}/api/tenants`] = {
      get: {
        summary: 'List all tenants',
        operationId: 'adminListTenants',
        tags: ['Admin — Tenants'],
        security: [adminAuth],
        responses: {
          200: { description: 'Tenant list', content: { 'application/json': { schema: { type: 'object', properties: { tenants: { type: 'array', items: { $ref: '#/components/schemas/AdminTenant' } } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
      post: {
        summary: 'Create a tenant',
        operationId: 'adminCreateTenant',
        tags: ['Admin — Tenants'],
        security: [adminAuth],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['name'], properties: { name: { type: 'string' }, isActive: { type: 'boolean' } } } } } },
        responses: {
          200: { description: 'Tenant created', content: { 'application/json': { schema: { type: 'object', properties: { tenant: { $ref: '#/components/schemas/AdminTenant' } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
    paths[`${basePath}/api/tenants/{id}`] = {
      delete: {
        summary: 'Delete a tenant',
        operationId: 'adminDeleteTenant',
        tags: ['Admin — Tenants'],
        security: [adminAuth],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Tenant deleted', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
    paths[`${basePath}/api/tenants/{id}/users`] = {
      get: {
        summary: 'List users in a tenant',
        operationId: 'adminGetTenantUsers',
        tags: ['Admin — Tenants'],
        security: [adminAuth],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'User IDs', content: { 'application/json': { schema: { type: 'object', properties: { userIds: { type: 'array', items: { type: 'string' } } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
      post: {
        summary: 'Add a user to a tenant',
        operationId: 'adminAddTenantUser',
        tags: ['Admin — Tenants'],
        security: [adminAuth],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['userId'], properties: { userId: { type: 'string' } } } } } },
        responses: {
          200: { description: 'User added', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
    paths[`${basePath}/api/tenants/{id}/users/{userId}`] = {
      delete: {
        summary: 'Remove a user from a tenant',
        operationId: 'adminRemoveTenantUser',
        tags: ['Admin — Tenants'],
        security: [adminAuth],
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
          { name: 'userId', in: 'path', required: true, schema: { type: 'string' } },
        ],
        responses: {
          200: { description: 'User removed', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── API Keys (optional) ────────────────────────────────────────────────────
  if (hasApiKeys) {
    paths[`${basePath}/api/api-keys`] = {
      get: {
        summary: 'List API keys (paginated)',
        operationId: 'adminListApiKeys',
        tags: ['Admin — API Keys'],
        security: [adminAuth],
        parameters: [
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 20 } },
          { name: 'offset', in: 'query', schema: { type: 'integer', default: 0 } },
          { name: 'filter', in: 'query', schema: { type: 'string' }, description: 'Filter by name, service ID, or prefix' },
        ],
        responses: {
          200: { description: 'API key list', content: { 'application/json': { schema: { type: 'object', properties: { keys: { type: 'array', items: { $ref: '#/components/schemas/AdminApiKey' } }, total: { type: 'integer' } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
      post: {
        summary: 'Create a new API key (returns rawKey once)',
        operationId: 'adminCreateApiKey',
        tags: ['Admin — API Keys'],
        security: [adminAuth],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', required: ['name'], properties: { name: { type: 'string' }, serviceId: { type: 'string' }, scopes: { type: 'array', items: { type: 'string' } }, allowedIps: { type: 'array', items: { type: 'string' } }, expiresAt: { type: 'string', format: 'date-time' } } } } },
        },
        responses: {
          200: { description: 'API key created. rawKey is shown once only.', content: { 'application/json': { schema: { type: 'object', properties: { rawKey: { type: 'string' }, record: { $ref: '#/components/schemas/AdminApiKey' } } } } } },
          400: { description: 'Validation error' },
          401: { description: 'Unauthorized' },
        },
      },
    };
    paths[`${basePath}/api/api-keys/{id}/revoke`] = {
      delete: {
        summary: 'Revoke an API key (sets isActive: false)',
        operationId: 'adminRevokeApiKey',
        tags: ['Admin — API Keys'],
        security: [adminAuth],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'API key revoked', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
    paths[`${basePath}/api/api-keys/{id}`] = {
      delete: {
        summary: 'Hard-delete an API key record',
        operationId: 'adminDeleteApiKey',
        tags: ['Admin — API Keys'],
        security: [adminAuth],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'API key deleted', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── Webhooks admin (optional) ──────────────────────────────────────────────
  if (hasWebhooks) {
    paths[`${basePath}/api/webhooks`] = {
      get: {
        summary: 'List registered webhooks (paginated)',
        operationId: 'adminListWebhooks',
        tags: ['Admin — Webhooks'],
        security: [adminAuth],
        parameters: [
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 20 } },
          { name: 'offset', in: 'query', schema: { type: 'integer', default: 0 } },
        ],
        responses: {
          200: { description: 'Webhook list', content: { 'application/json': { schema: { type: 'object', properties: { webhooks: { type: 'array', items: { $ref: '#/components/schemas/AdminWebhook' } }, total: { type: 'integer' } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
      post: {
        summary: 'Register a new outgoing webhook',
        operationId: 'adminCreateWebhook',
        tags: ['Admin — Webhooks'],
        security: [adminAuth],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', required: ['url'], properties: { url: { type: 'string', format: 'uri' }, events: { type: 'array', items: { type: 'string' } }, secret: { type: 'string' }, tenantId: { type: 'string' }, isActive: { type: 'boolean', default: true }, maxRetries: { type: 'integer', default: 3 } } } } },
        },
        responses: {
          200: { description: 'Webhook created', content: { 'application/json': { schema: { type: 'object', properties: { webhook: { $ref: '#/components/schemas/AdminWebhook' } } } } } },
          400: { description: 'Validation error' },
          401: { description: 'Unauthorized' },
        },
      },
    };
    paths[`${basePath}/api/webhooks/{id}`] = {
      patch: {
        summary: 'Partially update a webhook (e.g. toggle isActive)',
        operationId: 'adminUpdateWebhook',
        tags: ['Admin — Webhooks'],
        security: [adminAuth],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', properties: { isActive: { type: 'boolean' }, url: { type: 'string' }, events: { type: 'array', items: { type: 'string' } } } } } } },
        responses: {
          200: { description: 'Webhook updated', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
      delete: {
        summary: 'Delete a webhook registration',
        operationId: 'adminDeleteWebhook',
        tags: ['Admin — Webhooks'],
        security: [adminAuth],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Webhook deleted', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── UI Customization admin (optional) ──────────────────────────────────────
  if (hasUi) {
    paths[`${basePath}/api/ui-settings`] = {
      get: {
        summary: 'Get UI customization settings',
        operationId: 'adminGetUiSettings',
        tags: ['Admin — UI'],
        security: [adminAuth],
        responses: {
          200: { description: 'UI settings', content: { 'application/json': { schema: { $ref: '#/components/schemas/UiSettings' } } } },
          401: { description: 'Unauthorized' },
        },
      },
      post: {
        summary: 'Update UI customization settings',
        operationId: 'adminUpdateUiSettings',
        tags: ['Admin — UI'],
        security: [adminAuth],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/UiSettings' } } },
        },
        responses: {
          200: { description: 'Settings updated', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
    paths[`${basePath}/api/ui/logo`] = {
      post: {
        summary: 'Upload a custom logo image',
        operationId: 'adminUploadLogo',
        tags: ['Admin — UI'],
        security: [adminAuth],
        requestBody: {
          content: {
            'multipart/form-data': {
              schema: { type: 'object', properties: { logo: { type: 'string', format: 'binary' } } },
            },
          },
        },
        responses: {
          200: { description: 'Logo uploaded', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, logoUrl: { type: 'string' } } } } } },
          401: { description: 'Unauthorized' },
        },
      },
      delete: {
        summary: 'Remove custom logo',
        operationId: 'adminDeleteLogo',
        tags: ['Admin — UI'],
        security: [adminAuth],
        responses: {
          200: { description: 'Logo removed', content: { 'application/json': { schema: { $ref: '#/components/schemas/SuccessResponse' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── Schemas ────────────────────────────────────────────────────────────────
  const schemas: Record<string, unknown> = {
    SuccessResponse: {
      type: 'object',
      properties: { success: { type: 'boolean', example: true } },
      required: ['success'],
    },
    AdminUser: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        email: { type: 'string', format: 'email' },
        role: { type: 'string' },
        isEmailVerified: { type: 'boolean' },
        isTotpEnabled: { type: 'boolean' },
        loginProvider: { type: 'string' },
        lastLogin: { type: 'string', format: 'date-time' },
        createdAt: { type: 'string', format: 'date-time' },
      },
    },
    AdminSession: {
      type: 'object',
      properties: {
        handle: { type: 'string' },
        userId: { type: 'string' },
        deviceInfo: { type: 'string' },
        ip: { type: 'string' },
        createdAt: { type: 'string', format: 'date-time' },
        expiresAt: { type: 'string', format: 'date-time' },
      },
    },
    AdminTenant: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        name: { type: 'string' },
        isActive: { type: 'boolean' },
      },
    },
    AdminSettings: {
      type: 'object',
      properties: {
        require2FA: { type: 'boolean' },
        emailVerificationMode: { type: 'string', enum: ['none', 'lazy', 'strict'] },
        emailVerificationGracePeriodDays: { type: 'integer' },
      },
    },
    AdminApiKey: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        name: { type: 'string' },
        keyPrefix: { type: 'string', description: 'First ~11 chars of the key (safe to display)' },
        serviceId: { type: 'string', nullable: true },
        scopes: { type: 'array', items: { type: 'string' } },
        allowedIps: { type: 'array', items: { type: 'string' }, nullable: true },
        isActive: { type: 'boolean' },
        expiresAt: { type: 'string', format: 'date-time', nullable: true },
        createdAt: { type: 'string', format: 'date-time' },
        lastUsedAt: { type: 'string', format: 'date-time', nullable: true },
      },
    },
    AdminWebhook: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        url: { type: 'string', format: 'uri' },
        events: { type: 'array', items: { type: 'string' } },
        isActive: { type: 'boolean' },
        tenantId: { type: 'string', nullable: true },
        maxRetries: { type: 'integer' },
        retryDelayMs: { type: 'integer' },
        secret: { type: 'string', description: 'Masked as *** if set', nullable: true },
      },
    },
    UiSettings: {
      type: 'object',
      properties: {
        primaryColor: { type: 'string', example: '#1a1a2e' },
        secondaryColor: { type: 'string', example: '#ffffff' },
        logoUrl: { type: 'string', example: '/auth/ui/assets/logo/logo.png', nullable: true },
        siteName: { type: 'string', example: 'My Auth Service' },
      },
    },
  };

  const tags = [
    { name: 'Admin', description: 'Admin health check' },
    { name: 'Admin — Users', description: 'User management' },
    ...(hasSessions ? [{ name: 'Admin — Sessions', description: 'Session management' }] : []),
    ...(hasRoles ? [{ name: 'Admin — Roles', description: 'Role and permission management' }] : []),
    ...(hasTenants ? [{ name: 'Admin — Tenants', description: 'Tenant management' }] : []),
    ...(hasSettings ? [{ name: 'Admin — Settings', description: 'Global auth settings' }] : []),
    ...(hasApiKeys ? [{ name: 'Admin — API Keys', description: 'API key / service token management' }] : []),
    ...(hasWebhooks ? [{ name: 'Admin — Webhooks', description: 'Outgoing webhook management' }] : []),
    ...(hasUi ? [{ name: 'Admin — UI', description: 'UI customization and preview' }] : []),
  ];

  return {
    openapi: '3.0.3',
    info: {
      title: 'awesome-node-auth Admin API',
      version: '1.0.0',
      description: 'Admin REST API for user, session, role, tenant, settings, API key, and webhook management.',
    },
    tags,
    paths,
    components: {
      securitySchemes: {
        AdminAuth: {
          type: 'http',
          scheme: 'bearer',
          description: 'Admin secret token — pass as `Authorization: Bearer <adminSecret>`',
        },
      },
      schemas,
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Tools router spec (unchanged public API)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build an OpenAPI 3.0 JSON document describing the enabled `/tools` routes.
 *
 * Routes that are disabled via `options` are omitted from the spec.
 *
 * @param options   The same `ToolsRouterOptions` passed to `createToolsRouter`.
 * @param basePath  Base path where the tools router is mounted (default `'/tools'`).
 */
export function buildOpenApiSpec(
  options: Pick<ToolsRouterOptions, 'telemetry' | 'notify' | 'stream' | 'webhook' | 'telemetryStore'> = {},
  basePath = '/tools',
): OpenApiDocument {
  const {
    telemetry = true,
    notify = true,
    stream = true,
    webhook = true,
  } = options;

  const hasTelemetryQuery = telemetry && !!options.telemetryStore?.query;

  const paths: OpenApiDocument['paths'] = {};

  const bearer = { BearerAuth: [] };

  // ── POST /track/:eventName ────────────────────────────────────────────────
  if (telemetry) {
    paths[`${basePath}/track/{eventName}`] = {
      post: {
        summary: 'Track a telemetry event',
        operationId: 'trackEvent',
        tags: ['Telemetry'],
        security: [bearer],
        parameters: [
          {
            name: 'eventName',
            in: 'path',
            required: true,
            description: 'Event name in domain.resource.action format (e.g. identity.auth.login.success)',
            schema: { type: 'string', example: 'identity.auth.login.success' },
          },
        ],
        requestBody: {
          required: false,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/TrackPayload' },
            },
          },
        },
        responses: {
          202: {
            description: 'Event accepted',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/OkResponse' } } },
          },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── GET /telemetry ────────────────────────────────────────────────────────
  if (hasTelemetryQuery) {
    paths[`${basePath}/telemetry`] = {
      get: {
        summary: 'Query persisted telemetry events',
        operationId: 'queryTelemetry',
        tags: ['Telemetry'],
        security: [bearer],
        parameters: [
          { name: 'event', in: 'query', schema: { type: 'string' }, description: 'Filter by event name' },
          { name: 'userId', in: 'query', schema: { type: 'string' } },
          { name: 'tenantId', in: 'query', schema: { type: 'string' } },
          { name: 'from', in: 'query', schema: { type: 'string', format: 'date-time' } },
          { name: 'to', in: 'query', schema: { type: 'string', format: 'date-time' } },
          { name: 'limit', in: 'query', schema: { type: 'integer', minimum: 1 } },
          { name: 'offset', in: 'query', schema: { type: 'integer', minimum: 0 } },
        ],
        responses: {
          200: {
            description: 'List of telemetry events',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    data: { type: 'array', items: { $ref: '#/components/schemas/TelemetryEvent' } },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── POST /notify/:target ──────────────────────────────────────────────────
  if (notify) {
    paths[`${basePath}/notify/{target}`] = {
      post: {
        summary: 'Send a real-time SSE notification to a topic',
        operationId: 'notifyTarget',
        tags: ['Notifications'],
        security: [bearer],
        parameters: [
          {
            name: 'target',
            in: 'path',
            required: true,
            description: 'Topic (e.g. user:123, tenant:acme, global)',
            schema: { type: 'string', example: 'user:123' },
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/NotifyPayload' },
            },
          },
        },
        responses: {
          202: {
            description: 'Notification dispatched',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/OkResponse' } } },
          },
          401: { description: 'Unauthorized' },
        },
      },
    };
  }

  // ── GET /stream ───────────────────────────────────────────────────────────
  if (stream) {
    paths[`${basePath}/stream`] = {
      get: {
        summary: 'Subscribe to real-time events via Server-Sent Events',
        operationId: 'sseStream',
        tags: ['Notifications'],
        security: [bearer],
        parameters: [
          {
            name: 'topics',
            in: 'query',
            required: false,
            description: 'Comma-separated list of topics to subscribe to. The server enforces authorization.',
            schema: { type: 'string', example: 'global,user:123' },
          },
        ],
        responses: {
          200: {
            description: 'SSE stream (text/event-stream)',
            content: {
              'text/event-stream': {
                schema: { type: 'string', description: 'Newline-delimited SSE frames' },
              },
            },
          },
          401: { description: 'Unauthorized' },
          503: { description: 'SSE not enabled on this server' },
        },
      },
    };
  }

  // ── POST /webhook/:provider ───────────────────────────────────────────────
  if (webhook) {
    paths[`${basePath}/webhook/{provider}`] = {
      post: {
        summary: 'Receive an inbound webhook from an external provider',
        operationId: 'inboundWebhook',
        tags: ['Webhooks'],
        parameters: [
          {
            name: 'provider',
            in: 'path',
            required: true,
            description: 'Provider identifier (e.g. stripe, github)',
            schema: { type: 'string', example: 'stripe' },
          },
          {
            name: 'X-Hub-Signature-256',
            in: 'header',
            required: false,
            description: 'HMAC-SHA256 signature for payload verification (optional)',
            schema: { type: 'string' },
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': { schema: { type: 'object', description: 'Provider-specific payload' } },
          },
        },
        responses: {
          200: {
            description: 'Webhook accepted',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/OkResponse' } } },
          },
          400: { description: 'Webhook processing failed' },
        },
      },
    };
  }

  // ── Component schemas ─────────────────────────────────────────────────────
  const components: OpenApiDocument['components'] = {
    securitySchemes: {
      BearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
    schemas: {
      OkResponse: {
        type: 'object',
        properties: { ok: { type: 'boolean', example: true } },
        required: ['ok'],
      },
      TrackPayload: {
        type: 'object',
        description: 'Telemetry event payload',
        properties: {
          data: { description: 'Arbitrary event data' },
          userId: { type: 'string' },
          tenantId: { type: 'string' },
          sessionId: { type: 'string' },
          correlationId: { type: 'string' },
        },
      },
      NotifyPayload: {
        type: 'object',
        description: 'SSE notification payload',
        required: ['data'],
        properties: {
          data: { description: 'Payload to deliver' },
          type: { type: 'string', description: 'Event type label', example: 'notification' },
          tenantId: { type: 'string' },
          userId: { type: 'string' },
          metadata: { type: 'object', additionalProperties: true },
        },
      },
      TelemetryEvent: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          event: { type: 'string' },
          timestamp: { type: 'string', format: 'date-time' },
          data: {},
          userId: { type: 'string' },
          tenantId: { type: 'string' },
          sessionId: { type: 'string' },
          correlationId: { type: 'string' },
          ip: { type: 'string' },
          userAgent: { type: 'string' },
        },
      },
    },
  };

  const tags = [
    telemetry ? { name: 'Telemetry', description: 'Event tracking and query' } : null,
    (notify || stream) ? { name: 'Notifications', description: 'Real-time SSE notifications' } : null,
    webhook ? { name: 'Webhooks', description: 'Inbound webhook processing' } : null,
  ].filter(Boolean) as Array<{ name: string; description?: string }>;

  return {
    openapi: '3.0.3',
    info: {
      title: 'awesome-node-auth Tools API',
      version: '1.0.0',
      description: 'Optional event-driven tools: telemetry, SSE notifications, and webhooks.',
    },
    tags,
    paths,
    components,
  };
}

/**
 * Generate a self-contained Swagger UI HTML page that loads the spec from
 * the provided `specUrl` using the official CDN bundles.
 *
 * @param specUrl   URL of the OpenAPI JSON endpoint (default: `'./openapi.json'`).
 */
export function buildSwaggerUiHtml(specUrl = './openapi.json'): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>awesome-node-auth Tools API — Swagger UI</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: ${JSON.stringify(specUrl)},
      dom_id: '#swagger-ui',
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: 'BaseLayout',
      deepLinking: true,
    });
  </script>
</body>
</html>`;
}
