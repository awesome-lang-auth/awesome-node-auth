import { BaseUser } from './user.model';
import { ITemplateStore } from '../interfaces/template-store.interface';

/**
 * Configuration for the built-in HTTP-based mailer transport.
 *
 * The mailer makes a POST request to `endpoint` with a JSON body:
 * ```
 * POST {endpoint}
 * X-API-Key: {apiKey}
 * Content-Type: application/json
 *
 * { "to": "...", "subject": "...", "html": "...", "text": "...", "from": "...", "fromName": "...", "provider": "..." }
 * ```
 *
 * If you prefer to control email sending yourself, omit `mailer` and use
 * the `sendMagicLink`, `sendPasswordReset`, and `sendWelcome` callbacks instead.
 */
export interface MailerConfig {
  /** Full URL of the HTTP mailer endpoint (receives a POST with JSON body). */
  endpoint: string;
  /** API key sent as the `X-API-Key` header. */
  apiKey: string;
  /** Sender email address. */
  from: string;
  /** Sender display name (optional). */
  fromName?: string;
  /** Sender Provider (optional). */
  provider?: string;
  /**
   * Default language for built-in email templates.
   * Supported: `'en'` (default) | `'it'`.
   * Can be overridden per-request via `emailLang` in the request body.
   */
  defaultLang?: 'en' | 'it';
}

/**
 * Identity Provider (IdP) mode configuration block.
 *
 * When `enabled`, this instance acts as a central Identity Provider:
 * - Generates/loads an RSA-2048 keypair and signs JWTs with RS256
 * - Exposes a public JWKS endpoint so downstream Resource Servers can
 *   verify tokens without sharing a secret
 *
 * All existing HS256 behaviour is preserved and the two modes can coexist.
 */
export interface IdProviderConfig {
  /**
   * Enable IdP mode. When true (or when `privateKey` is set), `TokenService.generateIdProviderTokenPair()`
   * signs with RS256 and a JWKS endpoint is auto-registered.
   * Presence of `privateKey` is sufficient — `enabled: true` is not required.
   * @default false
   */
  enabled?: boolean;

  /**
   * PEM-encoded RSA private key. If omitted a keypair is auto-generated
   * at startup and stored in memory (ephemeral — for dev only).
   * In production inject via environment variable.
   */
  privateKey?: string;

  /**
   * PEM-encoded RSA public key. Auto-derived from `privateKey` if omitted.
   */
  publicKey?: string;

  /**
   * Path at which the JWKS endpoint is exposed.
   * @default '/.well-known/jwks.json'
   */
  jwksPath?: string;

  /**
   * `iss` (issuer) claim embedded in every IdP-issued JWT.
   * Resource Servers validate this claim.
   * When omitted, no `iss` claim is embedded in the JWT.
   * Example: `'https://auth.myplatform.com'`
   */
  issuer?: string;

  /**
   * Default token expiry for IdP-issued tokens.
   * Overrides `accessTokenExpiresIn` when IdP mode is enabled.
   * @default '30d'
   */
  tokenExpiry?: string;

  /**
   * Refresh token expiry for IdP-issued tokens.
   * In IdP mode the refresh token is also signed with RS256 using the same private key.
   * Falls back to `AuthConfig.refreshTokenExpiresIn` when omitted.
   * @default '90d'
   */
  refreshTokenExpiry?: string;

  /**
   * CORS origins allowed to fetch the JWKS endpoint.
   * @default '*'
   */
  jwksCorsOrigins?: string | string[];
}

/**
 * Resource Server mode configuration block.
 *
 * When `enabled`, this instance validates incoming Bearer tokens against a
 * remote JWKS endpoint (issued by a central IdP) instead of a local secret.
 * Login/register routes are not registered.
 */
export interface ResourceServerConfig {
  /**
   * Enable Resource Server mode. When true, the auth middleware switches to
   * JWKS-based verification for Bearer tokens.
   * @default false
   */
  enabled: boolean;

  /**
   * Full URL of the IdP's JWKS endpoint.
   * Example: `'https://auth.myplatform.com/.well-known/jwks.json'`
   */
  jwksUrl: string;

  /**
   * Expected `iss` claim. Tokens with a different issuer are rejected.
   * When omitted, the `iss` claim on incoming tokens is not validated.
   */
  issuer?: string;

  /**
   * JWKS public key cache TTL in milliseconds.
   * The key is re-fetched once per TTL to support key rotation.
   * @default 3_600_000 (1 hour)
   */
  jwksCacheTtl?: number;

  /**
   * Timeout in ms for the JWKS fetch request.
   * @default 5000
   */
  jwksFetchTimeout?: number;
}

export interface AuthConfig {
  accessTokenSecret: string;
  refreshTokenSecret: string;
  accessTokenExpiresIn?: string;
  refreshTokenExpiresIn?: string;
  /**
   * The global base path where the auth router is mounted in your Express app
   * (e.g. `'/api/auth'` or `'/auth'`).
   *
   * This acts as the single source of truth for email links, cookie paths, and
   * redirects. It can be overridden per-router instance by passing a local
   * `apiPrefix` via the `RouterOptions`.
   */
  apiPrefix?: string;
  cookieOptions?: {
    secure?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
    domain?: string;
    path?: string;
    /**
     * Path for the refresh-token cookie.
     * Defaults to `'/'` so the cookie is sent on every request and the
     * router can be mounted at any prefix.
     * For extra security you can restrict it to your refresh endpoint path
     * (e.g. `'/auth/refresh'`).
     */
    refreshTokenPath?: string;
  };
  /**
   * Anti-CSRF protection using the double-submit cookie pattern.
   *
   * When enabled the library sets a non-HttpOnly `csrf-token` cookie alongside
   * the JWT cookies.  Client-side JavaScript must read this cookie and include
   * its value in the `X-CSRF-Token` header on every authenticated request.
   * The `createAuthMiddleware` middleware will then verify the header matches
   * the cookie.
   *
   * Recommended when `cookieOptions.sameSite` is `'none'` or when you need
   * defence-in-depth beyond `sameSite: 'lax'`.
   */
  csrf?: {
    /** @default false */
    enabled?: boolean;
  };
  bcryptSaltRounds?: number;
  sms?: {
    endpoint: string;
    apiKey: string;
    username: string;
    password: string;
    codeExpiresInMinutes?: number;
  };
  email?: {
    /**
     * Base URL of your site, used to build reset / magic-link URLs and as the
     * post-OAuth login redirect destination.
     *
     * - **Single string** (`'https://yourapp.com'`): used as-is for all email
     *   links and OAuth redirects.
     * - **Array of strings** (`['https://app.example.com', 'https://admin.example.com']`):
     *   the router dynamically picks the entry that matches the `Origin` (or
     *   `Referer`) header of the incoming request.  For email links the first
     *   entry in the array is used as the default.  Any picked URL is also
     *   validated against this allowlist before being used in a redirect, so
     *   only pre-approved origins can receive tokens.
     *
     * When used with OAuth, the resolved URL is encoded into the OAuth `state`
     * parameter during the initiation request, so the callback can redirect the
     * browser back to the exact origin that started the flow.
     *
     * Example: `'https://yourapp.com'`
     */
    siteUrl?: string | string[];

    /**
     * Concrete HTTP mailer transport configuration.
     * When set, the library sends emails automatically using the built-in
     * templates (password reset, magic link, welcome) via HTTP POST.
     * Callback overrides below always take precedence over the mailer transport.
     */
    mailer?: MailerConfig;

    /**
     * Override: custom magic-link email sender.
     * When provided, this callback is used instead of `mailer`.
     */
    sendMagicLink?: (to: string, token: string, link: string, lang?: string) => Promise<void>;

    /**
     * Override: custom password-reset email sender.
     * When provided, this callback is used instead of `mailer`.
     */
    sendPasswordReset?: (to: string, token: string, link: string, lang?: string) => Promise<void>;

    /**
     * Override: custom welcome email sender.
     * When provided, this callback is used instead of `mailer`.
     */
    sendWelcome?: (to: string, data: Record<string, unknown>, lang?: string) => Promise<void>;

    /**
     * Override: custom email-verification sender.
     * When provided, this callback is used instead of `mailer`.
     */
    sendVerificationEmail?: (to: string, token: string, link: string, lang?: string) => Promise<void>;

    /**
     * Override: custom email-changed notification sender.
     * Called after the change-email flow completes.
     * When provided, this callback is used instead of `mailer`.
     */
    sendEmailChanged?: (to: string, newEmail: string, lang?: string) => Promise<void>;
  };
  oauth?: {
    google?: {
      clientId: string;
      clientSecret: string;
      callbackUrl: string;
      projectId?: string;
    };
    github?: {
      clientId: string;
      clientSecret: string;
      callbackUrl: string;
    };
  };
  twoFactor?: {
    appName?: string;
  };
  /**
   * Controls how strictly the server enforces email verification on login.
   *
   * - `'none'`   — email verification is never required (default).
   * - `'lazy'`   — the user may log in while their email is unverified, but
   *                only until `BaseUser.emailVerificationDeadline` is reached.
   *                After the deadline the login is blocked until the email is
   *                confirmed.  Set the deadline field when creating the user
   *                (e.g. `createdAt + lazyGracePeriodDays`).
   * - `'strict'` — the login is blocked immediately if the email is not
   *                verified (`isEmailVerified !== true`).
   *
   * When not set, falls back to the legacy `requireEmailVerification` boolean:
   * `true` → `'strict'`, `false` / `undefined` → `'none'`.
   */
  emailVerificationMode?: 'none' | 'lazy' | 'strict';

  /**
   * @deprecated Use `emailVerificationMode: 'strict'` instead.
   *
   * When `true`, equivalent to `emailVerificationMode: 'strict'`.
   * Ignored when `emailVerificationMode` is explicitly set.
   */
  requireEmailVerification?: boolean;

  /**
   * Optional callback to inject custom claims into both the access and refresh JWTs.
   *
   * Called with the authenticated/resolved `user` object every time a token pair is
   * generated.  The object returned by this callback is **merged** on top of the
   * standard `{ sub, email, role }` claims, so you can add roles, permissions, tenant
   * IDs, or any other project-specific data.
   *
   * Do not return a `purpose` claim: it marks tokens that are not sessions
   * (`purpose: '2fa'` on the 2FA step-up token, `purpose: 'admin'` on the
   * admin console token), so the library drops it from session tokens.
   *
   * @example
   * ```ts
   * buildTokenPayload: (user) => ({
   *   permissions: user.permissions,
   *   tenantId: user.tenantId,
   * }),
   * ```
   */
  buildTokenPayload?: (user: BaseUser) => Record<string, unknown>;

  /**
   * Optional built-in static UI configuration.
   */
  ui?: {
    /** Whether to enable and serve the static UI. Default is false. */
    enabled?: boolean;
    /**
     * Headless UI mode.
     *
     * When `true`, the UI router:
     *   - Still serves `auth.js` and other static assets (CSS, JS) at `/ui/assets/*`
     *     so they can be loaded from a remote SPA via a `<script>` tag.
     *   - Still exposes the `/ui/config` endpoint.
     *   - Returns **404** for all HTML page routes (`/login`, `/register`, …) because
     *     the hosting SPA provides its own login pages.
     *
     * `auth.js` automatically detects this flag from the `/ui/config` response and
     * disables any `window.location.href` redirects on session expiry or refresh
     * failure — preventing the library from navigating away from the external SPA.
     *
     * Typical use case: a Docusaurus documentation site or any React/Vue/Angular SPA
     * that shares the same auth backend but handles its own login flow.
     *
     * @default false
     */
    headless?: boolean;
    /** The URL where the login page is served (used for redirects). Default: `/auth/ui/login` */
    loginUrl?: string;
    /** Optional URL where the register page is served. Default: `/auth/ui/register` */
    registerUrl?: string;
    /**
     * Optional raw CSS string injected into every UI page via a `<style>` tag.
     * Use this to override any CSS variable or rule without providing a full stylesheet.
     * See the Built-in UI documentation for the full list of overridable CSS variables.
     */
    customCss?: string;
    /** Optional URL to a custom logo image displayed in the UI forms. */
    customLogo?: string;

    // Legacy settings kept for compatibility with UI router previews
    primaryColor?: string;
    secondaryColor?: string;
    logoUrl?: string;
    siteName?: string;

    /**
     * Background color for the entire page (sets the `--bg-color` CSS variable).
     * Accepts any valid CSS color value, e.g. `'#f0f4ff'` or `'rgba(240,244,255,1)'`.
     */
    bgColor?: string;

    /**
     * URL of a background image for the entire page (sets the `--bg-image` CSS variable).
     * The image is rendered with `background-size: cover; background-position: center`.
     * Example: `'https://example.com/auth-bg.jpg'`
     */
    bgImage?: string;

    /**
     * Background color for the form/card container (sets the `--card-bg` CSS variable).
     * Accepts any valid CSS color value. Default is `#ffffff`.
     */
    cardBg?: string;
  };
  /**
   * Session management configuration.
   */
  session?: {
    /**
     * Controls how strictly the library verifies session validity against the `sessionStore`.
     *
     * - `allcalls`: Verify the session on every single request. Maximum security, requires a low-latency store (Redis).
     * - `refresh`: Verify the session only during token refresh. High performance with good security.
     * - `none`: Sessions are created and tracked in the store but never verified during requests.
     *
     * @default 'refresh'
     */
    checkOn?: 'allcalls' | 'refresh' | 'none';
  };
  /**
   * Optional template store for custom email and UI translations.
   */
  templateStore?: ITemplateStore;

  /**
   * Identity Provider (IdP) mode configuration.
   * See {@link IdProviderConfig} for full field documentation.
   */
  idProvider?: IdProviderConfig;

  /**
   * Resource Server mode configuration.
   * See {@link ResourceServerConfig} for full field documentation.
   */
  resourceServer?: ResourceServerConfig;
}
