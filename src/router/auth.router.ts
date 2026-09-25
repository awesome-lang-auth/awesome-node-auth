import { Router, Request, Response, NextFunction, RequestHandler } from 'express';
import type { AuthRequestHandler } from '../http-types';
import { IUserStore } from '../interfaces/user-store.interface';
import { IUserMetadataStore } from '../interfaces/user-metadata-store.interface';
import { IRolesPermissionsStore } from '../interfaces/roles-permissions-store.interface';
import { ISessionStore } from '../interfaces/session-store.interface';
import { ITenantStore } from '../interfaces/tenant-store.interface';
import { ILinkedAccountsStore } from '../interfaces/linked-accounts-store.interface';
import { IPendingLinkStore } from '../interfaces/pending-link-store.interface';
import { ISettingsStore } from '../interfaces/settings-store.interface';
import { AuthConfig } from '../models/auth-config.model';
import { BaseUser } from '../models/user.model';
import { AccessTokenPayload, TokenPair } from '../models/token.model';
import { TokenService } from '../services/token.service';
import { PasswordService } from '../services/password.service';
import { MailerService } from '../services/mailer.service';
import { LocalStrategy } from '../strategies/local/local.strategy';
import { TotpStrategy } from '../strategies/two-factor/totp.strategy';
import { MagicLinkStrategy } from '../strategies/magic-link/magic-link.strategy';
import { SmsStrategy } from '../strategies/sms/sms.strategy';
import { GoogleStrategy } from '../strategies/oauth/google.strategy';
import { GithubStrategy } from '../strategies/oauth/github.strategy';
import { GenericOAuthStrategy } from '../strategies/oauth/generic-oauth.strategy';
import { createAuthMiddleware } from '../middleware/auth.middleware';
import { AuthError } from '../models/errors';
import { buildAuthOpenApiSpec, buildSwaggerUiHtml } from './openapi';
import { buildUiRouter } from './ui.router';
import { JwksService } from '../services/jwks.service';
import { AuthEventBus } from '../events/auth-event-bus';
import { AuthEventNames } from '../events/auth-event-names';
import { publishRequestEvent as publishRouterEvent, eventEmail, oauthConflictEventData } from './router-events';

export interface RouterOptions {
  googleStrategy?: GoogleStrategy;
  githubStrategy?: GithubStrategy;
  /**
   * Additional OAuth strategies for any provider that is not Google or GitHub.
   * Each strategy must extend `GenericOAuthStrategy` (or `BaseOAuthStrategy`).
   * The router will mount:
   *   GET  /auth/oauth/:name            — redirect to provider
   *   GET  /auth/oauth/:name/callback   — handle provider callback
   */
  oauthStrategies?: GenericOAuthStrategy[];
  /** Optional rate limiter middleware applied to sensitive auth endpoints (login, refresh, password reset, etc.).
   *
   * Accepts any Express `RequestHandler` (e.g. `express-rate-limit`) as well
   * as the framework-neutral `AuthRequestHandler` type.
   */
  rateLimiter?: AuthRequestHandler;
  /**
   * Optional user-metadata store.  When provided, the `GET /me` endpoint
   * will include a `metadata` field with the user's stored key/value pairs.
   */
  metadataStore?: IUserMetadataStore;
  /**
   * Optional RBAC store.  When provided, the `GET /me` endpoint will include
   * `roles` and `permissions` arrays for the authenticated user.
   */
  rbacStore?: IRolesPermissionsStore;
  /**
   * Optional session store.  When provided and the store implements
   * `deleteExpiredSessions`, the `POST /auth/sessions/cleanup` endpoint is
   * enabled so expired sessions can be purged (e.g. from a cron job).
   */
  sessionStore?: ISessionStore;
  /**
   * Optional tenant store.  When provided, the `DELETE /auth/account` endpoint
   * will also remove the user from all tenants they belong to.
   */
  tenantStore?: ITenantStore;
  /**
   * Optional linked-accounts store.  When provided:
   * - OAuth logins look up existing links via the store before falling back to
   *   `findOrCreateUser`, enabling multiple providers to be linked to one user.
   * - `GET  /auth/linked-accounts`                               — list linked accounts (authenticated)
   * - `DELETE /auth/linked-accounts/:provider/:providerAccountId` — unlink an account (authenticated)
   * - `POST /auth/link-request`                                  — request to link a new email address (authenticated)
   * - `POST /auth/link-verify`                                   — verify a pending link token (completes the link)
   */
  linkedAccountsStore?: ILinkedAccountsStore;
  /**
   * Optional pending-link store.  When provided alongside `linkedAccountsStore`,
   * the library will stash conflicting OAuth account details during an
   * `OAUTH_ACCOUNT_CONFLICT` and include `email` and `provider` query parameters
   * in the `/auth/account-conflict` redirect.  The `/link-verify` endpoint will
   * then retrieve the stashed `providerAccountId` and, when `loginAfterLinking`
   * is set in the request body, issue a session automatically upon completion.
   */
  pendingLinkStore?: IPendingLinkStore;
  /**
   * Optional settings store.  When provided, the `POST /auth/2fa/disable`
   * endpoint will check the global `require2FA` setting and reject the request
   * when two-factor authentication is mandated system-wide.
   */
  settingsStore?: ISettingsStore;
  /**
   * Optional registration handler.  When provided, a `POST /auth/register`
   * endpoint is exposed.  The callback receives the raw request body and must
   * create the user, returning the new `BaseUser` object.
   *
   * If omitted the register endpoint is **not** mounted (useful for projects
   * where self-registration should not be available), unless
   * `defaultRegister: true` opts into the built-in handler.
   *
   * @example
   * ```ts
   * onRegister: async (data) => {
   *   const hash = await passwordService.hash(data.password as string);
   *   return userStore.create({ email: data.email as string, password: hash });
   * }
   * ```
   */
  onRegister?: (data: Record<string, unknown>, config: AuthConfig, options: RouterOptions) => Promise<BaseUser>;

  /**
   * Mount `POST /auth/register` with the built-in handler when `onRegister`
   * is omitted.  Off by default: without `onRegister` and without this flag
   * the register endpoint is not mounted.
   *
   * The built-in handler requires `email` and `password` (non-empty strings),
   * answers `409 USER_EXISTS` when `userStore.findByEmail(email)` finds an
   * account, hashes the password and calls `userStore.create` with an allow-list of
   * fields: `email`, the password hash, and `firstName` / `lastName` when they
   * are strings.  Every other field of the request body (for example `id`,
   * `role`, `isAdmin`, `isEmailVerified`, `loginProvider`, token fields,
   * `tenantId` or `metadata`) is dropped.  Provide `onRegister` to accept
   * other fields.
   *
   * Ignored when `onRegister` is provided and in Resource Server mode.
   *
   * @default false
   */
  defaultRegister?: boolean;

  /**
   * Local base path where this specific auth router instance is mounted.
   *
   * **Note:** If provided, this overrides the global `config.apiPrefix`.
   * Use this when mounting multiple auth routers with different prefixes
   * (e.g., API versioning `/v1/auth`, `/v2/auth`) while sharing a single global `AuthConfig`.
   *
   * @default config.apiPrefix || '/auth'
   */
  apiPrefix?: string;

  /**
   * Enable Swagger UI (`GET /openapi.json`, `GET /docs`) on the auth router.
   *
   * - `true`   — always enabled
   * - `false`  — always disabled
   * - `'auto'` (default) — enabled when `NODE_ENV` is **not** `'production'`
   *
   * @default 'auto'
   */
  swagger?: boolean | 'auto';

  /**
   * Base path where the auth router is mounted.
   * Used to build accurate path entries in the OpenAPI spec.
   *
   * @default '/auth'
   */
  swaggerBasePath?: string;

  /**
   * Dynamic CORS configuration for the auth router.
   *
   * When set, the router automatically handles `Access-Control-*` response
   * headers and `OPTIONS` preflight requests.  Only origins that appear in the
   * `origins` array receive CORS headers, so the browser will allow
   * cross-origin requests with `credentials: 'include'`.
   *
   * This list is also merged with `config.email.siteUrl` (when an array) to
   * build the full allowlist used for dynamic OAuth redirect resolution.
   *
   * @example
   * ```ts
   * cors: { origins: ['https://app.example.com', 'https://admin.example.com'] }
   * ```
   */
  cors?: {
    origins: string[];
  };

  /**
   * Optional directory containing Vanilla UI assets (html, js, css).
   * If not provided, will look for 'ui-assets' relative to the library's dist.
   */
  uiAssetsDir?: string;

  /**
   * Optional directory where uploaded assets (like logos) are stored.
   */
  uploadDir?: string;

  /**
   * Branding and theming settings for the Vanilla UI.
   */
  ui?: {
    siteName?: string;
    primaryColor?: string;
    secondaryColor?: string;
    logoUrl?: string;
  };

  /**
   * Optional auth event bus. When provided, core auth lifecycle events are
   * published automatically from the router.
   */
  eventBus?: AuthEventBus;
}

/**
 * Profile fields the built-in register handler copies from the request body:
 * the fields a user may set on themselves through `PATCH /profile`.
 */
const DEFAULT_REGISTER_PROFILE_FIELDS = ['firstName', 'lastName'] as const;

const tokenService = new TokenService();
const passwordService = new PasswordService();
const totpStrategy = new TotpStrategy();
const magicLinkStrategy = new MagicLinkStrategy();
const smsStrategy = new SmsStrategy();

function handleError(res: Response, err: unknown): void {
  if (err instanceof AuthError) {
    res.status(err.statusCode).json({ error: err.message, code: err.code });
  } else {
    console.error('[node-auth] Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
}

/**
 * Returns the default (first) siteUrl for use in email links.
 * When `siteUrl` is an array the first entry is the canonical base URL.
 */
function getDefaultSiteUrl(config: AuthConfig): string {
  const su = config.email?.siteUrl;
  if (Array.isArray(su)) return su[0] ?? '';
  return su ?? '';
}

/**
 * Build the merged allowlist from `config.email.siteUrl` (string or array)
 * and `options.cors.origins`.  Used to validate dynamic redirects and to
 * decide which origin to echo back in `Access-Control-Allow-Origin`.
 */
function buildAllowedOrigins(config: AuthConfig, options: RouterOptions): string[] {
  const su = config.email?.siteUrl;
  const fromSiteUrl = Array.isArray(su) ? su : (su ? [su] : []);
  const fromCors = options.cors?.origins ?? [];
  // Deduplicate while preserving order
  return [...new Set([...fromSiteUrl, ...fromCors])];
}

/**
  * Dynamically resolves the best redirect / link base URL for the current
 * request.  Rules (in order):
 *  1. If `allowedOrigins` is non-empty, try to match the request `Origin`
 *     header against the list and return the matching entry.
 *  2. If no `Origin` header, try to extract and match the origin from the
 *     `Referer` header.
 *  3. Fall back to `getDefaultSiteUrl(config)`.
 *
 * The result is always guaranteed to be in `allowedOrigins` (when that list
 * is non-empty), preventing open-redirect vulnerabilities.
 */
function resolveSiteUrl(req: Request, config: AuthConfig, allowedOrigins: string[]): string {
  if (allowedOrigins.length > 0) {
    const origin = req.headers['origin'] as string | undefined;
    if (origin && allowedOrigins.includes(origin)) return origin;
    const referer = req.headers['referer'] as string | undefined;
    if (referer) {
      try {
        const refOrigin = new URL(referer).origin;
        if (allowedOrigins.includes(refOrigin)) return refOrigin;
      } catch { /* ignore malformed referer */ }
    }
  }
  return getDefaultSiteUrl(config);
}

/**
 * Resolves the effective apiPrefix by checking (1) RouterOptions, (2) AuthConfig, (3) defaulting to '/auth'.
 * This ensures a single source of truth across the library.
 * @internal
 */
export function resolveApiPrefix(config: AuthConfig, options?: RouterOptions): string {
  return options?.apiPrefix || config.apiPrefix || '/auth';
}

/**
 * Resolves the path to the static UI or legacy route base.
 * @public
 */
export function buildUiLink(siteUrl: string, path: string, config: AuthConfig, options: RouterOptions): string {
  const prefix = resolveApiPrefix(config, options);
  const cleanPrefix = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  const cleanPath = path.startsWith('/') ? path.slice(1) : path;
  if (config.ui?.enabled) {
    const result = `${siteUrl}${cleanPrefix}/ui/${cleanPath}`;
    return result;
  }
  const result = `${siteUrl}${cleanPrefix}/${cleanPath}`;
  return result;
}

/**
 * Encodes `{ n: nonce, o: resolvedOrigin, p?: path }` as a URL-safe base64
 * string for use as the OAuth `state` parameter.  Embedding the origin lets
 * the callback redirect back to the exact origin that started the flow, even
 * when multiple front-ends share a single auth server.  The optional `p` field
 * encodes the post-login path (e.g. `/example/account`).
 */
function encodeOAuthState(nonce: string, redirectOrigin: string, returnPath?: string): string {
  const payload: Record<string, string> = { n: nonce, o: redirectOrigin };
  if (returnPath) payload['p'] = returnPath;
  return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

/** Shape of the structured OAuth state parameter. */
interface OAuthState {
  /** Random nonce (CSRF protection). */
  n: string;
  /** Pre-validated redirect origin embedded at flow initiation. */
  o: string;
  /** Optional post-login path within the origin (e.g. `/example/account`). */
  p?: string;
}

function isOAuthState(value: unknown): value is OAuthState {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof (value as OAuthState).n === 'string' &&
    typeof (value as OAuthState).o === 'string'
  );
}

/**
 * Extracts the redirect origin from a previously encoded OAuth state.
 * Returns `null` for legacy plain-nonce states or on parse errors.
 * **Always validate the returned origin against `allowedOrigins` before use.**
 */
function decodeOAuthStateOrigin(state: string | undefined): string | null {
  if (!state) return null;
  try {
    const parsed: unknown = JSON.parse(Buffer.from(state, 'base64url').toString());
    if (isOAuthState(parsed)) return parsed.o;
  } catch { /* plain nonce or invalid base64 — ignore */ }
  return null;
}

/**
 * Resolves the post-OAuth redirect target from the encoded state.
 * Falls back to `getDefaultSiteUrl` when the state carries no origin or the
 * origin is not in the allowlist (prevents open-redirect attacks).  When the
 * state includes a `p` path field it is appended to the origin.
 */
function resolveOAuthRedirect(state: string | undefined, config: AuthConfig, allowedOrigins: string[]): string {
  const fromState = decodeOAuthStateOrigin(state);
  if (fromState && (allowedOrigins.length === 0 || allowedOrigins.includes(fromState))) {
    // Also extract the optional path field from the state
    try {
      if (state) {
        const parsed: unknown = JSON.parse(Buffer.from(state, 'base64url').toString());
        if (isOAuthState(parsed) && parsed.p) {
          const cleanPath = parsed.p.startsWith('/') ? parsed.p : `/${parsed.p}`;
          // If fromState has a path part (e.g. https://ex.com/example) and cleanPath
          // starts with that same path (e.g. /example/account), deduplicate to
          // prevent https://ex.com/example/example/account.
          try {
            const originUrl = new URL(fromState);
            const basePath = originUrl.pathname.replace(/\/$/, '');
            if (basePath && basePath !== '/' && cleanPath.startsWith(basePath)) {
              return `${originUrl.origin}${cleanPath}`;
            }
          } catch { /* ignore invalid URL */ }
          return `${fromState}${cleanPath}`;
        }
      }
    } catch { /* ignore */ }
    return fromState;
  }
  return getDefaultSiteUrl(config);
}

/**
 * Parse a JWT-style expiry string (e.g. '7d', '30d', '2h', '15m') to milliseconds.
 * Falls back to 7 days when the value is absent or unparseable.
 */
function parseExpiryMs(expiry: string | undefined): number {
  if (!expiry) return 7 * 24 * 60 * 60 * 1000;
  const match = expiry.match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)$/i);
  if (!match) return 7 * 24 * 60 * 60 * 1000;
  const value = parseFloat(match[1]);
  const unit = match[2].toLowerCase();
  const multipliers: Record<string, number> = {
    ms: 1,
    s: 1_000,
    m: 60 * 1_000,
    h: 60 * 60 * 1_000,
    d: 24 * 60 * 60 * 1_000,
    w: 7 * 24 * 60 * 60 * 1_000,
  };
  return value * (multipliers[unit] ?? multipliers['d']);
}

/**
 * Build the JWT payload for a user, merging any custom claims provided via
 * `config.buildTokenPayload`.
 */
function buildPayload(user: BaseUser, config: AuthConfig): AccessTokenPayload {
  const base: AccessTokenPayload = { sub: user.id, email: user.email, role: user.role, loginProvider: user.loginProvider ?? 'local', isEmailVerified: user.isEmailVerified ?? false, isTotpEnabled: user.isTotpEnabled ?? false };
  if (config.buildTokenPayload) {
    return { ...base, ...config.buildTokenPayload(user) };
  }
  return base;
}

/**
 * Returns true when the client has opted into bearer-token delivery by
 * sending the `X-Auth-Strategy: bearer` request header.
 */
function isBearerRequest(req: Request): boolean {
  return req.headers['x-auth-strategy'] === 'bearer';
}

/**
 * Issue tokens to the client.  When the request carries the
 * `X-Auth-Strategy: bearer` header the tokens are returned in the JSON
 * response body; otherwise they are set as HttpOnly cookies (default).
 */
function sendTokens(req: Request, res: Response, tokens: TokenPair, config: AuthConfig): void {
  if (isBearerRequest(req)) {
    res.json({ success: true, accessToken: tokens.accessToken, refreshToken: tokens.refreshToken });
  } else {
    tokenService.setTokenCookies(res, tokens, config);
    res.json({ success: true });
  }
}

/**
 * Enhanced token issuance that creates a stateful session when a sessionStore is configured.
 * Pass `oldSid` to atomically rotate the session (revoke old, create new) on token refresh.
 */
async function issueTokens(
  req: Request,
  res: Response,
  user: BaseUser,
  config: AuthConfig,
  options: RouterOptions,
  userStore: IUserStore,
  redirectTo?: string,
  oldSid?: string
): Promise<{ sessionId?: string }> {
  const payload = buildPayload(user, config);
  const refreshExpiryMs = parseExpiryMs(config.refreshTokenExpiresIn as string | undefined);

  if (options.sessionStore) {
    const session = await options.sessionStore.createSession({
      userId: user.id,
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip || req.socket.remoteAddress,
      expiresAt: new Date(Date.now() + refreshExpiryMs),
      createdAt: new Date(),
    });
    payload.sid = session.sessionHandle;

    // Revoke the previous session now that the new one is live (token rotation)
    if (oldSid) {
      await options.sessionStore.revokeSession(oldSid).catch(() => {});
    }
  }

  const tokens = tokenService.generateTokenPair(payload, config);
  const refreshExpiry = new Date(Date.now() + refreshExpiryMs);
  await userStore.updateRefreshToken(user.id, tokens.refreshToken, refreshExpiry);

  if (redirectTo) {
    tokenService.setTokenCookies(res, tokens, config);
    res.redirect(redirectTo);
  } else {
    sendTokens(req, res, tokens, config);
  }
  return { sessionId: payload.sid };
}

export function createAuthRouter(
  userStore: IUserStore,
  config: AuthConfig,
  options: RouterOptions = {}
): Router {
  const router = Router();

  // Parameterize refresh token path by default based on apiPrefix
  config.cookieOptions = {
    ...config.cookieOptions,
    refreshTokenPath: config.cookieOptions?.refreshTokenPath ?? `${options.apiPrefix || config.apiPrefix || '/auth'}/refresh`
  };

  // With a session store, `session.checkOn: 'allcalls'` checks revocation on
  // the router's own protected routes too.
  const authMiddleware = createAuthMiddleware(config, options.sessionStore);
  const localStrategy = new LocalStrategy(userStore, passwordService);
  const rl = options.rateLimiter ? [options.rateLimiter] : [];
  const allowedOrigins = buildAllowedOrigins(config, options);
  const isResourceServer = config.resourceServer?.enabled === true;
  const eventBus = options.eventBus;
  // Built-in register handler (opt-in via `defaultRegister: true`). It persists
  // an allow-list only: `email`, the password hash and the profile fields.
  // Anything else in the body (id, role, isAdmin, isEmailVerified, tokens,
  // tenantId, metadata, ...) is dropped, never forwarded to `create`.
  const defaultRegisterHandler = async (data: Record<string, unknown>): Promise<BaseUser> => {
    const body: Record<string, unknown> = data && typeof data === 'object' ? data : {};
    const email = body['email'];
    const password = body['password'];
    if (typeof email !== 'string' || typeof password !== 'string' || !email || !password) {
      throw new AuthError('Email and password are required', 'INVALID_INPUT', 400);
    }
    // IUserStore does not require unique e-mail addresses, so refuse a taken
    // one here rather than create a second account under it (as Go does, and
    // as POST /change-email/request does).
    if (await userStore.findByEmail(email)) {
      throw new AuthError('User already exists', 'USER_EXISTS', 409);
    }
    const hash = await passwordService.hash(password, config.bcryptSaltRounds);
    const newUser: Partial<BaseUser> = { email, password: hash };
    for (const field of DEFAULT_REGISTER_PROFILE_FIELDS) {
      const value = body[field];
      if (typeof value === 'string') newUser[field] = value;
    }
    return userStore.create(newUser);
  };
  const registerHandler: RouterOptions['onRegister'] | undefined = isResourceServer
    ? undefined
    : (options.onRegister
      ?? (options.defaultRegister === true && typeof userStore.create === 'function'
        ? defaultRegisterHandler
        : undefined));

  if (!isResourceServer && !options.onRegister && options.defaultRegister === true) {
    if (registerHandler) {
      process.stderr.write(
        '[awesome-node-auth] INFO: POST /register is enabled with the built-in handler (defaultRegister); it stores email, the password hash, firstName and lastName only.\n',
      );
    } else {
      process.stderr.write(
        '[awesome-node-auth] WARN: POST /register was not mounted: defaultRegister is set but userStore.create is unavailable.\n',
      );
    }
  }

  // ── IdP mode: JWKS endpoint ────────────────────────────────────────────────
  // Registered BEFORE auth middleware so it is always public (no token required).
  if (config.idProvider?.privateKey || config.idProvider?.enabled === true) {
    const idp = config.idProvider;
    const jwksPath = idp.jwksPath ?? '/.well-known/jwks.json';

    // Ensure the keypair is initialised at router-creation time so that the
    // JWKS document can be derived deterministically for the lifetime of this
    // router instance.
    if (!idp.privateKey) {
      const kp = JwksService.generateKeypair();
      idp.privateKey = kp.privateKey;
      idp.publicKey = kp.publicKey;
    } else if (!idp.publicKey) {
      idp.publicKey = JwksService.derivePublicKey(idp.privateKey);
    }

    const jwksDocument = JwksService.buildJwksDocument(idp.publicKey!);

    router.get(jwksPath, (_req: Request, res: Response) => {
      // Set CORS headers for the JWKS endpoint
      const corsOrigins = idp.jwksCorsOrigins ?? '*';
      if (corsOrigins === '*') {
        res.setHeader('Access-Control-Allow-Origin', '*');
      } else {
        const origins = Array.isArray(corsOrigins) ? corsOrigins : [corsOrigins];
        const reqOrigin = (_req.headers['origin'] as string | undefined) ?? '';
        if (origins.includes(reqOrigin)) {
          res.setHeader('Access-Control-Allow-Origin', reqOrigin);
        }
      }
      res.setHeader('Cache-Control', 'public, max-age=3600');
      res.json(jwksDocument);
    });
  }

  // ── Resource Server mode: skip auth-flow routes ────────────────────────────
  // When enabled this instance has no local user DB — only token verification
  // routes make sense. Auth-flow routes (login / register / etc.) are skipped.

  // Dynamic CORS — only active when `options.cors.origins` is provided
  if (options.cors?.origins?.length) {
    router.use((req: Request, res: Response, next: NextFunction) => {
      const origin = req.headers['origin'] as string | undefined;
      if (origin && options.cors!.origins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-CSRF-Token,X-Api-Key,X-Auth-Strategy');
      }
      // Ensure caches/proxies do not serve a cached response with the wrong origin
      res.setHeader('Vary', 'Origin');
      if (req.method === 'OPTIONS') { res.sendStatus(204); return; }
      next();
    });
  }

  // Auto-initialize CSRF token cookie if missing
  if (config.csrf?.enabled) {
    router.use((req: Request, res: Response, next: NextFunction) => {
      const existing = tokenService.extractTokenFromCookie(req, 'csrf-token');
      if (!existing) {
        tokenService.initCsrfToken(res, config);
      }
      next();
    });
  }

  // POST /login
  if (!isResourceServer) router.post('/login', ...rl, async (req: Request, res: Response) => {
    try {
      const { email, password } = req.body as { email: string; password: string };
      const user = await localStrategy.authenticate({ email, password }, config);

      // Determine whether a 2FA challenge is needed.
      // Triggered when:
      //   (a) the user has TOTP enabled (explicit authenticator-app 2FA), OR
      //   (b) require2FA is set on the user record (any available 2FA method suffices,
      //       including magic-link — the user does NOT need an authenticator app).
      const hasTotpEnabled = !!(user.isTotpEnabled && user.totpSecret);
      const requires2fa = hasTotpEnabled || !!user.require2FA;

      if (requires2fa) {
        // Compute which 2FA methods this user can use
        const available2faMethods: string[] = [];
        if (hasTotpEnabled) available2faMethods.push('totp');
        if (user.phoneNumber && config.sms) available2faMethods.push('sms');
        if (config.email?.sendMagicLink || config.email?.mailer) available2faMethods.push('magic-link');

        // If 2FA is required but the account has no configured method at all,
        // tell the client to set one up first.
        if (available2faMethods.length === 0) {
          const tempToken = tokenService.generateTempToken(buildPayload(user, config), config);
          res.status(403).json({ requires2FASetup: true, tempToken, code: '2FA_SETUP_REQUIRED' });
          return;
        }

        // The step-up token is accepted by the 2FA completion endpoints only,
        // never as a session (see TokenService.generateTempToken).
        const tempToken = tokenService.generateTempToken(buildPayload(user, config), config);
        res.json({ requiresTwoFactor: true, tempToken, available2faMethods });
        return;
      }

      await userStore.updateLastLogin(user.id);
      const { sessionId } = await issueTokens(req, res, user, config, options, userStore);
      publishRouterEvent(eventBus, AuthEventNames.AUTH_LOGIN_SUCCESS, req, {
        userId: user.id,
        sessionId,
        data: { method: 'local' },
      });
    } catch (err) {
      if (err instanceof AuthError && err.statusCode === 401) {
        publishRouterEvent(eventBus, AuthEventNames.AUTH_LOGIN_FAILED, req, {
          data: { method: 'local', email: eventEmail((req.body as { email?: unknown } | undefined)?.email) },
        });
      }
      handleError(res, err);
    }
  });

  // POST /logout
  // We don't use the standard authMiddleware here because we want to clear cookies
  // even if the token is expired or invalid.
  if (!isResourceServer) router.post('/logout', ...rl, async (req: Request, res: Response, next: NextFunction) => {
    // Try to get the user from the access token, but don't block if it fails.
    // Like auth.middleware(): the Authorization: Bearer header (bearer clients)
    // first, then the accessToken cookie.
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ')
      ? authHeader.substring(7)
      : tokenService.extractTokenFromCookie(req, 'accessToken');
    if (token) {
      try {
        const payload = tokenService.verifyAccessToken(token, config);
        req.user = payload;

        // Revoke stateful session
        if (options.sessionStore && payload.sid) {
          await options.sessionStore.revokeSession(payload.sid).catch(() => {});
        }
      } catch (err) {
        // Token dead, but we proceed to clear it
      }
    }
    // A bearer client may send its refresh token in the body, as for /refresh.
    // It ends the session only while it is the user's current refresh token.
    const bodyRefreshToken = (req.body as { refreshToken?: unknown } | undefined)?.refreshToken;
    if (typeof bodyRefreshToken === 'string' && bodyRefreshToken) {
      try {
        const payload = tokenService.verifyRefreshToken(bodyRefreshToken, config);
        const user = await userStore.findById(payload.sub);
        if (user && user.refreshToken === bodyRefreshToken) {
          if (options.sessionStore && payload.sid) {
            await options.sessionStore.revokeSession(payload.sid).catch(() => {});
          }
          if (!req.user) req.user = payload;
        }
      } catch {
        // Invalid, expired or already rotated: nothing to revoke
      }
    }
    next();
  }, async (req: Request, res: Response) => {
    try {
      const userId = req.user?.sub;
      const sessionId = req.user?.sid;
      if (req.user?.sub) {
        await userStore.updateRefreshToken(req.user.sub, null, null);
      }
      tokenService.clearTokenCookies(res, config);
      publishRouterEvent(eventBus, AuthEventNames.AUTH_LOGOUT, req, {
        userId,
        sessionId,
      });
      res.json({ success: true });
    } catch (err) {
      // Even if DB update fails, make sure we clear cookies on the client
      tokenService.clearTokenCookies(res, config);
      handleError(res, err);
    }
  });

  // POST /refresh
  if (!isResourceServer) router.post('/refresh', ...rl, async (req: Request, res: Response) => {
    try {
      // Accept refresh token from request body (bearer flow) or from cookie
      const bodyToken = (req.body as { refreshToken?: string } | undefined)?.refreshToken;
      const refreshToken = bodyToken ?? tokenService.extractTokenFromCookie(req, 'refreshToken');
      if (!refreshToken) {
        res.status(401).json({ error: 'No refresh token provided' });
        return;
      }
      const payload = tokenService.verifyRefreshToken(refreshToken, config);
      
      // Real-time Session Validation
      const checkOn = config.session?.checkOn ?? 'refresh';
      if (options.sessionStore && payload.sid && checkOn !== 'none') {
        const session = await options.sessionStore.getSession(payload.sid);
        if (!session) {
          res.status(401).json({ error: 'Session has been revoked', code: 'SESSION_REVOKED' });
          return;
        }
      }

      const user = await userStore.findById(payload.sub);
      if (!user || user.refreshToken !== refreshToken) {
        res.status(401).json({ error: 'Invalid refresh token' });
        return;
      }
      
      const { sessionId } = await issueTokens(req, res, user, config, options, userStore, /* redirectTo */ undefined, payload.sid);
      publishRouterEvent(eventBus, AuthEventNames.SESSION_ROTATED, req, {
        userId: user.id,
        sessionId,
        data: { previousSessionId: payload.sid },
      });
    } catch (err) {
      handleError(res, err);
    }
  });

  // GET /me
  router.get('/me', ...rl, authMiddleware, async (req: Request, res: Response) => {
    try {
      const user = await userStore.findById(req.user!.sub);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      // Build a safe profile — omit all sensitive internal fields
      const profile: Record<string, unknown> = {
        ...buildPayload(user, config),
      };
      if (options.metadataStore) {
        profile['metadata'] = await options.metadataStore.getMetadata(user.id);
      }
      if (options.rbacStore) {
        const roles = await options.rbacStore.getRolesForUser(user.id);
        const permissions = await options.rbacStore.getPermissionsForUser(user.id);
        profile['roles'] = roles;
        profile['permissions'] = permissions;
      }
      res.json(profile);
    } catch (err) {
      handleError(res, err);
    }
  });

  // PATCH /profile
  router.patch('/profile', ...rl, authMiddleware, async (req: Request, res: Response) => {
    try {
      if (!userStore.updateProfile) {
        res.status(501).json({ error: 'UserStore does not implement updateProfile' });
        return;
      }
      const { firstName, lastName } = req.body as { firstName?: string | null; lastName?: string | null };
      await userStore.updateProfile(req.user!.sub, { firstName, lastName });
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /add-phone
  router.post('/add-phone', ...rl, authMiddleware, async (req: Request, res: Response) => {
    try {
      if (!userStore.updatePhoneNumber) {
        res.status(501).json({ error: 'UserStore does not implement updatePhoneNumber' });
        return;
      }
      const { phoneNumber } = req.body as { phoneNumber: string | null };
      await userStore.updatePhoneNumber(req.user!.sub, phoneNumber);
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /register (optional — only mounted when onRegister is provided or defaultRegister is set)
  if (registerHandler && !isResourceServer) {
    router.post('/register', ...rl, async (req: Request, res: Response) => {
      try {
        const data = req.body as Record<string, unknown>;
        const user = await registerHandler(data, config, options);
        if (config.email?.sendWelcome) {
          // The welcome callback gets the request data without the plaintext password.
          const { password: _password, ...welcomeData } = data ?? {};
          await config.email.sendWelcome(user.email, welcomeData);
        } else if (config.email?.mailer) {
          const mailer = new MailerService(config.email.mailer, config.templateStore);
          const siteUrl = resolveSiteUrl(req, config, allowedOrigins);
          await mailer.sendWelcome(user.email, { loginUrl: `${siteUrl}/login` });
        }
        publishRouterEvent(eventBus, AuthEventNames.USER_CREATED, req, {
          userId: user.id,
          data: { email: eventEmail(user.email), method: options.onRegister ? 'custom' : 'default' },
        });
        res.status(201).json({ success: true, userId: user.id });
      } catch (err) {
        handleError(res, err);
      }
    });
  }

  // POST /sessions/cleanup (optional — only mounted when sessionStore with deleteExpiredSessions is provided)
  if (options.sessionStore?.deleteExpiredSessions) {
    const deleteExpiredSessions = options.sessionStore.deleteExpiredSessions.bind(options.sessionStore) as () => Promise<number>;
    router.post('/sessions/cleanup', ...rl, async (_req: Request, res: Response) => {
      try {
        const deleted = await deleteExpiredSessions();
        res.json({ success: true, deleted });
      } catch (err) {
        handleError(res, err);
      }
    });
  }

  // User-facing session management endpoints (require sessionStore)
  if (options.sessionStore) {
    // GET /sessions — list the current user's active sessions
    router.get('/sessions', ...rl, authMiddleware, async (req: Request, res: Response) => {
      try {
        const sessions = await options.sessionStore!.getSessionsForUser(req.user!.sub);
        res.json({ sessions });
      } catch (err) {
        handleError(res, err);
      }
    });

    // DELETE /sessions/:handle — revoke a specific session owned by the current user
    router.delete('/sessions/:handle', ...rl, authMiddleware, async (req: Request, res: Response) => {
      try {
        const handle = decodeURIComponent(req.params['handle'] as string);
        const session = await options.sessionStore!.getSession(handle);
        // Ensure the session belongs to the authenticated user before revoking
        if (!session || session.userId !== req.user!.sub) {
          res.status(404).json({ error: 'Session not found' });
          return;
        }
        await options.sessionStore!.revokeSession(handle);
        res.json({ success: true });
      } catch (err) {
        handleError(res, err);
      }
    });
  }

  // POST /forgot-password
  if (!isResourceServer) router.post('/forgot-password', ...rl, async (req: Request, res: Response) => {
    try {
      const { email, emailLang } = req.body as { email: string; emailLang?: string };
      const user = await userStore.findByEmail(email);
      if (user) {
        const token = tokenService.generateSecureToken();
        const expiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
        await userStore.updateResetToken(user.id, token, expiry);
        const siteUrl = resolveSiteUrl(req, config, allowedOrigins);
        const link = buildUiLink(siteUrl, `/reset-password?token=${token}`, config, options);
        if (config.email?.sendPasswordReset) {
          await config.email.sendPasswordReset(email, token, link, emailLang);
        } else if (config.email?.mailer) {
          const mailer = new MailerService(config.email.mailer, config.templateStore);
          await mailer.sendPasswordReset(email, token, link, emailLang);
        }
      }
      // Always return success to prevent email enumeration
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /reset-password
  if (!isResourceServer) router.post('/reset-password', ...rl, async (req: Request, res: Response) => {
    try {
      const { token, password } = req.body as { token: string; password: string };
      if (!userStore.findByResetToken) {
        res.status(500).json({ error: 'UserStore does not implement findByResetToken' });
        return;
      }
      const user = await userStore.findByResetToken(token);
      if (!user || !user.resetToken || user.resetToken !== token) {
        res.status(400).json({ error: 'Invalid reset token' });
        return;
      }
      if (user.resetTokenExpiry && new Date() > user.resetTokenExpiry) {
        res.status(400).json({ error: 'Reset token has expired' });
        return;
      }
      const hashed = await passwordService.hash(password, config.bcryptSaltRounds);
      await userStore.updatePassword(user.id, hashed);
      await userStore.updateResetToken(user.id, null, null);
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /2fa/setup
  router.post('/2fa/setup', ...rl, authMiddleware, (req: Request, res: Response) => {
    try {
      const appName = config.twoFactor?.appName ?? 'awesome-node-auth';
      const email = req.user!.email;
      const { secret, otpauthUrl, qrCode } = totpStrategy.generateSecret(email, appName);
      // Return qrCode as a promise - resolve it
      qrCode.then((dataUrl) => {
        res.json({ secret, otpauthUrl, qrCode: dataUrl });
      }).catch((err) => handleError(res, err));
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /2fa/verify-setup
  router.post('/2fa/verify-setup', ...rl, authMiddleware, async (req: Request, res: Response) => {
    try {
      const { token, secret } = req.body as { token: string; secret: string };
      const valid = await totpStrategy.verify(token, secret);
      if (!valid) {
        res.status(400).json({ error: 'Invalid TOTP code' });
        return;
      }
      await totpStrategy.enable(req.user!.sub, secret, userStore);
      publishRouterEvent(eventBus, AuthEventNames.USER_2FA_ENABLED, req, {
        userId: req.user!.sub,
      });
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /2fa/verify - after login with 2FA
  router.post('/2fa/verify', ...rl, async (req: Request, res: Response) => {
    try {
      const { tempToken, totpCode } = req.body as { tempToken: string; totpCode: string };
      const payload = tokenService.verifyTempToken(tempToken, config);
      const user = await userStore.findById(payload.sub);
      if (!user || !user.totpSecret) {
        res.status(400).json({ error: 'User not found or 2FA not set up' });
        return;
      }
      const valid = await totpStrategy.verify(totpCode, user.totpSecret);
      if (!valid) {
        res.status(401).json({ error: 'Invalid TOTP code' });
        return;
      }
      const { sessionId } = await issueTokens(req, res, user, config, options, userStore);
      publishRouterEvent(eventBus, AuthEventNames.AUTH_LOGIN_SUCCESS, req, {
        userId: user.id,
        sessionId,
        data: { method: 'totp' },
      });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /2fa/disable
  router.post('/2fa/disable', ...rl, authMiddleware, async (req: Request, res: Response) => {
    try {
      const userId = req.user!.sub;
      // Block disable when 2FA is enforced per-user
      const currentUser = await userStore.findById(userId);
      if (currentUser?.require2FA) {
        res.status(403).json({ error: 'Cannot disable 2FA: required for your account', code: '2FA_REQUIRED' });
        return;
      }
      // Block disable when 2FA is enforced system-wide
      if (options.settingsStore) {
        const settings = await options.settingsStore.getSettings();
        if (settings.require2FA) {
          res.status(403).json({ error: 'Cannot disable 2FA: required by system policy', code: '2FA_REQUIRED' });
          return;
        }
      }
      await totpStrategy.disable(userId, userStore);
      publishRouterEvent(eventBus, AuthEventNames.USER_2FA_DISABLED, req, {
        userId,
      });
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /change-password (authenticated)
  router.post('/change-password', ...rl, authMiddleware, async (req: Request, res: Response) => {
    try {
      const { currentPassword, newPassword } = req.body as {
        currentPassword: string;
        newPassword: string;
      };
      const user = await userStore.findById(req.user!.sub);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      if (user.password) {
        const valid = await passwordService.compare(currentPassword, user.password);
        if (!valid) {
          res.status(401).json({ error: 'Current password is incorrect' });
          return;
        }
      } else if (!currentPassword && !newPassword) {
        res.status(400).json({ error: 'New password is required' });
        return;
      }
      const hashed = await passwordService.hash(newPassword, config.bcryptSaltRounds);
      await userStore.updatePassword(user.id, hashed);
      publishRouterEvent(eventBus, AuthEventNames.USER_PASSWORD_CHANGED, req, {
        userId: user.id,
      });
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /send-verification-email (authenticated)
  router.post('/send-verification-email', ...rl, authMiddleware, async (req: Request, res: Response) => {
    try {
      if (!userStore.updateEmailVerificationToken || !userStore.updateEmailVerified) {
        res.status(500).json({ error: 'UserStore does not implement email verification' });
        return;
      }
      const { emailLang } = req.body as { emailLang?: string };
      const user = await userStore.findById(req.user!.sub);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      if (user.isEmailVerified) {
        res.status(400).json({ error: 'Email is already verified' });
        return;
      }
      const token = tokenService.generateSecureToken();
      const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
      await userStore.updateEmailVerificationToken(user.id, token, expiry);
      const siteUrl = resolveSiteUrl(req, config, allowedOrigins);
      const link = buildUiLink(siteUrl, `/verify-email?token=${token}`, config, options);
      if (config.email?.sendVerificationEmail) {
        await config.email.sendVerificationEmail(user.email, token, link, emailLang);
      } else if (config.email?.mailer) {
        const mailer = new MailerService(config.email.mailer, config.templateStore);
        await mailer.sendVerificationEmail(user.email, token, link, emailLang);
      }
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // GET /verify-email?token=...
  router.get('/verify-email', ...rl, async (req: Request, res: Response) => {
    try {
      const { token } = req.query as { token?: string };
      if (!token) {
        res.status(400).json({ error: 'Token is required' });
        return;
      }
      if (!userStore.findByEmailVerificationToken || !userStore.updateEmailVerificationToken || !userStore.updateEmailVerified) {
        res.status(500).json({ error: 'UserStore does not implement email verification' });
        return;
      }
      const user = await userStore.findByEmailVerificationToken(token);
      if (!user || user.emailVerificationToken !== token) {
        res.status(400).json({ error: 'Invalid verification token' });
        return;
      }
      if (user.emailVerificationTokenExpiry && new Date() > user.emailVerificationTokenExpiry) {
        res.status(400).json({ error: 'Verification token has expired' });
        return;
      }
      await userStore.updateEmailVerified(user.id, true);
      await userStore.updateEmailVerificationToken(user.id, null, null);
      publishRouterEvent(eventBus, AuthEventNames.USER_EMAIL_VERIFIED, req, {
        userId: user.id,
      });
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /change-email/request (authenticated)
  router.post('/change-email/request', ...rl, authMiddleware, async (req: Request, res: Response) => {
    try {
      if (!userStore.updateEmailChangeToken) {
        res.status(500).json({ error: 'UserStore does not implement change-email' });
        return;
      }
      const { newEmail, emailLang } = req.body as { newEmail: string; emailLang?: string };
      const existing = await userStore.findByEmail(newEmail);
      if (existing) {
        res.status(409).json({ error: 'Email address is already in use' });
        return;
      }
      const user = await userStore.findById(req.user!.sub);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      if (!user.password) {
        res.status(403).json({
          error: 'You must set a password before you can change your email address.',
          code: 'PASSWORD_REQUIRED'
        });
        return;
      }
      const token = tokenService.generateSecureToken();
      const expiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
      await userStore.updateEmailChangeToken(user.id, newEmail, token, expiry);
      const siteUrl = resolveSiteUrl(req, config, allowedOrigins);
      const link = buildUiLink(siteUrl, `/change-email/confirm?token=${token}`, config, options);
      if (config.email?.sendVerificationEmail) {
        await config.email.sendVerificationEmail(newEmail, token, link, emailLang);
      } else if (config.email?.mailer) {
        const mailer = new MailerService(config.email.mailer, config.templateStore);
        await mailer.sendVerificationEmail(newEmail, token, link, emailLang);
      }
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /change-email/confirm
  router.post('/change-email/confirm', ...rl, async (req: Request, res: Response) => {
    try {
      if (!userStore.findByEmailChangeToken || !userStore.updateEmail || !userStore.updateEmailChangeToken) {
        res.status(500).json({ error: 'UserStore does not implement change-email' });
        return;
      }
      const { token } = req.body as { token: string };
      const user = await userStore.findByEmailChangeToken(token);
      if (!user || user.emailChangeToken !== token) {
        res.status(400).json({ error: 'Invalid email-change token' });
        return;
      }
      if (user.emailChangeTokenExpiry && new Date() > user.emailChangeTokenExpiry) {
        res.status(400).json({ error: 'Email-change token has expired' });
        return;
      }
      const oldEmail = user.email;
      const newEmail = user.pendingEmail!;
      await userStore.updateEmail(user.id, newEmail);
      await userStore.updateEmailChangeToken(user.id, null, null, null);
      // Send notification to old address
      if (config.email?.sendEmailChanged) {
        await config.email.sendEmailChanged(oldEmail, newEmail);
      } else if (config.email?.mailer) {
        const mailer = new MailerService(config.email.mailer, config.templateStore);
        await mailer.sendEmailChanged(oldEmail, newEmail);
      }
      publishRouterEvent(eventBus, AuthEventNames.USER_EMAIL_CHANGED, req, {
        userId: user.id,
        data: { oldEmail, newEmail },
      });
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /magic-link/send
  // Supports two modes:
  //   mode='login'  (default) — passwordless direct login; body: { email, emailLang? }
  //   mode='2fa'             — second factor after password login; body: { tempToken, emailLang? }
  //     The user's email is derived from the tempToken; a magic link is sent to that address.
  router.post('/magic-link/send', ...rl, async (req: Request, res: Response) => {
    try {
      const { email, emailLang, mode, tempToken } = req.body as {
        email?: string;
        emailLang?: string;
        mode?: 'login' | '2fa';
        tempToken?: string;
      };

      if (mode === '2fa') {
        if (!tempToken) {
          res.status(400).json({ error: 'tempToken is required for 2FA mode', code: 'TEMP_TOKEN_REQUIRED' });
          return;
        }
        let payload: ReturnType<typeof tokenService.verifyTempToken>;
        try {
          payload = tokenService.verifyTempToken(tempToken, config);
        } catch {
          res.status(401).json({ error: 'Invalid or expired temp token', code: 'INVALID_TEMP_TOKEN' });
          return;
        }
        const user = await userStore.findById(payload.sub);
        if (!user) {
          res.status(404).json({ error: 'User not found' });
          return;
        }
        await magicLinkStrategy.sendMagicLink(user.email, userStore, config, emailLang, buildUiLink(resolveSiteUrl(req, config, allowedOrigins), '', config, options));
        res.json({ success: true });
        return;
      }

      // mode='login' (default)
      if (!email) {
        res.status(400).json({ error: 'email is required' });
        return;
      }
      await magicLinkStrategy.sendMagicLink(email, userStore, config, emailLang, buildUiLink(resolveSiteUrl(req, config, allowedOrigins), '', config, options));
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /magic-link/verify
  // Supports two modes:
  //   mode='login'  (default) — direct passwordless login; body: { token }
  //   mode='2fa'             — second factor; body: { token, tempToken }
  //     Both the magic-link token and the tempToken must be valid.
  router.post('/magic-link/verify', ...rl, async (req: Request, res: Response) => {
    try {
      const { token, mode, tempToken } = req.body as {
        token: string;
        mode?: 'login' | '2fa';
        tempToken?: string;
      };

      if (mode === '2fa') {
        if (!tempToken) {
          res.status(400).json({ error: 'tempToken is required for 2FA mode', code: 'TEMP_TOKEN_REQUIRED' });
          return;
        }
        // Validate the temp token (proves the user already completed step 1 — password)
        let tempPayload: ReturnType<typeof tokenService.verifyTempToken>;
        try {
          tempPayload = tokenService.verifyTempToken(tempToken, config);
        } catch {
          res.status(401).json({ error: 'Invalid or expired temp token', code: 'INVALID_TEMP_TOKEN' });
          return;
        }
        // Verify the magic-link token
        const user = await magicLinkStrategy.verify(token, userStore);
        // Ensure the magic link belongs to the same user identified by the temp token
        if (user.id !== tempPayload.sub) {
          res.status(401).json({ error: 'Token mismatch', code: 'TOKEN_MISMATCH' });
          return;
        }
        const { sessionId } = await issueTokens(req, res, user, config, options, userStore);
        publishRouterEvent(eventBus, AuthEventNames.AUTH_LOGIN_SUCCESS, req, {
          userId: user.id,
          sessionId,
          data: { method: 'magic-link' },
        });
        return;
      }

      // mode='login' (default) — passwordless direct login
      const user = await magicLinkStrategy.verify(token, userStore);
      // First magic-link login counts as email verification
      if (!user.isEmailVerified && userStore.updateEmailVerified) {
        await userStore.updateEmailVerified(user.id, true);
      }
      const { sessionId } = await issueTokens(req, res, user, config, options, userStore);
      publishRouterEvent(eventBus, AuthEventNames.AUTH_LOGIN_SUCCESS, req, {
        userId: user.id,
        sessionId,
        data: { method: 'magic-link' },
      });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /sms/send
  // Supports two modes:
  //   mode='login'  (default) — direct SMS login; body: { userId } OR { email }
  //     The user is looked up by userId or email; their stored phoneNumber is used.
  //   mode='2fa'             — second factor; body: { tempToken }
  //     The user is identified by the tempToken from step 1 (password).
  router.post('/sms/send', ...rl, async (req: Request, res: Response) => {
    try {
      if (!config.sms) {
        res.status(500).json({ error: 'SMS is not configured', code: 'SMS_NOT_CONFIGURED' });
        return;
      }

      const { userId, email, mode, tempToken } = req.body as {
        userId?: string;
        email?: string;
        mode?: 'login' | '2fa';
        tempToken?: string;
      };

      let resolvedUserId: string | undefined;

      if (mode === '2fa') {
        if (!tempToken) {
          res.status(400).json({ error: 'tempToken is required for 2FA mode', code: 'TEMP_TOKEN_REQUIRED' });
          return;
        }
        try {
          const payload = tokenService.verifyTempToken(tempToken, config);
          resolvedUserId = payload.sub;
        } catch {
          res.status(401).json({ error: 'Invalid or expired temp token', code: 'INVALID_TEMP_TOKEN' });
          return;
        }
      } else {
        // mode='login' — look up user by userId or email
        if (email) {
          const userByEmail = await userStore.findByEmail(email);
          if (!userByEmail) {
            // Don't reveal whether email exists
            res.json({ success: true });
            return;
          }
          resolvedUserId = userByEmail.id;
        } else if (userId) {
          resolvedUserId = userId;
        } else {
          res.status(400).json({ error: 'userId or email is required' });
          return;
        }
      }

      const user = await userStore.findById(resolvedUserId!);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      if (!user.phoneNumber) {
        res.status(400).json({ error: 'User does not have a phone number configured', code: 'PHONE_NOT_SET' });
        return;
      }
      await smsStrategy.sendCode(user.phoneNumber, user.id, userStore, config);
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // POST /sms/verify
  // Supports two modes:
  //   mode='login'  (default) — direct login; body: { userId, code }
  //     Verifies the SMS code and issues full JWT tokens.
  //   mode='2fa'             — second factor; body: { tempToken, code }
  //     Validates the tempToken (step 1 — password) and the SMS code, then issues full tokens.
  router.post('/sms/verify', ...rl, async (req: Request, res: Response) => {
    try {
      const { userId, code, mode, tempToken } = req.body as {
        userId?: string;
        code: string;
        mode?: 'login' | '2fa';
        tempToken?: string;
      };

      let resolvedUserId: string;

      if (mode === '2fa') {
        if (!tempToken) {
          res.status(400).json({ error: 'tempToken is required for 2FA mode', code: 'TEMP_TOKEN_REQUIRED' });
          return;
        }
        try {
          const payload = tokenService.verifyTempToken(tempToken, config);
          resolvedUserId = payload.sub;
        } catch {
          res.status(401).json({ error: 'Invalid or expired temp token', code: 'INVALID_TEMP_TOKEN' });
          return;
        }
      } else {
        if (!userId) {
          res.status(400).json({ error: 'userId is required' });
          return;
        }
        resolvedUserId = userId;
      }

      const valid = await smsStrategy.verify(resolvedUserId, code, userStore);
      if (!valid) {
        res.status(401).json({ error: 'Invalid or expired SMS code' });
        return;
      }
      const user = await userStore.findById(resolvedUserId);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      const { sessionId } = await issueTokens(req, res, user, config, options, userStore);
      publishRouterEvent(eventBus, AuthEventNames.AUTH_LOGIN_SUCCESS, req, {
        userId: user.id,
        sessionId,
        data: { method: 'sms' },
      });
    } catch (err) {
      handleError(res, err);
    }
  });

  /**
   * Shared handler for completing an OAuth login.
   * After the user is resolved by the strategy, this checks for a 2FA
   * requirement and either issues tokens or redirects to the 2FA challenge.
   * `redirectTo` is the pre-validated origin to send the browser back to
   * (resolved from the OAuth state parameter by `resolveOAuthRedirect`).
   */
  async function handleOAuthLogin(req: Request, res: Response, user: BaseUser, authConfig: AuthConfig, redirectTo: string): Promise<void> {
    const hasTotpEnabled = !!(user.isTotpEnabled && user.totpSecret);
    const requires2fa = hasTotpEnabled || !!user.require2FA;
    if (requires2fa) {
      const available2faMethods: string[] = [];
      if (hasTotpEnabled) available2faMethods.push('totp');
      if (user.phoneNumber && authConfig.sms) available2faMethods.push('sms');
      if (authConfig.email?.sendMagicLink || authConfig.email?.mailer) available2faMethods.push('magic-link');
      const tempToken = tokenService.generateTempToken(buildPayload(user, authConfig), authConfig);
      // For GET-based OAuth redirects always redirect to the 2FA page
      const methods = available2faMethods.join(',');
      res.redirect(`${redirectTo}/auth/2fa?tempToken=${encodeURIComponent(tempToken)}&methods=${encodeURIComponent(methods)}`);
      return;
    }
    await userStore.updateLastLogin(user.id);
    const { sessionId } = await issueTokens(req, res, user, authConfig, options, userStore, redirectTo || '/');
    publishRouterEvent(eventBus, AuthEventNames.AUTH_OAUTH_SUCCESS, req, {
      userId: user.id,
      sessionId,
      data: { provider: user.loginProvider ?? 'oauth', redirectTo },
    });
  }

  // OAuth Google
  if (options.googleStrategy) {
    const googleStrategy = options.googleStrategy;
    router.get('/oauth/google', ...rl, (req: Request, res: Response) => {
      const nonce = tokenService.generateSecureToken(16);
      const resolved = resolveSiteUrl(req, config, allowedOrigins);
      const returnPath = typeof req.query['return_path'] === 'string' ? req.query['return_path'] as string : undefined;
      const state = resolved ? encodeOAuthState(nonce, resolved, returnPath) : nonce;
      const url = googleStrategy.getAuthorizationUrl(state);
      res.redirect(url);
    });
    router.get('/oauth/google/callback', ...rl, async (req: Request, res: Response) => {
      try {
        const { code, state } = req.query as { code: string; state?: string };
        const redirectTo = resolveOAuthRedirect(state, config, allowedOrigins);
        const user = await googleStrategy.handleCallback(code, state);
        // Link the account if linkedAccountsStore is configured
        if (options.linkedAccountsStore && user.providerAccountId) {
          await options.linkedAccountsStore.linkAccount(user.id, {
            provider: 'google',
            providerAccountId: user.providerAccountId,
            email: user.email,
            linkedAt: new Date(),
          }).catch((e: unknown) => { console.error('[node-auth] linkAccount error (google):', e); });
        }
        user.loginProvider = user.loginProvider ?? 'google';
        await handleOAuthLogin(req, res, user, config, redirectTo);
      } catch (err) {
        if (err instanceof AuthError && err.code === 'OAUTH_ACCOUNT_CONFLICT') {
          publishRouterEvent(eventBus, AuthEventNames.AUTH_OAUTH_CONFLICT, req, {
            data: oauthConflictEventData('google', err.data),
          });
          const siteUrl = resolveOAuthRedirect((req.query as { state?: string }).state, config, allowedOrigins);
          const { email, providerAccountId } = (err.data ?? {}) as { email?: string; providerAccountId?: string };
          if (options.pendingLinkStore && email && providerAccountId) {
            await options.pendingLinkStore.stash(email, 'google', providerAccountId).catch((e: unknown) => { console.error('[node-auth] pendingLinkStore.stash error (google):', e); });
          }
          const emailParam = email ? `&email=${encodeURIComponent(email)}` : '';
          const paramStr = `?provider=google&code=OAUTH_ACCOUNT_CONFLICT${emailParam}`;
          res.redirect(buildUiLink(siteUrl, `/account-conflict${paramStr}`, config, options));
          return;
        }
        handleError(res, err);
      }
    });
  } else {
    router.get('/oauth/google', (_req, res) => res.status(404).json({ error: 'Google OAuth not configured' }));
    router.get('/oauth/google/callback', (_req, res) => res.status(404).json({ error: 'Google OAuth not configured' }));
  }

  // OAuth GitHub
  if (options.githubStrategy) {
    const githubStrategy = options.githubStrategy;
    router.get('/oauth/github', ...rl, (req: Request, res: Response) => {
      const nonce = tokenService.generateSecureToken(16);
      const resolved = resolveSiteUrl(req, config, allowedOrigins);
      const returnPath = typeof req.query['return_path'] === 'string' ? req.query['return_path'] as string : undefined;
      const state = resolved ? encodeOAuthState(nonce, resolved, returnPath) : nonce;
      const url = githubStrategy.getAuthorizationUrl(state);
      res.redirect(url);
    });
    router.get('/oauth/github/callback', ...rl, async (req: Request, res: Response) => {
      try {
        const { code, state } = req.query as { code: string; state?: string };
        const redirectTo = resolveOAuthRedirect(state, config, allowedOrigins);
        const user = await githubStrategy.handleCallback(code, state);
        // Link the account if linkedAccountsStore is configured
        if (options.linkedAccountsStore && user.providerAccountId) {
          await options.linkedAccountsStore.linkAccount(user.id, {
            provider: 'github',
            providerAccountId: user.providerAccountId,
            email: user.email,
            linkedAt: new Date(),
          }).catch((e: unknown) => { console.error('[node-auth] linkAccount error (github):', e); });
        }
        user.loginProvider = user.loginProvider ?? 'github';
        await handleOAuthLogin(req, res, user, config, redirectTo);
      } catch (err) {
        if (err instanceof AuthError && err.code === 'OAUTH_ACCOUNT_CONFLICT') {
          publishRouterEvent(eventBus, AuthEventNames.AUTH_OAUTH_CONFLICT, req, {
            data: oauthConflictEventData('github', err.data),
          });
          const siteUrl = resolveOAuthRedirect((req.query as { state?: string }).state, config, allowedOrigins);
          const { email, providerAccountId } = (err.data ?? {}) as { email?: string; providerAccountId?: string };
          if (options.pendingLinkStore && email && providerAccountId) {
            await options.pendingLinkStore.stash(email, 'github', providerAccountId).catch((e: unknown) => { console.error('[node-auth] pendingLinkStore.stash error (github):', e); });
          }
          const emailParam = email ? `&email=${encodeURIComponent(email)}` : '';
          const paramStr = `?provider=github&code=OAUTH_ACCOUNT_CONFLICT${emailParam}`;
          res.redirect(buildUiLink(siteUrl, `/account-conflict${paramStr}`, config, options));
          return;
        }
        handleError(res, err);
      }
    });
  } else {
    router.get('/oauth/github', (_req, res) => res.status(404).json({ error: 'GitHub OAuth not configured' }));
    router.get('/oauth/github/callback', (_req, res) => res.status(404).json({ error: 'GitHub OAuth not configured' }));
  }

  // Generic OAuth strategies (any provider beyond Google/GitHub)
  if (options.oauthStrategies) {
    for (const strategy of options.oauthStrategies) {
      const s = strategy;
      router.get(`/oauth/${s.name}`, ...rl, (req: Request, res: Response) => {
        const nonce = tokenService.generateSecureToken(16);
        const resolved = resolveSiteUrl(req, config, allowedOrigins);
        const returnPath = typeof req.query['return_path'] === 'string' ? req.query['return_path'] as string : undefined;
        const state = resolved ? encodeOAuthState(nonce, resolved, returnPath) : nonce;
        res.redirect(s.getAuthorizationUrl(state));
      });
      router.get(`/oauth/${s.name}/callback`, ...rl, async (req: Request, res: Response) => {
        try {
          const { code, state } = req.query as { code: string; state?: string };
          const redirectTo = resolveOAuthRedirect(state, config, allowedOrigins);
          const user = await s.handleCallback(code, state);
          // Link the account if linkedAccountsStore is configured
          if (options.linkedAccountsStore && user.providerAccountId) {
            await options.linkedAccountsStore.linkAccount(user.id, {
              provider: s.name,
              providerAccountId: user.providerAccountId,
              email: user.email,
              linkedAt: new Date(),
            }).catch((e: unknown) => { console.error(`[node-auth] linkAccount error (${s.name}):`, e); });
          }
          user.loginProvider = user.loginProvider ?? s.name;
          await handleOAuthLogin(req, res, user, config, redirectTo);
        } catch (err) {
          if (err instanceof AuthError && err.code === 'OAUTH_ACCOUNT_CONFLICT') {
            publishRouterEvent(eventBus, AuthEventNames.AUTH_OAUTH_CONFLICT, req, {
              data: oauthConflictEventData(s.name, err.data),
            });
            const siteUrl = resolveOAuthRedirect((req.query as { state?: string }).state, config, allowedOrigins);
            const { email, providerAccountId } = (err.data ?? {}) as { email?: string; providerAccountId?: string };
            if (options.pendingLinkStore && email && providerAccountId) {
              await options.pendingLinkStore.stash(email, s.name, providerAccountId).catch((e: unknown) => { console.error(`[node-auth] pendingLinkStore.stash error (${s.name}):`, e); });
            }
            const emailParam = email ? `&email=${encodeURIComponent(email)}` : '';
            const paramStr = `?provider=${encodeURIComponent(s.name)}&code=OAUTH_ACCOUNT_CONFLICT${emailParam}`;
            res.redirect(buildUiLink(siteUrl, `/account-conflict${paramStr}`, config, options));
            return;
          }
          handleError(res, err);
        }
      });
    }
  }

  // GET /linked-accounts — list OAuth accounts linked to the authenticated user
  if (options.linkedAccountsStore) {
    const linkedAccountsStore = options.linkedAccountsStore;
    router.get('/linked-accounts', ...rl, authMiddleware, async (req: Request, res: Response) => {
      try {
        const accounts = await linkedAccountsStore.getLinkedAccounts(req.user!.sub);
        res.json({ linkedAccounts: accounts });
      } catch (err) {
        handleError(res, err);
      }
    });

    // DELETE /linked-accounts/:provider/:providerAccountId — unlink a provider account
    router.delete('/linked-accounts/:provider/:providerAccountId', ...rl, authMiddleware, async (req: Request, res: Response) => {
      try {
        const { provider, providerAccountId } = req.params as { provider: string; providerAccountId: string };
        await linkedAccountsStore.unlinkAccount(req.user!.sub, provider, providerAccountId);
        res.json({ success: true });
      } catch (err) {
        handleError(res, err);
      }
    });

    // POST /link-request — support both authenticated and unauthenticated conflict-linking
    // Body: { email: string, provider?: string, emailLang?: string }
    //   email    — the address to link (becomes providerAccountId)
    //   provider — provider name to record (defaults to 'email')
    router.post('/link-request', ...rl, async (req: Request, res: Response) => {
      try {
        if (!userStore.updateAccountLinkToken) {
          res.status(500).json({ error: 'UserStore does not implement updateAccountLinkToken', code: 'NOT_IMPLEMENTED' });
          return;
        }
        // Same credential rule as auth.middleware(): an Authorization: Bearer
        // header is the credential, and then the accessToken cookie is ignored.
        const authHeader = req.headers['authorization'];
        const bearerToken = (authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : '') || null;
        // Manual CSRF check (since we removed authMiddleware which usually handles it).
        // Like the middleware, it applies to requests without a bearer
        // credential: cookie-authenticated and anonymous (conflict-linking) calls.
        if (config.csrf?.enabled && !bearerToken) {
          const cookie = tokenService.extractTokenFromCookie(req, 'csrf-token');
          const header = req.headers['x-csrf-token'];
          if (!cookie || !header || cookie !== header) {
            throw new AuthError('CSRF validation failed', 'CSRF_INVALID', 403);
          }
        }
        const { email, provider = 'email', emailLang } = req.body as { email: string; provider?: string; emailLang?: string };
        if (!email) {
          throw new AuthError('email is required', 'EMAIL_REQUIRED', 400);
        }
        let userId: string | null = null;
        // Try to get userId from existing session (standard linking)
        const rawToken = bearerToken ?? tokenService.extractTokenFromCookie(req, 'accessToken');
        if (rawToken) {
          try {
            const payload = tokenService.verifyAccessToken(rawToken, config);
            userId = payload.sub;
          } catch {
            // Token invalid/expired, proceed to check pending links
          }
        }
        // Fallback: check pending link store (conflict linking flow)
        if (!userId) {
          if (!options.pendingLinkStore) {
            throw new AuthError('Authentication required', 'UNAUTHORIZED', 401);
          }
          const pending = await options.pendingLinkStore.retrieve(email, provider);
          if (!pending) {
            throw new AuthError('Authentication required or no pending link found', 'UNAUTHORIZED', 401);
          }
          const user = await userStore.findByEmail(email);
          if (!user) throw new AuthError('Target user not found', 'USER_NOT_FOUND', 404);
          userId = user.id;
        }
        const tokenCode = tokenService.generateSecureToken();
        const expiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
        await userStore.updateAccountLinkToken(userId, email, provider, tokenCode, expiry);
        const siteUrl = resolveSiteUrl(req, config, allowedOrigins);
        const link = buildUiLink(siteUrl, `/link-verify?token=${tokenCode}`, config, options);
        if (config.email?.sendVerificationEmail) {
          await config.email.sendVerificationEmail(email, tokenCode, link, emailLang);
        } else if (config.email?.mailer) {
          const mailer = new MailerService(config.email.mailer, config.templateStore);
          await mailer.sendVerificationEmail(email, tokenCode, link, emailLang);
        }
        res.json({ success: true });
      } catch (err) {
        handleError(res, err);
      }
    });

    // POST /link-verify — complete an account-link flow initiated by /link-request
    // Body: { token: string, loginAfterLinking?: boolean }
    router.post('/link-verify', ...rl, async (req: Request, res: Response) => {
      try {
        if (!userStore.findByAccountLinkToken || !userStore.updateAccountLinkToken) {
          res.status(500).json({ error: 'UserStore does not implement account-link methods', code: 'NOT_IMPLEMENTED' });
          return;
        }
        const { token, loginAfterLinking } = req.body as { token: string; loginAfterLinking?: boolean };
        if (!token) {
          res.status(400).json({ error: 'token is required', code: 'TOKEN_REQUIRED' });
          return;
        }
        const user = await userStore.findByAccountLinkToken(token);
        if (!user || user.accountLinkToken !== token) {
          res.status(400).json({ error: 'Invalid account-link token', code: 'INVALID_LINK_TOKEN' });
          return;
        }
        if (user.accountLinkTokenExpiry && new Date() > user.accountLinkTokenExpiry) {
          res.status(400).json({ error: 'Account-link token has expired', code: 'LINK_TOKEN_EXPIRED' });
          return;
        }
        if (!user.accountLinkPendingEmail) {
          res.status(400).json({ error: 'No pending email found for this link token', code: 'INVALID_STATE' });
          return;
        }
        const email = user.accountLinkPendingEmail;
        const provider = user.accountLinkPendingProvider ?? 'email';
        // Determine the providerAccountId: prefer stashed OAuth value when available
        let providerAccountId = email;
        if (options.pendingLinkStore) {
          const pending = await options.pendingLinkStore.retrieve(email, provider);
          if (pending) {
            providerAccountId = pending.providerAccountId;
            await options.pendingLinkStore.remove(email, provider).catch((e: unknown) => { console.error('[node-auth] pendingLinkStore.remove error:', e); });
          }
        }
        await linkedAccountsStore.linkAccount(user.id, {
          provider,
          providerAccountId,
          email,
          linkedAt: new Date(),
        });
        await userStore.updateAccountLinkToken(user.id, null, null, null, null);
        if (loginAfterLinking) {
          await issueTokens(req, res, user, config, options, userStore);
          return;
        }
        res.json({ success: true });
      } catch (err) {
        handleError(res, err);
      }
    });
  }

  // DELETE /account — authenticated user self-deletes their account (full cleanup)
  router.delete('/account', ...rl, authMiddleware, async (req: Request, res: Response) => {
    try {
      const userId = req.user!.sub;
      // 1. Revoke all active sessions
      if (options.sessionStore?.revokeAllSessionsForUser) {
        await options.sessionStore.revokeAllSessionsForUser(userId);
      } else {
        // Fallback: clear the refresh token stored on the user record
        await userStore.updateRefreshToken(userId, null, null);
      }
      // 2. Remove all RBAC role assignments
      if (options.rbacStore) {
        const roles = await options.rbacStore.getRolesForUser(userId);
        await Promise.all(roles.map(r => options.rbacStore!.removeRoleFromUser(userId, r)));
      }
      // 3. Remove all tenant memberships
      if (options.tenantStore?.getTenantsForUser) {
        const tenants = await options.tenantStore.getTenantsForUser(userId);
        await Promise.all(tenants.map(t => options.tenantStore!.disassociateUserFromTenant(userId, t.id)));
      }
      // 4. Clear user metadata
      if (options.metadataStore?.clearMetadata) {
        await options.metadataStore.clearMetadata(userId);
      }
      // 5. Delete the user record
      const store = userStore as unknown as Record<string, unknown>;
      if (typeof store['deleteUser'] === 'function') {
        await (store['deleteUser'] as (id: string) => Promise<void>)(userId);
      } else {
        // Store doesn't support hard-delete — at minimum clear sensitive fields
        await userStore.updateRefreshToken(userId, null, null);
        await userStore.updateResetToken(userId, null, null);
      }
      tokenService.clearTokenCookies(res, config);
      publishRouterEvent(eventBus, AuthEventNames.USER_DELETED, req, {
        userId,
      });
      res.json({ success: true });
    } catch (err) {
      handleError(res, err);
    }
  });

  // ── Vanilla UI (HTML/JS/CSS) ──────────────────────────────────────────────
  if (config.ui?.enabled) {
    router.use('/ui', buildUiRouter({
      uiAssetsDir: options.uiAssetsDir,
      uploadDir: options.uploadDir,
      settingsStore: options.settingsStore,
      templateStore: config.templateStore,
      authConfig: config,
      routerOptions: { ...options, onRegister: registerHandler },
      apiPrefix: resolveApiPrefix(config, options),
    }));
  }

  // ── Swagger / OpenAPI (optional) ───────────────────────────────────────────
  const swaggerEnabled =
    options.swagger === true ||
    (options.swagger !== false && process.env['NODE_ENV'] !== 'production');

  if (swaggerEnabled) {
    const specBasePath = options.swaggerBasePath ?? resolveApiPrefix(config, options);
    router.get('/openapi.json', (_req: Request, res: Response) => {
      const spec = buildAuthOpenApiSpec(
        {
          hasRegister: !!registerHandler,
          hasSessionsCleanup: !!options.sessionStore?.deleteExpiredSessions,
          hasLinkedAccounts: !!options.linkedAccountsStore,
          hasGoogleOAuth: !!options.googleStrategy,
          hasGithubOAuth: !!options.githubStrategy,
          oauthProviders: (options.oauthStrategies ?? []).map((s) => s.name),
        },
        specBasePath,
      );
      res.setHeader('Content-Type', 'application/json');
      res.json(spec);
    });

    router.get('/docs', (_req: Request, res: Response) => {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(buildSwaggerUiHtml(`${specBasePath}/openapi.json`));
    });
  }

  // Global error handler — catches any unhandled errors thrown by route handlers
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  router.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    console.error('[node-auth] Unhandled router error:', err);
    if (err instanceof AuthError) {
      res.status(err.statusCode).json({ error: err.message, code: err.code });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
}
