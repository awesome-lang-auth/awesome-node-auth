import { Router, Request, Response, RequestHandler, json as expressJson } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { IUserStore } from '../interfaces/user-store.interface';
import { ISessionStore } from '../interfaces/session-store.interface';
import { IRolesPermissionsStore } from '../interfaces/roles-permissions-store.interface';
import { ITenantStore } from '../interfaces/tenant-store.interface';
import { IUserMetadataStore } from '../interfaces/user-metadata-store.interface';
import { ISettingsStore, AuthSettings } from '../interfaces/settings-store.interface';
import { ILinkedAccountsStore } from '../interfaces/linked-accounts-store.interface';
import { IApiKeyStore } from '../interfaces/api-key-store.interface';
import { IWebhookStore } from '../interfaces/webhook-store.interface';
import { ITemplateStore } from '../interfaces/template-store.interface';
import { ApiKeyService } from '../services/api-key.service';
import { TOKEN_PURPOSE_CLAIM, TEMP_TOKEN_PURPOSE, ADMIN_TOKEN_PURPOSE } from '../services/token.service';
import { ActionRegistry } from '../tools/webhook-action';
import { buildAdminOpenApiSpec, buildSwaggerUiHtml } from './openapi';
import { BaseUser } from '../models/user.model';
import { AuthEventBus } from '../events/auth-event-bus';
import { AuthEventNames } from '../events/auth-event-names';
import { publishRequestEvent as publishAdminEvent } from './router-events';

/*
 * Admin login lives here (typically /auth/admin/login when mounted via
 * AuthConfigurator.buildAllRouters). End-user login lives in ui.router.ts at
 * /auth/ui/login. Keep these two audiences distinct in code and docs.
 */

export type AuthorizedAdminUser = BaseUser & { roles: string[] };

/**
 * Policy that controls who may access the Admin UI and REST API.
 *
 * | Value | Description |
 * |-------|-------------|
 * | `'first-user'` | Only the first registered user (lowest-ID) is granted access. Ideal for single-owner setups. |
 * | `'is-admin-flag'` | Only users with `BaseUser.isAdmin === true` are granted access. |
 * | `'open'` | No restriction — all authenticated users are granted access.  Use only behind a VPN or IP allow-list. |
 * | `(user, rbacStore?) => Promise<boolean>` | Custom async predicate.  Return `true` to grant access. |
 *
 * When `accessPolicy` is set the guard validates the request JWT (using
 * `jwtSecret`) and redirects unauthenticated browsers to the app login page
 * (`/auth/ui/login?redirect=<adminPath>`).
 *
 * @since 1.8.0
 */
export type AdminAccessPolicy =
  | 'first-user'
  | 'is-admin-flag'
  | 'open'
  | ((user: AuthorizedAdminUser, rbacStore?: IRolesPermissionsStore) => boolean | Promise<boolean>);

export interface AdminOptions {
  /**
   * Secret token required to access all admin endpoints.
   * Pass as a Bearer token: `Authorization: Bearer <adminSecret>`
   * The HTML UI presents a login form that stores the token in sessionStorage.
   *
   * Must be non-empty: without `accessPolicy`, an empty string counts as no
   * secret, and the admin routes are mounted unprotected (with a stderr WARNING).
   *
   * @deprecated Use `accessPolicy` + `jwtSecret` instead (v1.8.0+).
   *   `adminSecret` will be removed in a future major version.
   *   It is still fully functional for backward compatibility.
   */
  adminSecret?: string;

  /**
   * Access control policy that governs who may use the Admin UI and API.
   *
   * When set, the guard validates the request JWT (`Authorization: Bearer <token>`
   * or the `accessToken` cookie).  A request without a valid session gets
   * `401`, except a browser request for the HTML panel (`GET <adminPath>/`),
   * which is redirected to `loginPath` when it is set and otherwise shows the
   * panel's built-in sign-in form.
   *
   * Requires `jwtSecret` to be set when using any policy other than `'open'`.
   *
   * @since 1.8.0
   */
  accessPolicy?: AdminAccessPolicy;

  /**
   * JWT secret used to verify the access token when `accessPolicy` is set.
   *
   * Must match `AuthConfig.accessTokenSecret` (the same secret used to sign
   * tokens during login).  Not required when `accessPolicy` is `'open'`.
   *
   * @since 1.8.0
   */
  jwtSecret?: string;

  /** Optional session store — enables the Sessions tab in the admin UI. */
  sessionStore?: ISessionStore;
  /** Optional RBAC store — enables the Roles & Permissions tab and user-role assignment. */
  rbacStore?: IRolesPermissionsStore;
  /** Optional tenant store — enables the Tenants tab and user-tenant assignment. */
  tenantStore?: ITenantStore;
  /**
   * Optional user-metadata store — enables the Metadata section in the user detail
   * panel (view and edit arbitrary per-user key/value data).
   */
  userMetadataStore?: IUserMetadataStore;
  /** Optional settings store — enables the ⚙️ Control tab in the admin UI. */
  settingsStore?: ISettingsStore;
  /**
   * Optional linked-accounts store — enables the Linked Accounts column in the
   * users table and the Linked Accounts section in the user detail panel.
   */
  linkedAccountsStore?: ILinkedAccountsStore;

  /**
   * Optional prefix for the authentication cookies (e.g. `__Host-` or `__Secure-`).
   * If provided, the guard will look for `${cookiePrefix}accessToken`.
   * If not provided, it will try the default variants.
   *
   * @since 1.8.1
   */
  cookiePrefix?: string;

  /**
   * Optional root user for the Admin UI.
   * Useful for bootstrapping or in environments without local users.
   *
   * @since 1.8.1
   */
  rootUser?: {
    email: string;
    /** Bcrypt-hashed password. */
    passwordHash: string;
  };

  /**
   * Optional API Key store — enables the 🔑 API Keys tab in the admin UI.
   * Requires `IApiKeyStore.listAll` for listing and optionally `delete` for hard deletion.
   */
  apiKeyStore?: IApiKeyStore;

  /**
   * Optional webhook store — enables the 🔗 Webhooks tab in the admin UI.
   * Requires `IWebhookStore.listAll` for listing and optionally `add`/`remove`/`update`
   * for full management.
   */
  webhookStore?: IWebhookStore;
  /** Optional template store — enables the Email & UI tab in the admin UI. */
  templateStore?: ITemplateStore;
  /** Optional directory for uploaded assets (e.g. logos). */
  uploadDir?: string;
  /**
   * Public base URL where uploaded assets (stored in `uploadDir`) are served
   * by the UI router.  This must match where `buildUiRouter` is mounted plus
   * `/assets/uploads`, e.g. `'/auth/ui/assets/uploads'` when the UI router is
   * mounted at `'/auth/ui'`.
   *
   * When set, the upload endpoints return a ready-to-use browser URL:
   *   `<uploadBaseUrl>/<filename>`
   *
   * When omitted the endpoints still return the filename so callers can
   * construct the URL themselves.
   *
   * @example '/auth/ui/assets/uploads'
   */
  uploadBaseUrl?: string;

  /**
   * Optional auth event bus. When provided, admin-side auth and RBAC events are
   * published automatically.
   */
  eventBus?: AuthEventBus;

  /**
   * The base path where the main auth router is mounted.
   * Used to automatically compute uploadBaseUrl if not provided.
   * @default '/auth'
   */
  apiPrefix?: string;

  /**
   * Enable Swagger UI (`GET /api/openapi.json`, `GET /api/docs`) on the admin router.
   *
   * - `true`   — always enabled
   * - `false`  — always disabled
   * - `'auto'` (default) — enabled when `NODE_ENV` is **not** `'production'`
   *
   * @default 'auto'
   */
  swagger?: boolean | 'auto';

  /**
   * Base path where the admin router is mounted.
   * Used to build accurate path entries in the OpenAPI spec.
   *
   * @default '/admin'
   */
  swaggerBasePath?: string;

  /**
   * Optional custom login path to redirect unauthenticated browser requests
   * for the HTML panel to.  If not provided, the panel serves its own internal
   * login form as a fallback.  The REST API answers `401` either way.
   *
   * @example '/login'
   * @since 1.8.0
   */
  loginPath?: string;

  /**
   * Suppress startup logs from the admin router.
   */
  silent?: boolean;

  /**
   * Optional rate limiter middleware applied to sensitive admin mutations.
   */
  rateLimiter?: RequestHandler;
}

type AdminWritableUserStore = IUserStore & {
  update?: (userId: string, patch: Partial<BaseUser>) => Promise<void>;
};

/**
 * Id of the admin the `accessPolicy` guard authorized for this request (the
 * actor of a privilege change).  Only the policy guard sets it, in
 * `res.locals.adminActorId`; `req.user` is not read, because under
 * `adminSecret` or `'open'` it can only come from an upstream middleware.
 */
function adminActorId(res: Response): string | undefined {
  const actorId: unknown = res.locals['adminActorId'];
  return typeof actorId === 'string' ? actorId : undefined;
}

/**
 * Refuse a request whose body is not `application/json` with `415`.
 *
 * For admin mutations that need no body field to grant a privilege (such as
 * `POST /users/:id/promote`): an HTML form or a `text/plain` POST is a CORS
 * "simple" request that a browser sends cross-site without a preflight, an
 * `application/json` one is not.  Every route that grants admin access this
 * way must use this check.
 */
const requireJsonBody: RequestHandler = (req, res, next) => {
  if (!req.is('application/json')) {
    res.status(415).json({ error: 'Content-Type must be application/json' });
    return;
  }
  next();
};

/** Legacy guard — still used when `adminSecret` is provided. */
function adminAuth(secret: string): RequestHandler {
  return (req: Request, res: Response, next) => {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    const token = auth.slice(7);
    if (token !== secret) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }
    next();
  };
}

/**
 * Compute the cookie name for the admin session token, mirroring the same
 * `__Host-` / `__Secure-` prefix logic that TokenService uses for regular
 * auth tokens.  This ensures the guard reads exactly the cookie that was
 * written by the admin login handler — and vice-versa — even on HTTPS.
 *
 * Rules (identical to TokenService.getCookieName):
 *   - HTTP  (isSecure=false) → plain name, e.g. `accessToken`
 *   - HTTPS, path=/, no domain → `__Host-accessToken`  (most secure)
 *   - HTTPS, custom path/domain → `__Secure-accessToken`
 *
 * An explicit `cookiePrefix` from AdminOptions always overrides the prefix.
 */
function resolveAdminCookieName(
  isSecure: boolean,
  cookiePrefix?: string,
  cookiePath?: string,
  cookieDomain?: string,
): string {
  if (cookiePrefix !== undefined) {
    // Explicit override — respect whatever the caller configured.
    return cookiePrefix + 'accessToken';
  }
  if (!isSecure) return 'accessToken';
  const isPathRoot = !cookiePath || cookiePath === '/';
  if (isPathRoot && !cookieDomain) return '__Host-accessToken';
  return '__Secure-accessToken';
}

/**
 * Enforce the browser requirements for a `__Host-` prefixed cookie:
 *  - Secure flag must be set
 *  - Path must be `/`
 *  - Domain attribute must be absent
 *
 * Returns a new object (shallow copy of `opts`) with the required attributes
 * applied when the cookie name starts with `__Host-`, leaving `opts` untouched.
 */
function applyHostCookieRequirements(cookieName: string, opts: Record<string, unknown>): Record<string, unknown> {
  if (!cookieName.startsWith('__Host-')) return opts;
  const result = { ...opts };
  result.secure = true;
  result.path = '/';
  delete result.domain;
  return result;
}

/**
 * JWT-based guard that enforces `AdminAccessPolicy`.
 *
 * A request without a valid session gets `401`.  The one exception is the
 * guard built with `loginFormFallback` for the HTML panel route: there an
 * unauthenticated browser request (`Accept: text/html`) is redirected to
 * `loginPath` when it is set, or, for a `GET`, let through with the
 * `adminNeedsAuth` marker so the panel renders its built-in sign-in form.
 * No other route may use that guard: its handlers do not check the marker.
 */
function buildPolicyGuard(
  policy: AdminAccessPolicy,
  userStore: IUserStore,
  jwtSecret: string | undefined,
  rbacStore?: IRolesPermissionsStore,
  loginPath?: string,
  cookiePrefix?: string,
  loginFormFallback = false,
): RequestHandler {
  return async (req: Request, res: Response, next) => {
    // 'open' — no auth required at all
    if (policy === 'open') { next(); return; }

    // ── 1. Extract and verify JWT ──────────────────────────────────────────
    let payload: Record<string, unknown> | null = null;

    if (jwtSecret) {
      // Try Authorization header first, then cookie
      const bearerToken = req.headers.authorization?.startsWith('Bearer ')
        ? req.headers.authorization.slice(7)
        : undefined;

      // Prefer cookie-parser parsed cookies; fall back to raw Cookie header parsing
      // in case the app does not use cookie-parser middleware.
      let cookies = (req.cookies as Record<string, string> | undefined);
      if (!cookies) {
        const cookieHeader = req.headers.cookie ?? '';
        cookies = cookieHeader.split(';').reduce<Record<string, string>>((acc, part) => {
          const [key, ...val] = part.trim().split('=');
          if (key) acc[key.trim()] = decodeURIComponent(val.join('='));
          return acc;
        }, {});
      }
      const cookieName = cookiePrefix ? `${cookiePrefix}accessToken` : undefined;
      const cookieToken = cookieName
        ? cookies[cookieName]
        : (cookies['__Host-accessToken'] ?? cookies['__Secure-accessToken'] ?? cookies['accessToken']);

      const rawToken = bearerToken || cookieToken;

      if (rawToken) {
        try {
          payload = jwt.verify(rawToken, jwtSecret) as Record<string, unknown>;
        } catch {
          payload = null;
        }
        // The 2FA step-up token proves a password, not a session: refuse it.
        if (payload && payload[TOKEN_PURPOSE_CLAIM] === TEMP_TOKEN_PURPOSE) {
          payload = null;
        }
      }
    }

    // ── 2. Unauthenticated → 401, or (panel route only) redirect / sign-in form
    if (!payload) {
      const acceptsHtml = req.headers.accept?.includes('text/html');
      if (acceptsHtml && loginFormFallback) {
        // 1. External redirect if configured
        if (loginPath) {
          const redirectTo = encodeURIComponent(req.baseUrl + req.path);
          res.redirect(302, `${loginPath}?redirect=${redirectTo}`);
          return;
        }

        // 2. Internal fallback: let the GET request through but mark as unauthenticated
        // so the panel handler can show the built-in login form.
        if (req.method === 'GET') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (req as any).adminNeedsAuth = true;
          next();
          return;
        }

        // For non-GET requests (e.g. API) that aren't authenticated
        res.status(401).json({ error: 'Unauthorized' });
      } else {
        res.status(401).json({ error: 'Unauthorized' });
      }
      return;
    }

    // ── 3. Load the full user record ───────────────────────────────────────
    const userId = payload['sub'] as string | undefined;
    if (!userId) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    // Handle root/bootstrap override.  Only the admin console token minted by
    // POST /login may carry it: on any other token (for example one whose
    // claims come from `buildTokenPayload`) `isRoot` is ignored.
    if (payload['isRoot'] === true && payload[TOKEN_PURPOSE_CLAIM] === ADMIN_TOKEN_PURPOSE) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any).user = {
        id: userId,
        email: (payload['email'] as string) || 'root@admin',
        isAdmin: true,
        roles: ['admin'],
      } as AuthorizedAdminUser;
      res.locals['adminActorId'] = userId;
      next();
      return;
    }

    let user: BaseUser | null = null;
    try {
      user = await userStore.findById(userId);
    } catch {
      user = null;
    }

    if (!user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const roles = rbacStore ? await rbacStore.getRolesForUser(user.id).catch(() => []) : [];
    const authorizedUser: AuthorizedAdminUser = { ...user, roles };

    // ── 4. Evaluate the policy ─────────────────────────────────────────────
    let granted = false;
    try {
      if (policy === 'is-admin-flag') {
        granted = authorizedUser.isAdmin === true;
      } else if (policy === 'first-user') {
        if (typeof (userStore as unknown as { listUsers?: unknown }).listUsers === 'function') {
          const firstPage = await (userStore as IUserStore & { listUsers(limit: number, offset: number): Promise<BaseUser[]> }).listUsers(1, 0);
          granted = firstPage.length > 0 && firstPage[0].id === authorizedUser.id;
        } else {
          // If listUsers is not implemented, fall back to denying access with a clear error
          res.status(500).json({ error: 'accessPolicy: first-user requires IUserStore.listUsers to be implemented' });
          return;
        }
      } else if (typeof policy === 'function') {
        granted = await policy(authorizedUser, rbacStore);
      }
    } catch {
      granted = false;
    }

    if (!granted) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    // Store user on request for downstream handlers
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (req as any).user = authorizedUser;
    res.locals['adminActorId'] = authorizedUser.id;
    next();
  };
}

// ---------------------------------------------------------------------------
// Admin UI — static assets (admin.css / admin.js) are served from the same
// directory as the auth UI assets.  buildAdminHtml returns only a thin HTML
// shell that injects the runtime config and references those files, keeping
// the compiled router free of large embedded strings.
// ---------------------------------------------------------------------------

function buildAdminHtml(baseUrl: string, features: {
  sessions: boolean;
  roles: boolean;
  tenants: boolean;
  metadata: boolean;
  twoFAPolicy: boolean;
  control: boolean;
  linkedAccounts: boolean;
  apiKeys: boolean;
  webhooks: boolean;
  templates: boolean;
  upload: boolean;
  uploadBaseUrl: string;
  /** When true the login screen is omitted — auth is handled by the server-side guard. */
  sessionBased?: boolean;
  /** When true the login screen is forced (e.g. unauthenticated session-based access). */
  showLogin?: boolean;
  /** Path to the main auth API router (for login calls). */
  authApiPrefix?: string;
  /** Optional prefix for cookies. */
  cookiePrefix?: string;
}): string {
  // Config object injected as window.__ADMIN_CONFIG__ and read by admin.js.
  const cfg = JSON.stringify({
    base: baseUrl,
    featSessions: features.sessions,
    featRoles: features.roles,
    featTenants: features.tenants,
    featMetadata: features.metadata,
    feat2faPolicy: features.twoFAPolicy,
    featControl: features.control,
    featLinkedAccounts: features.linkedAccounts,
    featApiKeys: features.apiKeys,
    featWebhooks: features.webhooks,
    featTemplates: features.templates,
    featUpload: features.upload,
    uploadBaseUrl: features.uploadBaseUrl,
    sessionBased: !!features.sessionBased,
    authApiPrefix: features.authApiPrefix || '/auth',
    cookiePrefix: features.cookiePrefix,
  });

  const showLogin = features.showLogin || !features.sessionBased;

  // When using accessPolicy the login screen is omitted: the server-side
  // guard has already verified the session and will redirect unauthenticated
  // browsers to the app login page before this HTML is ever served.
  const loginScreen = !showLogin ? '' : `
<!-- Login screen -->
<div id="login">
  <div class="login-card">
    <h1>&#128272; awesome-node-auth</h1>
    <p>Administration panel</p>
    <div id="login-error" class="alert alert-error" style="display:none"></div>
    <div style="display:flex;flex-direction:column;gap:.75rem">
      ${features.sessionBased ? '<input type="email" id="email-input" placeholder="Email" autofocus>' : ''}
      <input type="password" id="secret-input" placeholder="${features.sessionBased ? 'Password' : 'Admin secret'}" ${features.sessionBased ? '' : 'autofocus'}>
      <button class="btn btn-primary" onclick="doLogin()">Sign in</button>
    </div>
    <p style="margin-top:.75rem;font-size:.8rem;color:#6b7280">End-user login is at <code>/auth/ui/login</code>. This is the admin panel.</p>
  </div>
</div>
`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>awesome-node-auth Admin</title>
  <link rel="stylesheet" href="${baseUrl}/assets/admin.css">
</head>
<body>
${loginScreen}
<!-- Main app -->
<div id="app">
  <div id="flash"></div>
  <header>
    <h1>&#128272; awesome-node-auth Admin</h1>
    <span id="header-meta"></span>
  </header>
  <nav id="nav">
    <button class="btn logout-btn" style="margin-left:auto;margin-top:.4rem;margin-bottom:.4rem;font-size:.75rem;padding:.25rem .75rem;background:#f3f4f6;border:1px solid #e5e7eb;border-radius:6px" onclick="doLogout()">Logout</button>
  </nav>
  <main id="main"></main>
</div>

<script>window.__ADMIN_CONFIG__ = ${cfg};</script>
<script src="${baseUrl}/assets/admin.js"></script>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Admin REST API + UI router
// ---------------------------------------------------------------------------

export function createAdminRouter(
  userStore: IUserStore,
  options: AdminOptions,
): Router {
  const router = Router();
  const eventBus = options.eventBus;
  const rateLimiter = options.rateLimiter ? [options.rateLimiter] : [];

  // Ensure request bodies are parsed even if the parent app has no global body parser.
  router.use(expressJson());

  // ── Select the appropriate authentication guard ──────────────────────────
  // Priority: accessPolicy (new) > adminSecret (legacy) > open (no auth).
  let guard: RequestHandler;
  // Guard of the HTML panel route only (see buildPolicyGuard): the one route
  // that may answer an unauthenticated browser with the sign-in form.
  let panelGuard: RequestHandler | undefined;
  let sessionBased = false;

  if (options.accessPolicy !== undefined) {
    // New session-based guard
    guard = buildPolicyGuard(
      options.accessPolicy,
      userStore,
      options.jwtSecret,
      options.rbacStore,
      options.loginPath,
      options.cookiePrefix,
    );
    panelGuard = buildPolicyGuard(
      options.accessPolicy,
      userStore,
      options.jwtSecret,
      options.rbacStore,
      options.loginPath,
      options.cookiePrefix,
      true,
    );
    sessionBased = options.accessPolicy !== 'open';
  } else if (options.adminSecret) {
    // Legacy Bearer-token guard (backward compat)
    guard = adminAuth(options.adminSecret);
  } else {
    // Neither provided — warn and default to open (developer must protect externally)
    process.stderr.write(
      '[awesome-node-auth] WARNING: createAdminRouter called without `accessPolicy` or `adminSecret`. ' +
      'Admin routes are unprotected. Set accessPolicy in production.\n',
    );
    guard = (_req, _res, next) => next();
  }

  const secret = options.jwtSecret;

  // ── Local Login Handler (Self-contained Auth) ──────────────────────────
  if (sessionBased && secret) {
    router.post('/login', async (req, res) => {
      const { email, password } = req.body;
      if (!password) {
        res.status(400).json({ error: 'Password required' });
        return;
      }

      let authedUser: { id: string; email: string; isRoot?: boolean } | null = null;

      // 1. Check Root User
      if (options.rootUser && email === options.rootUser.email) {
        if (await bcrypt.compare(password, options.rootUser.passwordHash)) {
          authedUser = { id: 'root', email: options.rootUser.email, isRoot: true };
        }
      }

      // 2. Check Admin Secret (Bootstrap override)
      if (!authedUser && options.adminSecret && (!email || email === 'admin')) {
        if (password === options.adminSecret) {
          authedUser = { id: 'admin', email: 'admin@bootstrap', isRoot: true };
        }
      }

      // 3. Fallback to UserStore (standard login)
      if (!authedUser && email) {
        try {
          const user = await userStore.findByEmail(email);
          if (user && user.password && await bcrypt.compare(password, user.password)) {
            authedUser = { id: user.id || '', email: user.email };
          }
        } catch { /* ignore */ }
      }

      if (!authedUser) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      // Sign JWT.  `purpose: 'admin'` confines it to the admin console: the
      // app's auth middleware refuses it even when `jwtSecret` is the
      // access-token secret.
      const token = jwt.sign(
        { sub: authedUser.id, email: authedUser.email, isRoot: authedUser.isRoot, [TOKEN_PURPOSE_CLAIM]: ADMIN_TOKEN_PURPOSE },
        secret,
        { expiresIn: '24h' },
      );

      // Determine Secure flag dynamically: honour explicit cookieOptions if provided,
      // otherwise use the actual protocol of the request so the cookie works correctly
      // whether the app is behind an HTTPS-terminating reverse proxy or served directly.
      const isSecure = (req as any).secure === true || req.headers['x-forwarded-proto'] === 'https';

      // Fix: use the same __Host- / __Secure- naming logic as TokenService so
      // the guard can always read back exactly the cookie that was just written,
      // even when a regular-auth session (e.g. __Host-accessToken) is also active.
      const explicitOptions: any = (options as any).cookieOptions;
      const cookieName = resolveAdminCookieName(
        isSecure,
        options.cookiePrefix,
        explicitOptions?.path,
        explicitOptions?.domain,
      );
      const cookieOptions = applyHostCookieRequirements(cookieName, explicitOptions || {
        httpOnly: true,
        secure: isSecure,
        sameSite: 'lax' as const,
        path: '/',
        // Align maxAge with the JWT expiresIn ('24h') so the cookie persists across
        // browser restarts and does not vanish when the tab is closed.
        maxAge: 24 * 60 * 60 * 1000,
      });
      res.cookie(cookieName, token, cookieOptions);

      res.json({ success: true });
    });

    // ── Local Logout Handler ───────────────────────────────────────────────
    router.post('/logout', (req, res) => {
      const isSecure = (req as any).secure === true || req.headers['x-forwarded-proto'] === 'https';
      const explicitOptions: any = (options as any).cookieOptions;
      const cookieName = resolveAdminCookieName(
        isSecure,
        options.cookiePrefix,
        explicitOptions?.path,
        explicitOptions?.domain,
      );
      const cookieOptions = applyHostCookieRequirements(cookieName, explicitOptions || {
        httpOnly: true,
        secure: isSecure,
        sameSite: 'lax' as const,
        path: '/',
      });
      res.clearCookie(cookieName, cookieOptions);
      res.json({ success: true });
    });
  }

  // Resolve effective uploadBaseUrl for both UI script and API responses
  let effectiveUploadBaseUrl = options.uploadBaseUrl || '';
  if (!effectiveUploadBaseUrl && options.apiPrefix && options.uploadDir) {
    const prefix = options.apiPrefix.replace(/\/$/, '');
    effectiveUploadBaseUrl = `${prefix}/ui/assets/uploads`;
  }

  const featSessions = !!options.sessionStore;
  const featRoles = !!options.rbacStore;
  const featTenants = !!options.tenantStore;
  const featMetadata = !!options.userMetadataStore;
  const featTwoFAPolicy = typeof (userStore as unknown as Record<string, unknown>)['updateRequire2FA'] === 'function'
    && typeof userStore.listUsers === 'function';
  const featControl = !!options.settingsStore;
  const featLinkedAccounts = !!options.linkedAccountsStore;
  const featApiKeys = !!options.apiKeyStore;
  const featWebhooks = !!options.webhookStore;
  const featTemplates = !!options.templateStore;
  const featUpload = !!options.uploadDir;

  if (!options.silent) {
    const featureEntries = [
      ['Sessions', featSessions],
      ['Roles & Permissions', featRoles],
      ['Tenants', featTenants],
      ['Metadata', featMetadata],
      ['Control', featControl],
      ['Linked Accounts', featLinkedAccounts],
      ['API Keys', featApiKeys],
      ['Webhooks', featWebhooks],
      ['Email & UI', featTemplates],
      ['Logo Upload', featUpload],
    ] as const;
    const enabled = featureEntries.filter(([, enabledFlag]) => enabledFlag).map(([label]) => label);
    const disabled = featureEntries.filter(([, enabledFlag]) => !enabledFlag).map(([label]) => label);
    process.stderr.write(
      `[awesome-node-auth] INFO: Admin tabs enabled=[${enabled.join(', ') || 'none'}] disabled=[${disabled.join(', ') || 'none'}]\n`,
    );
  }

  // Resolve the directory that contains admin.css / admin.js.
  // Mirrors the same candidate-list pattern used in ui.router.ts.
  let _dirname = '';
  try { _dirname = __dirname; } catch { /* __dirname not available in some ESM contexts, fall back to cwd */ _dirname = process.cwd(); }
  const adminAssetCandidates = [
    path.resolve(_dirname, '../ui-assets'),           // dist
    path.resolve(_dirname, '../../ui-assets'),        // alternate dist
    path.resolve(_dirname, '../ui/assets'),           // src
    path.resolve(_dirname, '../../src/ui/assets'),    // alternate src
    path.resolve(process.cwd(), 'node_modules/awesome-node-auth/dist/ui-assets'),
    path.resolve(process.cwd(), 'node_modules/awesome-node-auth/src/ui/assets'),
  ];

  // Read admin static assets once at startup to avoid repeated filesystem access.
  // These files are small (<100 KB each) so in-memory caching is fine.
  const adminCss = (() => {
    for (const candidate of adminAssetCandidates) {
      const f = path.join(candidate, 'admin.css');
      if (fs.existsSync(f)) { try { return fs.readFileSync(f, 'utf8'); } catch { /* fall through */ } }
    }
    return '';
  })();
  const adminJs = (() => {
    for (const candidate of adminAssetCandidates) {
      const f = path.join(candidate, 'admin.js');
      if (fs.existsSync(f)) { try { return fs.readFileSync(f, 'utf8'); } catch { /* fall through */ } }
    }
    return '';
  })();

  // Serve admin.css and admin.js as public static assets (no auth required).
  // Content is cached in memory (read once above) to avoid repeated fs access.
  router.get('/assets/admin.css', (_req: Request, res: Response) => {
    if (!adminCss) { res.status(404).send('Not found'); return; }
    res.setHeader('Content-Type', 'text/css; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(adminCss);
  });
  router.get('/assets/admin.js', (_req: Request, res: Response) => {
    if (!adminJs) { res.status(404).send('Not found'); return; }
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.send(adminJs);
  });

  // GET /admin — serve the HTML UI.
  // When using accessPolicy (session-based): guard is applied so unauthenticated browsers are
  // redirected to the login page before the HTML is served.
  // When using legacy adminSecret: the HTML is served without auth (the client-side JS handles login).
  const htmlRoute: RequestHandler[] = sessionBased && panelGuard
    ? [panelGuard, (_req: Request, res: Response) => {
      const needsAuth = ((_req as any).adminNeedsAuth === true);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      res.send(buildAdminHtml(_req.baseUrl, {
        sessions: featSessions, roles: featRoles, tenants: featTenants, metadata: featMetadata,
        twoFAPolicy: featTwoFAPolicy, control: featControl, linkedAccounts: featLinkedAccounts,
        apiKeys: featApiKeys, webhooks: featWebhooks, templates: featTemplates, upload: featUpload,
        uploadBaseUrl: effectiveUploadBaseUrl, sessionBased,
        showLogin: needsAuth,
        authApiPrefix: options.apiPrefix,
        cookiePrefix: options.cookiePrefix,
      }));
    }]
    : [(_req: Request, res: Response) => {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      res.send(buildAdminHtml(_req.baseUrl, {
        sessions: featSessions, roles: featRoles, tenants: featTenants, metadata: featMetadata,
        twoFAPolicy: featTwoFAPolicy, control: featControl, linkedAccounts: featLinkedAccounts,
        apiKeys: featApiKeys, webhooks: featWebhooks, templates: featTemplates, upload: featUpload,
        uploadBaseUrl: effectiveUploadBaseUrl, sessionBased,
        authApiPrefix: options.apiPrefix,
        cookiePrefix: options.cookiePrefix,
      }));
    }];
  router.get('/', ...htmlRoute);

  // GET /admin/api/ping — health / auth check
  router.get('/api/ping', guard, (_req: Request, res: Response) => {
    res.json({ ok: true, features: { sessions: featSessions, roles: featRoles, tenants: featTenants, metadata: featMetadata, twoFAPolicy: featTwoFAPolicy, control: featControl, linkedAccounts: featLinkedAccounts, apiKeys: featApiKeys, webhooks: featWebhooks, templates: featTemplates, upload: featUpload } });
  });

  // ---- Users ----------------------------------------------------------------

  // GET /admin/api/users?limit=&offset=
  router.get('/api/users', guard, async (req: Request, res: Response) => {
    try {
      const limit = Math.min(parseInt((req.query['limit'] as string) || '20', 10), 100);
      const offset = parseInt((req.query['offset'] as string) || '0', 10);
      const filter = (req.query['filter'] as string || '').toLowerCase().trim();
      if (!userStore.listUsers) {
        res.status(501).json({ error: 'IUserStore.listUsers is not implemented', users: [], total: 0 });
        return;
      }
      // When a filter is provided, fetch up to 500 users to apply in-memory filtering.
      // This is a best-effort approach for stores that don't implement native filtering.
      // For large deployments, implement server-side filtering directly in IUserStore.listUsers.
      const batchLimit = filter ? 500 : limit;
      const batchOffset = filter ? 0 : offset;
      const users = await userStore.listUsers(batchLimit, batchOffset);
      // Strip sensitive fields before sending to admin
      let safe = users.map(u => ({
        id: u.id,
        email: u.email,
        role: u.role,
        isEmailVerified: u.isEmailVerified,
        isTotpEnabled: u.isTotpEnabled,
        require2FA: u.require2FA,
        phoneNumber: u.phoneNumber,
        createdAt: (u as unknown as Record<string, unknown>)['createdAt'],
      }));
      if (filter) {
        safe = safe.filter(u => u.email.toLowerCase().includes(filter) || u.id.toLowerCase().includes(filter));
        const total = safe.length;
        safe = safe.slice(offset, offset + limit);
        res.json({ users: safe, total });
        return;
      }
      // Return total as the count of users returned (best-effort — stores may not expose total)
      res.json({ users: safe, total: safe.length + offset + (safe.length === limit ? 1 : 0) });
    } catch (err) {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // GET /admin/api/users/:id
  router.get('/api/users/:id', guard, async (req: Request, res: Response) => {
    try {
      const user = await userStore.findById(req.params['id'] as string);
      if (!user) { res.status(404).json({ error: 'User not found' }); return; }
      res.json({
        id: user.id, email: user.email, role: user.role,
        isEmailVerified: user.isEmailVerified, isTotpEnabled: user.isTotpEnabled,
      });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // DELETE /admin/api/users/:id — delete user (requires userStore to have a delete method if available)
  router.delete('/api/users/:id', guard, async (req: Request, res: Response) => {
    try {
      const store = userStore as unknown as Record<string, unknown>;
      if (typeof store['deleteUser'] === 'function') {
        await (store['deleteUser'] as (id: string) => Promise<void>)(req.params['id'] as string);
        res.json({ success: true });
      } else {
        res.status(501).json({ error: 'IUserStore.deleteUser is not implemented' });
      }
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- User Metadata --------------------------------------------------------

  // POST /admin/api/2fa-policy — bulk set / clear the require-2FA flag on all users
  router.post('/api/2fa-policy', guard, async (req: Request, res: Response) => {
    try {
      const { required } = req.body as { required: boolean };
      if (typeof required !== 'boolean') {
        res.status(400).json({ error: '"required" must be a boolean' });
        return;
      }
      if (typeof (userStore as unknown as Record<string, unknown>)['updateRequire2FA'] !== 'function') {
        res.status(501).json({ error: 'IUserStore.updateRequire2FA is not implemented' });
        return;
      }
      if (!userStore.listUsers) {
        res.status(501).json({ error: 'IUserStore.listUsers is not implemented' });
        return;
      }
      const updateFn = (userStore as unknown as { updateRequire2FA(id: string, required: boolean): Promise<void> }).updateRequire2FA.bind(userStore);
      let offset = 0;
      const batchSize = 100;
      let updated = 0;
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const batch = await userStore.listUsers(batchSize, offset);
        if (batch.length === 0) break;
        await Promise.all(batch.map(u => updateFn(u.id, required)));
        updated += batch.length;
        if (batch.length < batchSize) break;
        offset += batchSize;
      }
      res.json({ success: true, updated });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // GET /admin/api/users/:id/metadata
  router.get('/api/users/:id/metadata', guard, async (req: Request, res: Response) => {
    if (!options.userMetadataStore) { res.status(404).json({ error: 'User metadata store not configured' }); return; }
    try {
      const metadata = await options.userMetadataStore.getMetadata(req.params['id'] as string);
      res.json(metadata);
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // PUT /admin/api/users/:id/metadata
  router.put('/api/users/:id/metadata', guard, async (req: Request, res: Response) => {
    if (!options.userMetadataStore) { res.status(404).json({ error: 'User metadata store not configured' }); return; }
    try {
      const metadata = req.body as Record<string, unknown>;
      await options.userMetadataStore.updateMetadata(req.params['id'] as string, metadata);
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- Linked Accounts (read-only view in admin panel) ----------------------

  // GET /admin/api/users/:id/linked-accounts
  router.get('/api/users/:id/linked-accounts', guard, async (req: Request, res: Response) => {
    if (!options.linkedAccountsStore) { res.status(404).json({ error: 'Linked accounts store not configured' }); return; }
    try {
      const linkedAccounts = await options.linkedAccountsStore.getLinkedAccounts(req.params['id'] as string);
      res.json({ linkedAccounts });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- User ↔ Role assignment -----------------------------------------------

  // GET /admin/api/users/:id/roles
  router.get('/api/users/:id/roles', guard, async (req: Request, res: Response) => {
    if (!options.rbacStore) { res.status(404).json({ error: 'RBAC store not configured' }); return; }
    try {
      const roles = await options.rbacStore.getRolesForUser(req.params['id'] as string);
      res.json({ roles });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // POST /admin/api/users/:id/roles — assign a role to a user
  router.post('/api/users/:id/roles', guard, async (req: Request, res: Response) => {
    if (!options.rbacStore) { res.status(404).json({ error: 'RBAC store not configured' }); return; }
    try {
      const { role, tenantId } = req.body as { role: string; tenantId?: string };
      if (!role) { res.status(400).json({ error: 'role is required' }); return; }
      const userId = req.params['id'] as string;
      await options.rbacStore.addRoleToUser(userId, role, tenantId);
      publishAdminEvent(eventBus, AuthEventNames.ROLE_ASSIGNED, req, {
        userId,
        tenantId,
        data: { role, actorId: adminActorId(res) },
      });
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // DELETE /admin/api/users/:id/roles/:role — remove a role from a user
  router.delete('/api/users/:id/roles/:role', guard, async (req: Request, res: Response) => {
    if (!options.rbacStore) { res.status(404).json({ error: 'RBAC store not configured' }); return; }
    try {
      const userId = req.params['id'] as string;
      const role = decodeURIComponent(req.params['role'] as string);
      await options.rbacStore.removeRoleFromUser(userId, role);
      publishAdminEvent(eventBus, AuthEventNames.ROLE_REVOKED, req, {
        userId,
        data: { role, actorId: adminActorId(res) },
      });
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  router.post('/users/:id/promote', ...rateLimiter, guard, requireJsonBody, async (req: Request, res: Response) => {
    const userId = req.params['id'] as string;
    const method = (req.body as { method?: 'flag' | 'role' } | undefined)?.method ?? 'role';
    try {
      if (method === 'flag') {
        const writableUserStore = userStore as AdminWritableUserStore;
        if (typeof writableUserStore.update !== 'function') {
          res.status(501).json({ error: 'IUserStore.update is required for method=flag' });
          return;
        }
        await writableUserStore.update(userId, { isAdmin: true });
        publishAdminEvent(eventBus, AuthEventNames.ROLE_ASSIGNED, req, {
          userId,
          data: { role: 'admin', method: 'flag', actorId: adminActorId(res) },
        });
        res.json({ success: true, method });
        return;
      }

      if (!options.rbacStore) {
        res.status(404).json({ error: 'RBAC store not configured' });
        return;
      }
      await options.rbacStore.createRole('admin');
      await options.rbacStore.addRoleToUser(userId, 'admin');
      publishAdminEvent(eventBus, AuthEventNames.ROLE_ASSIGNED, req, {
        userId,
        data: { role: 'admin', method: 'role', actorId: adminActorId(res) },
      });
      res.json({ success: true, method });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- User ↔ Tenant assignment (from user panel) --------------------------

  // GET /admin/api/users/:id/tenants
  router.get('/api/users/:id/tenants', guard, async (req: Request, res: Response) => {
    if (!options.tenantStore) { res.status(404).json({ error: 'Tenant store not configured' }); return; }
    try {
      const tenants = await options.tenantStore.getTenantsForUser(req.params['id'] as string);
      res.json({ tenantIds: tenants.map(t => t.id) });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- Control settings -----------------------------------------------------

  // GET /admin/api/actions — return registered webhook action metadata
  router.get('/api/actions', guard, (_req: Request, res: Response) => {
    res.json({ actions: ActionRegistry.getAllMeta() });
  });

  // GET /admin/api/settings
  router.get('/api/settings', guard, async (_req: Request, res: Response) => {
    if (!options.settingsStore) { res.status(404).json({ error: 'Settings store not configured' }); return; }
    try {
      const settings = await options.settingsStore.getSettings();
      res.json(settings);
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // PUT /admin/api/settings
  router.put('/api/settings', guard, async (req: Request, res: Response) => {
    if (!options.settingsStore) { res.status(404).json({ error: 'Settings store not configured' }); return; }
    try {
      const updates = req.body as Record<string, unknown>;
      await options.settingsStore.updateSettings(updates);
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // PATCH /admin/api/settings/ui — deep-merge only the UI sub-object, avoids the GET+PUT race
  router.patch('/api/settings/ui', guard, async (req: Request, res: Response) => {
    if (!options.settingsStore) { res.status(404).json({ error: 'Settings store not configured' }); return; }
    try {
      const uiPatch = req.body as Record<string, unknown>;
      // Read current settings, merge new UI fields, write back
      const current = await options.settingsStore.getSettings();
      const mergedUi = { ...(current.ui || {}), ...uiPatch };
      await options.settingsStore.updateSettings({ ui: mergedUi } as Partial<AuthSettings>);
      res.json({ success: true });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Internal server error';
      res.status(500).json({ error: msg });
    }
  });

  // ---- File upload (requires uploadDir) -------------------------------------

  if (options.uploadDir) {
    const uploadDir = options.uploadDir;
    // Ensure uploadDir exists
    if (!fs.existsSync(uploadDir)) {
      try {
        fs.mkdirSync(uploadDir, { recursive: true });
      } catch (err) {
        console.error('[awesome-node-auth] Failed to create uploadDir:', err);
      }
    }

    const upload = multer({
      storage: multer.diskStorage({
        destination: (_req, _file, cb) => cb(null, uploadDir),
        filename: (_req, file, cb) => {
          // Sanitize name (no dots, max 40 chars) and keep a clean extension
          const rawExt = path.extname(file.originalname).toLowerCase();
          const ext = rawExt.replace(/[^a-z0-9]/g, '');  // strip anything that isn't letters/digits
          const name = path.basename(file.originalname, path.extname(file.originalname))
            .replace(/[^a-z0-9_-]/gi, '_')
            .slice(0, 40);
          cb(null, `${name}_${Date.now()}.${ext}`);
        },
      }),
      limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
      fileFilter: (_req, file, cb) => {
        const allowed = /\.(png|jpg|jpeg|gif|svg|webp|ico)$/i;
        if (allowed.test(file.originalname)) cb(null, true);
        else cb(new Error('Only image files are allowed'));
      },
    });

    // POST /admin/api/upload/logo — upload logo image
    router.post('/api/upload/logo', guard, upload.single('file'), (req: Request, res: Response) => {
      if (!req.file) { res.status(400).json({ error: 'No file uploaded' }); return; }
      const filename = req.file.filename;
      // Return the filename; the browser resolves the full URL via effectiveUploadBaseUrl
      const url = effectiveUploadBaseUrl
        ? `${effectiveUploadBaseUrl.replace(/\/$/, '')}/${encodeURIComponent(filename)}`
        : filename;
      res.json({ success: true, filename, url });
    });

    // POST /admin/api/upload/bg-image — upload background image
    router.post('/api/upload/bg-image', guard, upload.single('file'), (req: Request, res: Response) => {
      if (!req.file) { res.status(400).json({ error: 'No file uploaded' }); return; }
      const filename = req.file.filename;
      const url = effectiveUploadBaseUrl
        ? `${effectiveUploadBaseUrl.replace(/\/$/, '')}/${encodeURIComponent(filename)}`
        : filename;
      res.json({ success: true, filename, url });
    });

    // GET /admin/api/upload/files — list uploaded files
    // Access is already gated behind adminAuth (Bearer token), so unauthorized
    // callers are rejected before the filesystem is read.
    router.get('/api/upload/files', guard, (_req: Request, res: Response) => {
      try {
        const files = fs.readdirSync(uploadDir)
          .filter(f => /\.(png|jpg|jpeg|gif|svg|webp|ico)$/i.test(f))
          .map(f => {
            const stat = fs.statSync(path.join(uploadDir, f));
            return { name: f, size: stat.size, mtime: stat.mtime.toISOString() };
          })
          .sort((a, b) => b.mtime.localeCompare(a.mtime));
        res.json({ files });
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Could not list files';
        res.status(500).json({ error: msg });
      }
    });

    // DELETE /admin/api/upload/:filename — delete an uploaded file
    // Access is already gated behind adminAuth (Bearer token), so unauthorized
    // callers are rejected before any filesystem mutation occurs.
    router.delete('/api/upload/:filename', guard, (req: Request, res: Response) => {
      const filename = req.params['filename'] as string;
      // Prevent path traversal
      if (filename.includes('/') || filename.includes('\\') || filename.startsWith('.')) {
        res.status(400).json({ error: 'Invalid filename' });
        return;
      }
      const filepath = path.join(uploadDir, filename);
      if (!fs.existsSync(filepath)) { res.status(404).json({ error: 'File not found' }); return; }
      try {
        fs.unlinkSync(filepath);
        res.json({ success: true });
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Could not delete file';
        res.status(500).json({ error: msg });
      }
    });
  }

  // GET /admin/api/sessions?limit=&offset=&filter=
  router.get('/api/sessions', guard, async (req: Request, res: Response) => {
    if (!options.sessionStore) { res.status(404).json({ error: 'Session store not configured' }); return; }
    try {
      const limit = Math.min(parseInt((req.query['limit'] as string) || '20', 10), 100);
      const offset = parseInt((req.query['offset'] as string) || '0', 10);
      const filter = (req.query['filter'] as string || '').toLowerCase().trim();
      if (!options.sessionStore.getAllSessions) {
        res.status(501).json({ error: 'ISessionStore.getAllSessions is not implemented', sessions: [], total: 0 });
        return;
      }
      if (filter) {
        // Best-effort in-memory filter (up to 500 records). For large deployments,
        // implement native filtering in ISessionStore.getAllSessions.
        const all = await options.sessionStore.getAllSessions(500, 0);
        const filtered = all.filter(s =>
          s.userId.toLowerCase().includes(filter) ||
          (s.ipAddress ?? '').toLowerCase().includes(filter)
        );
        const total = filtered.length;
        res.json({ sessions: filtered.slice(offset, offset + limit), total });
        return;
      }
      const sessions = await options.sessionStore.getAllSessions(limit, offset);
      res.json({ sessions, total: sessions.length + offset + (sessions.length === limit ? 1 : 0) });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // DELETE /admin/api/sessions/:handle
  router.delete('/api/sessions/:handle', guard, async (req: Request, res: Response) => {
    if (!options.sessionStore) { res.status(404).json({ error: 'Session store not configured' }); return; }
    try {
      await options.sessionStore.revokeSession(decodeURIComponent(req.params['handle'] as string));
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- Roles & Permissions --------------------------------------------------

  // GET /admin/api/roles
  router.get('/api/roles', guard, async (_req: Request, res: Response) => {
    if (!options.rbacStore) { res.status(404).json({ error: 'RBAC store not configured' }); return; }
    try {
      if (!options.rbacStore.getAllRoles) {
        res.status(501).json({ error: 'IRolesPermissionsStore.getAllRoles is not implemented', roles: [] });
        return;
      }
      const roleNames = await options.rbacStore.getAllRoles();
      const roles = await Promise.all(
        roleNames.map(async name => ({
          name,
          permissions: await options.rbacStore!.getPermissionsForRole(name),
        }))
      );
      res.json({ roles });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // POST /admin/api/roles
  router.post('/api/roles', guard, async (req: Request, res: Response) => {
    if (!options.rbacStore) { res.status(404).json({ error: 'RBAC store not configured' }); return; }
    try {
      const { name, permissions } = req.body as { name: string; permissions?: string[] };
      if (!name) { res.status(400).json({ error: 'name is required' }); return; }
      await options.rbacStore.createRole(name, permissions);
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // DELETE /admin/api/roles/:name
  router.delete('/api/roles/:name', guard, async (req: Request, res: Response) => {
    if (!options.rbacStore) { res.status(404).json({ error: 'RBAC store not configured' }); return; }
    try {
      await options.rbacStore.deleteRole(decodeURIComponent(req.params['name'] as string));
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- Tenants --------------------------------------------------------------

  // GET /admin/api/tenants
  router.get('/api/tenants', guard, async (_req: Request, res: Response) => {
    if (!options.tenantStore) { res.status(404).json({ error: 'Tenant store not configured' }); return; }
    try {
      const tenants = await options.tenantStore.getAllTenants();
      res.json({ tenants });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // POST /admin/api/tenants
  router.post('/api/tenants', guard, async (req: Request, res: Response) => {
    if (!options.tenantStore) { res.status(404).json({ error: 'Tenant store not configured' }); return; }
    try {
      const { name, isActive } = req.body as { name: string; isActive?: boolean };
      if (!name) { res.status(400).json({ error: 'name is required' }); return; }
      const tenant = await options.tenantStore.createTenant({ name, isActive: isActive ?? true });
      res.json({ tenant });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // DELETE /admin/api/tenants/:id
  router.delete('/api/tenants/:id', guard, async (req: Request, res: Response) => {
    if (!options.tenantStore) { res.status(404).json({ error: 'Tenant store not configured' }); return; }
    try {
      await options.tenantStore.deleteTenant(decodeURIComponent(req.params['id'] as string));
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ---- Tenant ↔ User membership ---------------------------------------------

  // GET /admin/api/tenants/:id/users
  router.get('/api/tenants/:id/users', guard, async (req: Request, res: Response) => {
    if (!options.tenantStore) { res.status(404).json({ error: 'Tenant store not configured' }); return; }
    try {
      const userIds = await options.tenantStore.getUsersForTenant(decodeURIComponent(req.params['id'] as string));
      res.json({ userIds });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // POST /admin/api/tenants/:id/users — add a user to a tenant
  router.post('/api/tenants/:id/users', guard, async (req: Request, res: Response) => {
    if (!options.tenantStore) { res.status(404).json({ error: 'Tenant store not configured' }); return; }
    try {
      const { userId } = req.body as { userId: string };
      if (!userId) { res.status(400).json({ error: 'userId is required' }); return; }
      await options.tenantStore.associateUserWithTenant(userId, decodeURIComponent(req.params['id'] as string));
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // DELETE /admin/api/tenants/:id/users/:userId — remove a user from a tenant
  router.delete('/api/tenants/:id/users/:userId', guard, async (req: Request, res: Response) => {
    if (!options.tenantStore) { res.status(404).json({ error: 'Tenant store not configured' }); return; }
    try {
      await options.tenantStore.disassociateUserFromTenant(
        decodeURIComponent(req.params['userId'] as string),
        decodeURIComponent(req.params['id'] as string),
      );
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ── API Keys ───────────────────────────────────────────────────────────────

  // GET /admin/api/api-keys?limit=&offset=&filter=
  router.get('/api/api-keys', guard, async (req: Request, res: Response) => {
    if (!options.apiKeyStore) { res.status(404).json({ error: 'API key store not configured' }); return; }
    try {
      const limit = Math.min(parseInt((req.query['limit'] as string) || '20', 10), 100);
      const offset = parseInt((req.query['offset'] as string) || '0', 10);
      const filter = (req.query['filter'] as string || '').toLowerCase().trim();
      if (!options.apiKeyStore.listAll) {
        res.status(501).json({ error: 'IApiKeyStore.listAll is not implemented', keys: [], total: 0 });
        return;
      }
      const batchLimit = filter ? 500 : limit;
      const batchOffset = filter ? 0 : offset;
      const keys = await options.apiKeyStore.listAll(batchLimit, batchOffset);
      const safe = (arr: typeof keys) => arr.map(k => ({
        id: k.id,
        name: k.name,
        keyPrefix: k.keyPrefix,
        serviceId: k.serviceId,
        scopes: k.scopes,
        allowedIps: k.allowedIps,
        isActive: k.isActive,
        expiresAt: k.expiresAt,
        createdAt: k.createdAt,
        lastUsedAt: k.lastUsedAt,
      }));
      if (filter) {
        const filtered = safe(keys).filter(k =>
          k.name.toLowerCase().includes(filter) ||
          (k.serviceId ?? '').toLowerCase().includes(filter) ||
          k.keyPrefix.toLowerCase().includes(filter)
        );
        const total = filtered.length;
        res.json({ keys: filtered.slice(offset, offset + limit), total });
        return;
      }
      res.json({ keys: safe(keys), total: keys.length + offset + (keys.length === limit ? 1 : 0) });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // POST /admin/api/api-keys — create a new key (returns rawKey once)
  router.post('/api/api-keys', guard, async (req: Request, res: Response) => {
    if (!options.apiKeyStore) { res.status(404).json({ error: 'API key store not configured' }); return; }
    try {
      const { name, serviceId, scopes, allowedIps, expiresAt } = req.body as {
        name: string;
        serviceId?: string;
        scopes?: string[];
        allowedIps?: string[];
        expiresAt?: string;
      };
      if (!name) { res.status(400).json({ error: 'name is required' }); return; }
      const service = new ApiKeyService();
      const { rawKey, record } = await service.createKey(options.apiKeyStore, {
        name,
        serviceId,
        scopes,
        allowedIps,
        expiresAt: expiresAt ? new Date(expiresAt) : undefined,
      });
      res.json({
        rawKey,
        record: {
          id: record.id,
          name: record.name,
          keyPrefix: record.keyPrefix,
          serviceId: record.serviceId,
          scopes: record.scopes,
          allowedIps: record.allowedIps,
          isActive: record.isActive,
          expiresAt: record.expiresAt,
          createdAt: record.createdAt,
        },
      });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // DELETE /admin/api/api-keys/:id/revoke — mark inactive (soft revoke)
  router.delete('/api/api-keys/:id/revoke', guard, async (req: Request, res: Response) => {
    if (!options.apiKeyStore) { res.status(404).json({ error: 'API key store not configured' }); return; }
    try {
      await options.apiKeyStore.revoke(req.params['id'] as string);
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // DELETE /admin/api/api-keys/:id — hard delete (falls back to revoke if .delete not implemented)
  router.delete('/api/api-keys/:id', guard, async (req: Request, res: Response) => {
    if (!options.apiKeyStore) { res.status(404).json({ error: 'API key store not configured' }); return; }
    try {
      if (typeof options.apiKeyStore.delete === 'function') {
        await options.apiKeyStore.delete(req.params['id'] as string);
        res.json({ success: true });
      } else {
        await options.apiKeyStore.revoke(req.params['id'] as string);
        res.json({ success: true, note: 'IApiKeyStore.delete not implemented; key was revoked instead' });
      }
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ── Webhooks ───────────────────────────────────────────────────────────────

  // GET /admin/api/webhooks?limit=&offset=
  router.get('/api/webhooks', guard, async (req: Request, res: Response) => {
    if (!options.webhookStore) { res.status(404).json({ error: 'Webhook store not configured' }); return; }
    try {
      const limit = Math.min(parseInt((req.query['limit'] as string) || '20', 10), 100);
      const offset = parseInt((req.query['offset'] as string) || '0', 10);
      if (!options.webhookStore.listAll) {
        res.status(501).json({ error: 'IWebhookStore.listAll is not implemented', webhooks: [], total: 0 });
        return;
      }
      const webhooks = await options.webhookStore.listAll(limit, offset);
      const safe = webhooks.map(w => ({
        id: w.id,
        url: w.url,
        events: w.events,
        isActive: w.isActive,
        tenantId: w.tenantId,
        maxRetries: w.maxRetries,
        retryDelayMs: w.retryDelayMs,
        secret: w.secret ? '***' : undefined,
      }));
      res.json({ webhooks: safe, total: safe.length + offset + (safe.length === limit ? 1 : 0) });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // POST /admin/api/webhooks — register a new webhook
  router.post('/api/webhooks', guard, async (req: Request, res: Response) => {
    if (!options.webhookStore) { res.status(404).json({ error: 'Webhook store not configured' }); return; }
    try {
      const { url, events, secret, tenantId, isActive, maxRetries, retryDelayMs } = req.body as {
        url: string; events?: string[]; secret?: string; tenantId?: string;
        isActive?: boolean; maxRetries?: number; retryDelayMs?: number;
      };
      if (!url) { res.status(400).json({ error: 'url is required' }); return; }
      if (!options.webhookStore.add) {
        res.status(501).json({ error: 'IWebhookStore.add is not implemented' });
        return;
      }
      const webhook = await options.webhookStore.add({
        url, events: events ?? ['*'], secret, tenantId,
        isActive: isActive ?? true, maxRetries, retryDelayMs,
      });
      res.json({ webhook: { ...webhook, secret: webhook.secret ? '***' : undefined } });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // PATCH /admin/api/webhooks/:id — partial update (e.g. toggle isActive)
  router.patch('/api/webhooks/:id', guard, async (req: Request, res: Response) => {
    if (!options.webhookStore) { res.status(404).json({ error: 'Webhook store not configured' }); return; }
    try {
      if (!options.webhookStore.update) {
        res.status(501).json({ error: 'IWebhookStore.update is not implemented' });
        return;
      }
      await options.webhookStore.update(req.params['id'] as string, req.body as Record<string, unknown>);
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // DELETE /admin/api/webhooks/:id
  router.delete('/api/webhooks/:id', guard, async (req: Request, res: Response) => {
    if (!options.webhookStore) { res.status(404).json({ error: 'Webhook store not configured' }); return; }
    try {
      if (!options.webhookStore.remove) {
        res.status(501).json({ error: 'IWebhookStore.remove is not implemented' });
        return;
      }
      await options.webhookStore.remove(req.params['id'] as string);
      res.json({ success: true });
    } catch {
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // ── Email & UI Templates ──────────────────────────────────────────────────

  if (featTemplates && options.templateStore) {
    const store = options.templateStore;

    // GET /admin/api/templates/mail — list all mail templates
    router.get('/api/templates/mail', guard, async (_req: Request, res: Response) => {
      try {
        const templates = await store.listMailTemplates();
        res.json({ templates });
      } catch {
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    // POST /admin/api/templates/mail — create or update a mail template
    router.post('/api/templates/mail', guard, async (req: Request, res: Response) => {
      try {
        const { id, baseHtml, baseText, translations } = req.body;
        if (!id) { res.status(400).json({ error: 'id is required' }); return; }
        await store.updateMailTemplate(id, { baseHtml, baseText, translations });
        res.json({ success: true });
      } catch {
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    // GET /admin/api/templates/ui — list all UI translations
    router.get('/api/templates/ui', guard, async (_req: Request, res: Response) => {
      try {
        const translations = await store.listUiTranslations();
        res.json({ translations });
      } catch {
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    // POST /admin/api/templates/ui — update UI translations for a page
    router.post('/api/templates/ui', guard, async (req: Request, res: Response) => {
      try {
        const { page, translations } = req.body;
        if (!page || !translations) { res.status(400).json({ error: 'page and translations are required' }); return; }
        await store.updateUiTranslations(page, translations);
        res.json({ success: true });
      } catch {
        res.status(500).json({ error: 'Internal server error' });
      }
    });
  }

  // ── Swagger / OpenAPI (optional) ───────────────────────────────────────────
  const swaggerEnabled =
    options.swagger === true ||
    (options.swagger !== false && process.env['NODE_ENV'] !== 'production');

  if (swaggerEnabled) {
    const specBasePath = options.swaggerBasePath ?? '/admin';
    router.get('/api/openapi.json', (_req: Request, res: Response) => {
      const spec = buildAdminOpenApiSpec(
        {
          hasSessions: !!options.sessionStore,
          hasRoles: !!options.rbacStore,
          hasTenants: !!options.tenantStore,
          hasMetadata: !!options.userMetadataStore,
          hasSettings: !!options.settingsStore,
          hasLinkedAccounts: !!options.linkedAccountsStore,
          hasApiKeys: !!options.apiKeyStore,
          hasWebhooks: !!options.webhookStore,
        },
        specBasePath,
      );
      res.setHeader('Content-Type', 'application/json');
      res.json(spec);
    });

    router.get('/api/docs', (_req: Request, res: Response) => {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(buildSwaggerUiHtml(`${specBasePath}/api/openapi.json`));
    });
  }

  return router;
}
