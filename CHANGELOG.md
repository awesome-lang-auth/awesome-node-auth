# Changelog

All notable changes to **awesome-node-auth** are documented in this file.  
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`auth.js` and `/ui/config` are always served** (family rule: every backend serves the browser client at the same route): as soon as the auth router is mounted, `GET <apiPrefix>/ui/auth.js` (default `/auth/ui/auth.js`) and `GET <apiPrefix>/ui/config` answer `200`, with or without `ui.enabled`. This holds for `auth.router()` / `createAuthRouter()` and for `buildAllRouters()`. The mount prefix moves both, together with the pages.
  - `auth.js` is the shipped `src/ui/assets/auth.js`, byte for byte. `/ui/config` is the same node-shaped document as with the full UI; its `headless` field still reports `ui.headless`.
  - `ui: { headless: true }` without `enabled` now takes effect: `/ui/config` reports `headless: true` (before, nothing under `/ui` was served).
- **`clientOnly` on `UiRouterOptions`**: `buildUiRouter({ …, clientOnly: true })` serves only `GET /auth.js` and `GET /config`. The auth router uses it when `ui.enabled` is not set.

### Changed
- **The UI router is always mounted under `<apiPrefix>/ui`.** `ui.enabled` (default `false`) now only controls the built-in HTML pages and the other assets (`base.css`, `admin.js`, …). Without it they still answer `404`, as `ui.enabled` + `ui.headless` already did for the pages. With `ui.enabled` nothing changes.
  - If you mount `buildUiRouter` yourself at `<apiPrefix>/ui` **after** `auth.router()`, the auth router now answers `/ui/auth.js` and `/ui/config` first, from its own options. Pass the same `settingsStore` (and `uiAssetsDir`) in the `auth.router()` options, mount your UI router before `auth.router()`, or set `ui.enabled` and drop the separate mount. The Express demo now passes `settingsStore` to `auth.router()`.

### Documentation
- **Wrong `auth.js` path**: the `ui.headless` JSDoc, the Express demo and the generic OAuth example pointed at `/auth/ui/assets/auth.js`, which answers `404`. The route is `<apiPrefix>/ui/auth.js`. `README.md` and `README.detailed.md` describe the always-on client and list what each `ui` option serves.

## [1.10.8] — 2026-09-29

### Added
- **`apiPrefix` option on `AuthConfiguratorOptions`** (Issue #29):
  - `new AuthConfigurator(config, userStore, { apiPrefix })` sets the default prefix for `router()` and `buildAllRouters()` when their options do not set one, and for the link built by `sendVerificationEmail()`, also before any router has been built.
- **`AuthError.hasExplicitStatus`** (Issue #29): `true` when the status was passed to the constructor, `false` when `statusCode` is the default `401`.

### Fixed
- **Admin `:id` decoded twice** (Issue #29, regression in 1.10.7): `POST /admin/api/users/:id/send-verification-email` no longer calls `decodeURIComponent` on the parameter Express has already decoded. An id containing `%` works, and a double-encoded email (`a%2540b.c`) answers 404 instead of reaching `a@b.c`.
- **`unsupported_store` on the user route** (Issue #29): `POST /auth/send-verification-email` now answers `501` like the admin route. The 500 pre-check that made the 501 branch unreachable is removed (1.10.7 already claimed 501 on both routes).
- **Verification link prefix edge cases** (Issue #29):
  - `AuthConfigurator.sendVerificationEmail` merges defaults per field. An explicit `{ routerOptions: undefined }`, or router options without `apiPrefix`, no longer override the configured prefix. Precedence: `opts.routerOptions.apiPrefix`, then the last `router()`/`buildAllRouters()` prefix, then the configurator `apiPrefix` option, then `config.apiPrefix`, then `'/auth'`.
  - On the admin router, `routerOptions` without `apiPrefix` no longer hides the `apiPrefix` option. A standalone admin router with only `authConfig` uses `authConfig.apiPrefix` (documented: set it there or in the `apiPrefix` option).
- **Hook errors never answer 401 by default** (Issue #29): an `AuthError` thrown by `onBeforeDeleteUser` without an explicit status now answers `500` with `{ error, code }` on both `DELETE /auth/account` and `DELETE /admin/api/users/:id`, instead of the `AuthError` default `401`. Explicit statuses (e.g. `409`) are kept as before.
- **Route parameters decoded twice** (follow-up to #29): removed the extra `decodeURIComponent` on route parameters that Express has already decoded.
  - Admin routes:
    - `DELETE /api/users/:id/roles/:role`
    - `DELETE /api/sessions/:handle`
    - `DELETE /api/roles/:name`
    - `DELETE /api/tenants/:id`
    - `GET` and `POST /api/tenants/:id/users`
    - `DELETE /api/tenants/:id/users/:userId`
    - `POST /api/users/:id/send-verification-email`
  - User route: `DELETE /auth/sessions/:handle`.
  - A value containing a literal `%` (sent as `%25`) no longer answers 500 (`URIError`), and `%2541` is passed on as `%41` instead of `A`.

### Documentation
- **Cookie clearing** (Issue #29): removed the non-existent `clearAuthCookies` export documented in 1.10.7 from `README.md` and `README.detailed.md`. The real API is `new TokenService().clearTokenCookies(res, config)`.
- **Verification email reasons and statuses** (Issue #29):
  - `README.detailed.md` lists every `reason` (`already_verified | not_found | no_mailer | unsupported_store`) and its status on both routes (400/404/501, plus 500 on the admin route without `authConfig`).
  - It documents the email-as-`:id` rule: only `send-verification-email` accepts it, lookup is by id then by email, and the value is URL-encoded once.
  - The OpenAPI entry of `POST /auth/send-verification-email` now lists 400/404/501.
- **OAuth nonce cookie behind path-rewriting proxies** (Issue #29): documented that the nonce cookie path is the pathname of `redirect_uri` (`callbackUrl`), which must be the public callback path served by the proxy. Behaviour is unchanged.

### Tests
- **Supertest servers bound to `127.0.0.1`**: fixes the intermittent unexpected 401 and `Parse Error: Expected HTTP/, RTSP/ or ICE/` in the test suite.
  - **Cause:** with a bare Express app, `supertest(app)` listens on `::` but connects to `127.0.0.1`, so on macOS another local process bound to `127.0.0.1` on the same ephemeral port could answer.
  - **Fix:** the new `tests/helpers/listen.ts` starts the app on `127.0.0.1:0`, waits for `listening`, and closes the server after the test (or after the file). Every `request(app)` in `tests/` now uses `request(await listen(app))`; assertions are unchanged.
  - No library code changed.

---

## [1.10.7] — 2026-09-28

### Added
- **Route alias `DELETE /users/:id` on admin router** (Issue #26):
  - Added route alias `DELETE /users/:id` matching `DELETE /admin/api/users/:id` on the admin router for symmetry with `/users/:id/send-verification-email`.
- **Reason codes `no_mailer` and `unsupported_store` for verification email triggers** (Issue #26):
  - `performSendVerificationEmail` returns `{ sent: false, reason: 'no_mailer' }` when no mailer is configured (without generating or persisting a verification token).
  - Returns `{ sent: false, reason: 'unsupported_store' }` when `userStore` lacks `updateEmailVerificationToken` or `updateEmailVerified` instead of throwing an Error.
  - Endpoints (`POST /auth/send-verification-email` and `POST /admin/api/users/:id/send-verification-email`) map both reasons to HTTP 501.

### Fixed
- **Admin delete hook error status code propagation** (Issue #26):
  - In `deleteUserHandler`, caught `AuthError` instances propagate `err.statusCode` (e.g. 409) and `err.code` to the HTTP response, rather than collapsing to generic HTTP 500.
  - Enhanced `AuthError` constructor to accept either `(message, code, statusCode)` or `(message, statusCode, code)`.
- **Admin delete non-existent user returns 404 before hook** (Issue #26):
  - `deleteUserHandler` now checks `await userStore.findById(userId)` first; if the user does not exist, returns HTTP 404 (`User not found`) immediately without invoking `onBeforeDeleteUser`.
- **Automatic prefix derivation for verification email links** (Issue #26):
  - `AuthConfigurator.sendVerificationEmail`, `createAdminRouter`, and `performSendVerificationEmail` now default `routerOptions` to active configuration (e.g. `_lastRouterOptions` or `{ apiPrefix: config.apiPrefix }`) if not explicitly passed, ensuring UI links correctly use the configured prefix instead of falling back to `/auth`.

### Documentation
- **Admin send verification email accepts ID or email** (Issue #26):
  - Documented in OpenAPI specification, `README.md`, and `README.detailed.md` that `POST /admin/api/users/:id/send-verification-email` accepts either a user ID or URL-encoded email address in the `:id` parameter.
- **Cookie clearing helper functions documented** (Issue #26):
  - Documented `clearAuthCookies(res, config)` and `tokenService.clearTokenCookies(res, config)` in `README.md` and `README.detailed.md`.

---

## [1.10.6] — 2026-09-28

### Security
- **Strict OAuth state signature & expiry verification** (Issue #22 residuals):
  - Callback endpoints (`/oauth/google/callback`, `/oauth/github/callback`, `/oauth/:name/callback`) now unconditionally require structured OAuth state containing valid expiry (`exp`) and cryptographic HMAC signature (`s`).
  - Bare nonce strings, states missing `exp` or `s`, or states reduced to `{ n, o }` are strictly rejected with HTTP 400 (`INVALID_OAUTH_STATE`), preventing origin swapping or expiry bypass.
- **Removed duplicate nonce cookie** (Issue #22 residuals / Issue #14):
  - Removed duplicate `res.cookie` on `Path=/` in OAuth start routes; `oauth_nonce_*` is now set exclusively with `path: callbackPath`.

### Fixed
- **Stateful RegExp in `allowedReturnPaths`** (Issue #22 residuals):
  - Reset `lastIndex = 0` before and after testing regular expressions with `/g` or `/y` flags in `validateReturnPath`, preventing consecutive logins from failing with HTTP 400.
- **Precedence fallback for empty `allowedReturnPaths: []`** (Issue #22 residuals):
  - Treat empty array `[]` as "not set", properly falling through across all 4 configuration candidates without defeating restriction rules.

### Documentation
- **Documented all 4 configuration locations for `allowedReturnPaths` and precedence** (Issue #22 residuals):
  - Clarified precedence order: `RouterOptions.allowedReturnPaths` > `RouterOptions.oauth.allowedReturnPaths` > `AuthConfig.allowedReturnPaths` > `AuthConfig.oauth.allowedReturnPaths`.
  - Documented that string entries (e.g. `'/oauth/done'`) match on pathname and allow query parameters on the same origin (e.g. `/oauth/done?tab=profile`).

---

## [1.10.5] — 2026-09-28

### Added
- **Account deletion hook (`onBeforeDeleteUser`)** (Issue #20):
  - Added `onBeforeDeleteUser?: (userId: string, ctx: { req: Request; source: 'self' | 'admin' }) => Promise<void> | void` to `RouterOptions`, `AdminOptions`, and `AuthConfiguratorOptions`.
  - Awaited before sessions are revoked and before the user record is deleted in `DELETE /auth/account` (`source: 'self'`) and in admin `DELETE /admin/api/users/:id` (`source: 'admin'`).
  - If the hook throws, deletion is aborted immediately with HTTP 500, preserving user, sessions, RBAC, and metadata intact.
- **Server-side and admin email verification triggers** (Issue #24):
  - Added `AuthConfigurator.sendVerificationEmail(userIdOrEmail, opts?: { emailLang?: string; siteUrl?: string; routerOptions?: RouterOptions }): Promise<{ sent: boolean; reason?: 'already_verified' | 'not_found' }>`. Re-uses the configured 24h token expiry, store update, and mailer callback.
  - Added admin endpoint `POST /admin/api/users/:id/send-verification-email` (with alias `/users/:id/send-verification-email`), returning 200 on success, 400 if already verified, 404 if not found, and 500 if unconfigured.
  - Exported `performSendVerificationEmail`, `DeleteUserContext`, `BeforeDeleteUserHook`, `SendVerificationEmailOptions`, `SendVerificationEmailResult`.

### Fixed
- **Input robustness on body-less POST and PATCH requests** (Issue #21):
  - Replaced direct `req.body` destructuring across all auth router, admin router, and tools router endpoints with safe `(req.body ?? {})` fallback.
  - Prevented 500 `TypeError` crashes when authenticated POST/PATCH requests are submitted without a body or without `Content-Type: application/json`.
  - `POST /auth/send-verification-email`, `PATCH /auth/profile`, and `POST /auth/logout` without a body now succeed with HTTP 200.
  - Requests missing required fields across all other endpoints return HTTP 400 with a descriptive error message instead of crashing with HTTP 500.

### Documentation
- **Security clarification on `node:vm` sandbox boundary** (Issue #10):
  - Clarified in `README.detailed.md` that Node.js's built-in `node:vm` is not a secure isolation sandbox, warning that dynamic inbound webhook scripts (`jsScript`) must only be authored and managed by trusted system administrators.

---

## [1.10.4] — 2026-09-28

### Security
- **OAuth start return_path validation and restriction** (Issue #22):
  - Strictly validate `req.query.return_path` on start endpoints (`/oauth/google`, `/oauth/github`, `/oauth/:name`):
    - Must start with a single `/` (rejects protocol-relative `//` and absolute URLs).
    - Rejects backslashes (`\`) and control characters (`[\x00-\x1f\x7f]`).
    - Enforces maximum length of 512 characters.
    - Invalid syntax returns HTTP 400 (`OAUTH_RETURN_PATH_INVALID`) immediately with no cookie set.
  - Added `allowedReturnPaths?: (string | RegExp)[]` option in `AuthConfig['oauth']` and `RouterOptions` to restrict permitted redirect targets (e.g. `['/oauth/done']`).
- **Cryptographic state binding and expiry** (Issue #22):
  - Structured OAuth state parameter now embeds `{ n, o, p, exp, s }` where `exp` is a 10-minute expiry timestamp and `s` is an HMAC-SHA256 signature binding the nonce, origin, return path, and expiry via `config.accessTokenSecret`.
  - Callback endpoints verify state freshness (`Date.now() <= exp`) and cryptographically verify the signature before token exchange. Tampered `p` or expired state returns HTTP 400 (`INVALID_OAUTH_STATE`) without calling provider strategy callback.
  - Re-validate `return_path` against syntax and `allowedReturnPaths` on callback.
- **Production origin allowlist enforcement** (Issue #22):
  - When origin allowlist (`allowedOrigins`) is empty in production mode (`NODE_ENV === 'production'`), OAuth start endpoints refuse initiation with HTTP 500 (`OAUTH_ORIGIN_ALLOWLIST_EMPTY`) and no cookie is set.
  - Callbacks refuse to trust arbitrary origins from state when allowlist is empty in production.

---

## [1.10.3] — 2026-09-28

### Security
- **OAuth state nonce CSRF protection completed** (Issue #14):
  - Strictly enforce matching cookie and state nonce across Google, GitHub, and generic strategies.
  - Return HTTP 400 (`INVALID_OAUTH_STATE`) on missing cookie, missing state parameter, or mismatched nonces via constant-time comparison (`crypto.timingSafeEqual`).
  - Scoped state cookie to the callback path.
- **Refresh token multi-device security** (Issue #13):
  - Disallow `refreshTokenSecret === accessTokenSecret` when a `sessionStore` is configured (throws fast on router construction).
  - Always validate active session existence in the store during `/refresh` even when `checkOn: 'none'`, rejecting revoked sessions with `401 SESSION_REVOKED`.
  - Validate session ownership matches token subject (`session.userId === payload.sub`).
  - Propagate `revokeSession` store failures during `/refresh` as an HTTP 500 error instead of swallowing, preventing old rotated tokens from remaining replayable.

### Fixed
- **Multi-device session isolation** (Issue #13):
  - Skip `userStore.updateRefreshToken` unconditionally when `sessionStore` is configured, preventing cross-device session overwrite.
- **OAuth conflict redirect & 4xx robustness** (Issues #15, #16):
  - Prevent return_path pollution during account conflict redirects.
  - Safe URI error handling and defensive `req.body` handling on admin routes.

---

## [1.10.2] — 2026-09-27

### Security
- **OAuth state nonce CSRF protection** (Issue #14):
  - OAuth initiation routes (`/oauth/google`, `/oauth/github`, generic strategies) set an `HttpOnly`, `SameSite=Lax` cookie scoped to the callback path.
  - Callback endpoints strictly validate that the cookie is present and constant-time matches (`crypto.timingSafeEqual`) the `state` parameter nonce, returning HTTP 400 (`INVALID_OAUTH_STATE`) on missing cookie, missing state, or mismatched nonces, effectively preventing Login CSRF.
- **Refresh token security & secret separation** (Issue #13):
  - `createAuthRouter` now throws an error if `refreshTokenSecret === accessTokenSecret` when a `sessionStore` is configured.
  - Revocation failure (`revokeSession`) during `/refresh` properly propagates as an HTTP 500 error instead of being swallowed, preventing old rotated tokens from remaining replayable.

### Added
- **Multi-device session isolation and singleSessionPerUser option** (Issue #13):
  - With a `sessionStore` configured, refresh tokens are tracked per session and never written to the user record (`userStore.updateRefreshToken` is never called with a non-null token).
  - `/refresh` always validates active session existence in the store even when `checkOn: 'none'`, rejecting revoked sessions with `401 SESSION_REVOKED`.
  - Session ownership is strictly verified against token subject (`session.userId === payload.sub`).
  - Added optional `singleSessionPerUser` (and alias `singleSession`) in `AuthConfig['session']`. When set to `true`, logging in from a new device automatically terminates all previous active sessions for the user.
  - Added optional `updateSessionRefreshTokenHash?(sessionHandle, hash)` to `ISessionStore`.

### Fixed
- **OAuth account conflict redirect path pollution** (Issue #15):
  - Account conflict redirects now resolve cleanly to the base site origin (`conflictOrigin`), preventing URL path pollution when the OAuth flow was initiated with a custom `return_path` or `returnTo`.
- **HTTP 4xx input robustness against 500 server crashes** (Issue #16):
  - Cookie parsing safely catches `URIError` when malformed percent sequences (such as `%` or `%ZZ`) are supplied, returning 401/403 rather than throwing unhandled 500 errors.
  - Admin router endpoints safely guard against missing or non-object `req.body` with `(req.body ?? {})`, returning HTTP 400 with descriptive error messages.
  - Admin router list query parameters (`limit`, `offset`, `filter`) safely handle repeated query parameters without producing `NaN` or unhandled exceptions.

---

## [1.10.1] — 2026-09-25

### Changed
- The package is now published as **`@awesome-lang-auth/node`**, with no API change: the API, the HTTP routes and the served UI are those of 1.10.0. `awesome-node-auth` will remain available as a deprecated alias that depends on `@awesome-lang-auth/node` (published separately).
- Migration: replace the dependency (`npm uninstall awesome-node-auth && npm install @awesome-lang-auth/node`) and change the import specifier from `'awesome-node-auth'` to `'@awesome-lang-auth/node'`, in `import` and `require()` alike.
- The repository moved to the `awesome-lang-auth` GitHub organization: <https://github.com/awesome-lang-auth/awesome-node-auth>. `repository` and `bugs` in `package.json` point there.
- README, README.detailed, the examples, the demos and the doc comments use the new package name; the demos depend on `@awesome-lang-auth/node` `^1.10.1`.
- The publish workflow skips `npm publish` when the `package.json` version is already on the registry.

### Fixed
- The auth UI and admin panel asset lookup also tries `node_modules/@awesome-lang-auth/node/{dist/ui-assets,src/ui/assets}` under the working directory, before the old `node_modules/awesome-node-auth/…` paths. That fallback is the one a bundled server (esbuild, webpack) reaches when `__dirname` no longer points into the package; without it, a bundled app on the new name served 404 for the UI and the admin CSS and JS.

---

## [1.10.0] — 2026-09-25

### Added

#### One-call mounting and admin bootstrap
- **`AuthConfigurator.buildAllRouters(options)`** — mounts the auth router at the API prefix and the admin router at `<apiPrefix>/admin` in a single router; the admin `jwtSecret` defaults to `AuthConfig.accessTokenSecret`. New exported types `BuildAllRoutersOptions` and `AuthConfiguratorOptions` (optional third constructor argument, `{ eventBus }`). `BuildAllRoutersOptions.admin` requires `accessPolicy` or a non-empty legacy `adminSecret`.
- **`AuthConfigurator.promoteToAdmin()` / `revokeAdmin()`** — grant or remove admin access by role (`rbacStore`, the default) or by the `isAdmin` flag (`IUserStore.update`); `revokeAdmin` also accepts `method: 'both'`, which needs both stores. Both helpers throw on an unknown `method`, and a revocation checks its prerequisites first and throws before changing anything when a store is missing.
- **`POST /api/users/:id/promote`** on the admin router — HTTP equivalent of `promoteToAdmin` (`{ method?: 'role' | 'flag' }`; `400` on any other `method`). It requires a JSON body (`415` otherwise). The same route without `/api`, `POST /users/:id/promote`, is a deprecated alias (see Deprecated).
- **`IUserStore.update?(userId, patch)`** — optional partial update, used by the flag-based promote/revoke.
- **`AuthorizedAdminUser`** type — the admin guard loads the user's roles from `rbacStore` before evaluating `accessPolicy`; custom policies and `req.user` receive `BaseUser & { roles: string[] }`.
- **`AdminOptions.eventBus`**, **`AdminOptions.rateLimiter`** (applied to the promote endpoint) and **`AdminOptions.silent`** (suppresses the startup tab summary).

#### Registration
- **`RouterOptions.defaultRegister`** — opt-in built-in handler for `POST /register` when `onRegister` is omitted (never in Resource Server mode). It requires `email` and `password` (`400 INVALID_INPUT` otherwise), refuses an address that `userStore.findByEmail` already finds (`409 USER_EXISTS`, nothing created), hashes the password and stores an allow-list of fields: `email`, the password hash, and `firstName` / `lastName` when they are strings. Every other field of the request body is dropped. Without `onRegister` or `defaultRegister` the route is not mounted, as in 1.9.0; the built-in UI and the OpenAPI spec follow the same rule.

#### Event publication
- **Automatic event publication** — when an `AuthEventBus` is passed (`RouterOptions.eventBus`, `AdminOptions.eventBus`, or `AuthConfiguratorOptions.eventBus`), the auth router publishes login success/failure, logout, session rotation, registration, 2FA enable/disable, password change, email verification, email change, account deletion and OAuth success/conflict events, and the admin router publishes `ROLE_ASSIGNED` / `ROLE_REVOKED`. `AuthConfigurator.promoteToAdmin()` / `revokeAdmin()` publish `ROLE_ASSIGNED` / `ROLE_REVOKED` as well (no request context). Router payloads include `ip`, `userAgent` and `correlationId` (`X-Correlation-Id`, kept only when it is 1–128 characters of `[A-Za-z0-9_.:-]`). A client-supplied `email` is kept only as a string of at most 320 characters, `AUTH_OAUTH_CONFLICT` carries `provider`, `email` and `providerAccountId` only, and the admin router's `ROLE_ASSIGNED` / `ROLE_REVOKED` carry the acting admin as `data.actorId`. A listener that throws is reported on `stderr` and does not fail the request.
- **`AuthEventNames.USER_EMAIL_CHANGED`** (`identity.user.email.changed`) — published by `POST /change-email/confirm` with `{ oldEmail, newEmail }`.
- **`AuthToolsOptions.sseDistributor`** — custom `ISseDistributor` used by `AuthTools.notify()` instead of the built-in `SseManager` broadcaster. It receives a complete `StreamEvent` (`id`, `timestamp`, `topic`), so it can also feed an `SseManager` through `sseOptions.distributor`.

#### Tokens
- **`TokenService.generateTempToken()` / `verifyTempToken()`** — mint and verify the 2FA step-up token (`tempToken`, 5 minutes, `purpose: '2fa'` claim). `verifyTempToken` accepts only that token.

#### Tests
- `tests/dx-improvements.test.ts`, `tests/register-default-handler.test.ts` (`REGRESSION-REGISTER-MASS-ASSIGNMENT`, `REGRESSION-REGISTER-EXISTING-EMAIL`) and `tests/router-events.test.ts` (event payloads), plus event-publication, built-in register handler and `sseDistributor` coverage in `auth.router`, `auth-flow-improvements`, `new-features`, `swagger` and `tools` suites.
- `tests/two-factor-token.test.ts` (`REGRESSION-2FA-ADMIN-GUARD`), `tests/admin-guard.test.ts` (`REGRESSION-ADMIN-GUARD-HTML-ACCEPT`, empty `adminSecret`), `tests/admin-promote.test.ts`, `tests/session-check.test.ts`, `tests/cookie-max-age.test.ts`, `tests/logout-bearer.test.ts`, `tests/link-request-csrf.test.ts` and `tests/cors-headers.test.ts`.

#### Docs
- README: `buildAllRouters()` quick start, "Admin UI", "Two login endpoints, two audiences" and "Ecosystem".
- README.detailed: `buildAllRouters()`, admin policy and `AuthorizedAdminUser`, `promoteToAdmin`/`revokeAdmin`, the promote endpoint, automatic event publication, `USER_EMAIL_CHANGED`, `IUserStore.update?()`, `sseDistributor` and the built-in register handler (`defaultRegister`).

### Changed
- OAuth logins set `loginProvider` to the provider name when the user record has none, so the `loginProvider` token claim is the provider instead of `'local'` (OAuth logins completed without a 2FA step).
- The auth and admin routers write startup `INFO`/`WARN` lines to `stderr` (built-in register handler status when `defaultRegister` is set, enabled admin tabs); `AuthTools` warns when both `sse: true` and `sseDistributor` are set.
- The admin panel sign-in form points end users to `/auth/ui/login`.
- A `purpose` claim returned by `buildTokenPayload` is dropped from the access and refresh tokens: the library reserves it to mark tokens that are not sessions (`'2fa'`, `'admin'`).
- `package-lock.json` refreshed within the existing dependency ranges.

### Deprecated
- `POST <admin>/users/:id/promote` (without `/api`) — alias of `POST <admin>/api/users/:id/promote`, with the same rate limiter, guard, JSON-body requirement and answers. Use the `/api` path.

### Removed
- Documentation of the retired MCP server, and its npm keywords (`mcp`, `model-context-protocol`, `cursor-mcp`, `vscode-mcp`, `antigravity-mcp`).
- The `sync:public` npm script: development now happens in this repository.

### Fixed
- `session.checkOn: 'allcalls'` now applies to the auth router's own protected routes (`/me`, `/sessions`, `/change-password`, ...): the router passes its `sessionStore` to its access-token middleware, so a revoked session gets `401 SESSION_REVOKED` on the next call, and the session's last-active time is updated there.
- The `accessToken` and `refreshToken` cookies live as long as the tokens they carry (`accessTokenExpiresIn` / `refreshTokenExpiresIn`) instead of a fixed 15 minutes / 7 days. The defaults are unchanged (`Max-Age=900` / `604800`); the CSRF cookie keeps 15 minutes, so with `csrf.enabled` and a longer `accessTokenExpiresIn` a state-changing request made after 15 minutes gets `403 CSRF_INVALID` until the client refreshes (see README.detailed, CSRF Protection).
- `POST /link-request` exempts requests with an `Authorization: Bearer` credential from its CSRF check, like `auth.middleware()`, and then identifies the user from the bearer token only. Cookie-authenticated and anonymous conflict-linking requests are still checked. (#4)
- The auth router's CORS layer allows the `X-Auth-Strategy` request header, so browser apps on a listed origin can use bearer mode. (#5)
- The Next.js demo's edge middleware and the edge-middleware snippet in `examples/nextjs-integration.example.ts` check the token expiry and refuse tokens that are not sessions (`purpose` claim), not only the signature.

### Security
- `POST /register`: `config.email.sendWelcome(to, data)` no longer receives the plaintext `password` in `data`, with a custom `onRegister` as well as with the built-in handler.
- The built-in register handler is opt-in (`defaultRegister`) and persists an allow-list of fields only.
- The 2FA step-up token (`tempToken`) is no longer accepted as a session token: `auth.middleware()`, the admin router and every route behind them refuse it, and the 2FA completion endpoints accept only that token. The `tempToken` of a `2FA_SETUP_REQUIRED` answer no longer opens the enrolment routes. A 2FA challenge started before the upgrade must be restarted. Upgrading is recommended.
- The admin console token issued by `POST <admin>/login` is accepted by the admin router only, not as an application session; the admin guard honours `isRoot` only on that token, and a `purpose` claim returned by `buildTokenPayload` is dropped from session tokens, so they cannot pass for it. The admin sign-in still checks the password only (no second factor): set `loginPath` to the application login to send operators through its 2FA flow, and restrict `POST <admin>/login`, which stays mounted, at the proxy.
- A root or bootstrap admin console session (`rootUser` / `adminSecret` sign-in) issued by 1.9.0 is refused after the upgrade and needs one new sign-in; the panel shows its sign-in form, or redirects to `loginPath`. Other admin console sessions stay valid until they expire.
- The session-based admin guard answers `401` to every unauthenticated request for the admin REST API, whatever its `Accept` header; only the HTML panel redirects to `loginPath` or shows its sign-in form, also when a validly signed token names no stored user.
- `createAdminRouter()` throws a configuration error when `adminSecret` is present but empty and no `accessPolicy` is set, instead of mounting unprotected routes.
- `POST /logout` also ends the session of bearer clients: it reads the access token from the `Authorization: Bearer` header and accepts the current refresh token in the body, then revokes the session and the stored refresh token. (#3)

---

## [1.9.0] — 2026-04-29

### Added

#### Identity Provider (IdP) mode — RS256 + JWKS
- **`idProvider` config block** — enables RS256-signed JWTs and exposes a public JWKS endpoint (`GET /.well-known/jwks.json` by default). When `privateKey` is omitted an ephemeral RSA-2048 keypair is auto-generated at startup (dev only).
- **`resourceServer` config block** — turns any instance into a downstream Resource Server that validates Bearer tokens via JWKS without sharing secrets.
- **`JwksService`** static class — `generateKeypair()`, `derivePublicKey()`, `publicKeyToJwk()`, `buildJwksDocument()`, `jwkToPublicKey()`, `createRemoteClient()`; all using Node.js built-in `crypto`.
- **`JwksClient`** — cached JWKS fetching with stale-while-revalidate TTL, `getKey(kid)` lookup, and automatic cache invalidation on unknown `kid` for seamless key rotation.
- **`createJwksAuthMiddleware()`** — auth middleware for Resource Servers: Bearer → JWKS RS256 validation; cookie fallback → local HS256 for SSR dashboard pages.
- **`TokenService.generateIdProviderTokenPair()`** — issues RS256-signed access **and** refresh tokens with `iss` claim and `kid` JOSE header parameter (RFC 7515 §4.1.4).
- **`TokenService.verifyWithJwks()`** — validates a token via `JwksClient`, enforces issuer, retries with cache invalidation on key rotation.
- **`IdProviderConfig` / `ResourceServerConfig`** interfaces — exported from the main entry point.
- **New exports**: `JwksService`, `JwksClient`, `JWK`, `JwksDocument`, `JwksClientOptions`, `createJwksAuthMiddleware`, `IdProviderConfig`, `ResourceServerConfig`.
- **26 new tests** — `tests/jwks.service.test.ts` (18) and `tests/jwks-auth.middleware.test.ts` (8) covering the full IdP/RS surface.
- **Zero new npm dependencies** — implemented entirely with Node.js built-in `crypto` and `https` modules.

> **Spec note:** `kid` is a JOSE header parameter (RFC 7515 §4.1.4), not a JWT payload claim. Both access and refresh tokens are RS256-signed in IdP mode to prevent HS256 downgrade attacks on the refresh flow.

#### Flutter client support
- **`awesome-node-auth-flutter`** package support added to MCP server docs, tools, and prompts — guides agents through integrating the Dart/Flutter client with a node-auth backend.

#### MCP server — v1.9.0 updates
- **`setup-idp-mode` prompt** — guides agents through Provisioner and/or Resource Server setup, keypair generation, JWKS verification, and the full docker-compose scaffold.
- **`scaffold_idp_project` tool** — generates a ready-to-run Provisioner + Resource Server skeleton (or both with a shared `docker-compose.yml` and `.env.example`).
- **`docs.ts` resource** — new IdP mode section covering `IdProviderConfig`, `ResourceServerConfig`, `JwksService` API, `createJwksAuthMiddleware`, key rotation, and production checklist.
- Version fallback in `mcp-server/src/tools/version.ts` bumped to `1.9.0`.

#### Wiki
- **`advanced/idp-mode.md`** — new page covering architecture, config reference, token signing behaviour, JWKS endpoint, Resource Server validation, key rotation, and security checklist.
- `sidebars.ts` updated to include `advanced/idp-mode`.
- `advanced/index.md` table updated with IdP Mode row.
- `wiki/package.json` bumped to `1.9.0`.

---

## [1.8.4] - 2026-04-18

### Fixed
- **Admin panel — Email & UI Templates tab (silent failures)**: the template catalogue in the admin UI listed `email-verification` (non-existent) and the spurious `otp` ID while omitting `welcome` and `email-changed`. Customisations appeared saved but were never applied because `MailerService` looks up different IDs. All six IDs (`magic-link`, `password-reset`, `verify-email`, `welcome`, `email-changed`, `invitation`) now match `MailerService.render()` exactly.
- **Admin panel — UI translations pages list drift**: `sms-login` (no HTML file) and `common` (not queried by the UI router) have been removed; `magic-link`, `link-verify`, and `account-conflict` have been added. Each page now carries its exact `data-i18n` keys extracted from the corresponding HTML file.
- **Admin panel — CSS classes missing**: all class names referenced by the Templates tab JavaScript (`template-grid`, `template-list`, `template-item`, `template-editor-*`, `template-preview-*`, `template-vars`, `template-var-chip`, `translation-grid`, `translation-lang-*`) are now defined in `admin.css`.
- **`MailerService.render()`**: templates stored with empty `baseHtml` or `baseText` (e.g. after pressing "Reset to default" in the admin panel) now correctly fall back to the built-in template instead of rendering an empty email.

### Added
- **Admin panel — Live preview**: the template editor now renders a sandboxed `<iframe srcdoc>` preview in real time, interpolating `{{VAR}}` and `{{T.key}}` with labelled sample values. The subject line is displayed above the preview. `sandbox=""` prevents scripts, forms, and navigation entirely.
- **Admin panel — Translations key/value grid**: the raw JSON textarea for translations has been replaced with a per-language tab + key/value grid. Languages and keys can be added/removed without touching JSON. Shared by both the email template and UI translations editors.
- **Admin panel — Click-to-insert variable chips**: each template exposes its `{{VAR}}` and `{{T.key}}` placeholders as clickable chips; clicking one inserts it at the cursor position in the focused textarea.
- **Admin panel — Reset to default button**: clears `baseHtml`, `baseText`, and `translations` in the store so `MailerService` falls back to its built-in template.
- **`scripts/extract-i18n-keys.js`**: new build script that reads every HTML page in `src/ui/assets/` and writes `src/ui/assets/ui-i18n-keys.json` — a static map of `page → data-i18n keys`. Run via `npm run extract-i18n` (also executed automatically during `npm run build`).

---


## [1.8.3] — 2026-04-02

### Fixed
- **Admin UI JS** — fixed a regression where the Admin UI was not rendering the admin panel

---

## [1.8.2] — 2026-04-01

### Added
- **Self-Contained Admin Authentication** — the Admin UI now handles its own login and logout via internal `POST /admin/login` and `POST /admin/logout` routes. This removes dependencies on the main application's auth router, making the Admin Panel truly autonomous.
- **Root/Bootstrap User Support** — added `AdminOptions.rootUser` (email + password hash) for permanent emergency access.
- **Bootstrap Mode** — if `adminSecret` is configured, the Admin login form allows password-only access (leaving email blank).
- **Dynamic Cookie Prefix Detection** — the admin guard now automatically detects and handles secure cookie prefixes (`__Host-`, `__Secure-`) based on the environment and `AdminOptions.cookiePrefix`.

### Fixed
- **Admin UI Logout** — fixed a regression where the logout button would attempt to call the main auth API instead of the local admin logout handler.
- **Cookie Prefix Conflicts** — resolved issues where admin sessions were not persisted correctly when running behind a proxy or in production with secure cookies.

---

## [1.8.1] — 2026-04-01

### Added
- **Built-in Admin Login Fallback** — the Admin UI now includes a native login form (Email + Password) that appears when a user is not authenticated. This allows the Admin Panel to function in "zero-config" mode for headless or SPA-only projects without requiring a custom login path.

### Changed
- **`AuthRequestHandler` return type** — relaxed from `void | Promise<void>` to `any`. This improves compatibility with many common third-party Express middlewares (like `express-rate-limit`) that may return `unknown` or non-standard types.
- **Admin Security Enforcement** — `accessPolicy` and `jwtSecret` are now strictly required in `createAdminRouter`.
- **MCP Server Templates** — updated all code generators to use the standard `AuthConfigurator` and `createAdminRouter` patterns, removing dependencies on deprecated factory functions.
- **`.env.example`** — removed `AUTH_ADMIN_SECRET` and added `ADMIN_LOGIN_PATH` documentation.

### Fixed
- **TypeScript Error 2322** in `mcp-server` and other integration points where `RateLimitRequestHandler` was not assignable to `AuthRequestHandler`.
- **Angular SSR Template** — removed defunct `createNodeAuth` factory and restored manual setup in MCP scaffolding.

### Removed
- **`adminSecret` support** — the deprecated static password has been fully removed in favor of the session-based `accessPolicy`.

---

## [1.8.0] — 2026-03-30

### Added
- **`NotificationService`** (`src/services/notification.service.ts`) — lightweight facade
  wrapping `MailerService` and `SmsService`; accepts `email` and `sms` config independently
  so notification capabilities can be passed to `AuthTools` without exposing the full `AuthConfig`.
- **Multi-channel `notify()`** — `AuthTools.notify()` is now `async` and accepts an optional
  `channels?: ('sse' | 'email' | 'sms')[]` array in `NotifyOptions`.  Email and SMS channels
  require `userStore`, `emailConfig`/`smsConfig` in `AuthToolsOptions` respectively.
  Defaults to `['sse']` — fully backward-compatible.
- **`AdminAccessPolicy`** type — `'first-user' | 'is-admin-flag' | 'open' | (user, rbacStore?) => boolean`;
  exported from the main package entry point.
- **Session-based Admin UI guard** — new `buildPolicyGuard()` middleware validates the app JWT
  and evaluates `accessPolicy`.  Unauthenticated browser requests are redirected automatically to
  `/auth/ui/login?redirect=<adminPath>` (302); API requests receive 401.
- **`BaseUser.isAdmin?: boolean`** — convenience flag used by the `'is-admin-flag'` policy.
- **`MailerService.sendCustom()`** — sends arbitrary business emails using the configured mailer
  transport (subject, HTML, plain-text).
- **`AuthToolsOptions.userStore?`** — optional `IUserStore` for resolving contact details in
  multi-channel notify.
- **`AuthToolsOptions.emailConfig?`** / **`AuthToolsOptions.smsConfig?`** — transport configs
  for email/SMS notification channels; accept the same shape as `MailerConfig` / `SmsConfig`.

### Changed
- `AdminOptions.adminSecret` is now **optional** and **deprecated**.  The field remains fully
  functional for backward compatibility but will be removed in a future major version.
  Migrate to `accessPolicy` + `jwtSecret` as described in the Admin Panel guide.
- `AdminOptions` now exposes `accessPolicy?: AdminAccessPolicy` and `jwtSecret?: string`.
- Admin HTML (`buildAdminHtml`) omits the secret-input login screen when `accessPolicy` is set
  (`sessionBased: true`); the server-side guard handles authentication before serving the page.
- MCP code generators (`backend.ts`, `scaffold.ts`, `test-generator.ts`) now emit
  `accessPolicy: 'first-user'` + `jwtSecret` instead of `adminSecret` + `ADMIN_SECRET`.
- `env-generator.ts` no longer emits an `ADMIN_SECRET` variable; replaced with a comment
  explaining that session-based auth is used.
- `mcp-server/src/resources/docs.ts` and `prompts/index.ts` updated to document the new
  access policy system and remove `ADMIN_SECRET` instructions.
- `wiki/docs/advanced/admin.md` rewritten: auth-flow diagram updated, setup examples use
  `accessPolicy`/`jwtSecret`, migration tip added.
- `wiki/docs/advanced/auth-tools.md` updated: `notify()` section extended with email/SMS
  channel examples and configuration.

### Fixed
- Admin router no longer warns about missing `adminSecret` when `accessPolicy` is provided.

---

## [1.7.0] — 2026-03-30

### Added
- **Framework-agnostic HTTP types** (`src/http-types.ts`) — `AuthRequest`, `AuthResponse`,
  `AuthNextFunction`, `AuthRequestHandler`, `AuthRouter` interfaces with zero framework
  dependencies, exported from the main package entry point.
- **Express adapter** (`src/adapters/express.ts`) — `expressAdapter()` zero-overhead cast
  from `AuthRequestHandler` to Express `RequestHandler`; re-exports `Router`, `RequestHandler`,
  `Request`, `Response`, `NextFunction` from Express for convenience.
- **Fastify adapter** (`src/adapters/fastify.ts`) — `fastifyAdapter()` wraps an
  `AuthRequestHandler` as a Fastify `preHandler` hook via `req.raw` / `reply.raw`;
  no extra dependencies required.
- **`awesome-node-auth://guides/framework-agnostic`** MCP resource — guide covering Express,
  NestJS, Next.js App Router, and custom adapter patterns.
- **`examples/fastify-integration.example.ts`** — reference Fastify integration showing
  middleware-only, full-router (`@fastify/express`), and manual token-service patterns.

### Changed
- `RouterOptions.rateLimiter` now typed as `AuthRequestHandler` instead of `RequestHandler`
  (Express `RequestHandler` remains directly assignable — no breaking change).
- `AuthRequestHandler` JSDoc extended with `@example`, `@since 1.7.0`, and a full
  explanation of the TypeScript contravariance reason for using `any` parameters.
- `examples/nestjs-integration.example.ts` updated: `JwtAuthGuard` and `CurrentUser`
  decorator now use the framework-neutral `AuthRequest` type instead of `import { Request }
  from 'express'`.

### Fixed
- MCP server: corrected stale endpoint names across `docs.ts`, `prompts/index.ts`,
  `test-generator.ts` (`/magic-link/request` → `/magic-link/send`, `2fa/login` → `2fa/verify`,
  `sms/request` → `sms/send`).
- `wiki/docs/frameworks/framework-agnostic.md`: replaced inaccurate "Express `RequestHandler`
  is structurally assignable to `AuthRequestHandler`" with a technically-correct contravariance
  explanation.

---

## [1.6.0] — 2026-03-21

### Added
- **`ITemplateStore`** — optional interface for dynamic, per-language email templates and UI i18n, with a built-in `MemoryTemplateStore` in-memory implementation.
- **Dynamic email templates** — `MailerService` now resolves templates through the store before falling back to the built-in en/it templates; supports `{{T.key}}` translation interpolation and `{{VAR}}` data interpolation in subject, HTML and plain-text bodies.
- **UI i18n** — `buildUiRouter` accepts an optional `templateStore`; `auth.js` `applyTranslations()` patches `data-i18n` elements at runtime while keeping the original hardcoded text as a safe fallback when no translation is found.
- **Admin "Email & UI" tab** — `createAdminRouter` activates a new template-editor tab (mail templates + UI translations) only when a `templateStore` is provided; REST endpoints `GET/POST /admin/api/templates/mail` and `GET/POST /admin/api/templates/ui`.

### Changed
- `AuthConfig.templateStore?: ITemplateStore` and `AdminOptions.templateStore?: ITemplateStore` added as optional fields (fully backward-compatible).
- `MailerService` constructor now accepts an optional `templateStore` as a second argument.

---

## [1.5.1] — 2026-03-19

### Fixed
- Fixed admin ui height

---

## [1.5.0] — 2026-03-18

### Added
- **Hybrid Stateful Sessions** (`ISessionStore`) — optional server-side session tracking layered on top of JWT, enabling real-time revocation without invalidating all tokens.
- **Session validation modes** — `session.checkOn: 'none' | 'refresh' | 'allcalls'`; `allcalls` validates the session on every authenticated request via the auth middleware.
- **User-facing session endpoints** — `GET /auth/sessions` (list own devices) and `DELETE /auth/sessions/:handle` (revoke a device), both guarded by auth middleware and ownership check.
- **Atomic session rotation** — on `POST /auth/refresh` the old session handle is revoked and a new one is issued atomically; the `sid` claim in the JWT tracks the handle.
- **L1/L2 caching helpers** — `RedisSessionStore` (L2 Redis-backed) and `L1CachedSessionStore` (in-process LRU decorator) for high-throughput session validation.
- **`SESSION_REVOKED` loop protection** — `auth.js` fetch interceptor and Angular HTTP interceptors now detect `code: 'SESSION_REVOKED'` on a 401 and force an immediate local logout instead of looping through refresh retries.
- **`getActiveSessions()` / `revokeSession(handle)`** in `ng-awesome-node-auth` Angular service for "Manage devices" UI.
- **`SessionInfo` interface** exported from the Angular library.

### Changed
- `auth.middleware` updated to perform real-time session validation when `checkOn: 'allcalls'` is configured.
- JWT payload now includes `sid` (session ID) claim when a `sessionStore` is configured.
- `auth.js` `refresh()` public method returns `false` immediately for `SESSION_REVOKED` responses.

### Fixed
- Infinite refresh loop: `refreshResult.success !== false` incorrectly treated `{code:'SESSION_REVOKED'}` (no `success` field) as a successful refresh.
- Session expiry now reads `session.expiresIn` from `AuthConfig` rather than defaulting to a hard-coded 7-day value.

---

## [1.4.2] — 2026-03-17

### Fixed
- `__Host-` cookies require `Path=/` per the RFC; the refresh-token cookie path was incorrect under certain route prefixes, causing browsers to reject it.
- Added integration tests for `__Host-` / `__Secure-` cookie path compliance.

---

## [1.4.1] — 2026-03-17

### Changed
- `auth.js` fetch interceptor switched from path-prefix matching to **origin-based credential matching**, preventing credential leakage to unrelated origins (e.g., a LiteLLM proxy on a different port).

### Fixed
- `auth.js` was inadvertently intercepting requests to third-party origins when running alongside a Docusaurus wiki or AI proxy on the same page.

---

## [1.4.0] — 2026-03-17

### Added
- **Headless UI mode** (`ui.headless: true`) — the built-in UI router serves `auth.js` and CSS assets but returns 404 for HTML pages; ideal for SPAs and wiki integrations that provide their own UI. The `/config` endpoint includes `headless: true` for the client to detect the mode.
- `window.AwesomeNodeAuth` singleton with a public `refresh()` API, exposing token refresh to external scripts without re-entrant loops.

---

## [1.3.0] — 2026-03-14

### Added
- **CSRF cookie-tossing protection** — CSRF cookie now uses `__Host-` prefix (`__Secure-` when `secure` is true but running under a subdomain), preventing subdomain cookie-tossing attacks.
- **`ng-awesome-node-auth` Angular library** — first official Angular integration guide with `AuthService`, `authInterceptor` (CSRF + refresh queue), `APP_INITIALIZER`, and SSR support.
- **Built-in UI documentation** — comprehensive reference for the zero-dependency HTML/CSS/JS login UI.
- **Admin panel platform settings** — configurable per-platform feature flags exposed through the admin UI.
- MCP server tools: `get_mailer_integration`, `get_sms_integration`, `get_ui_customization`, `get_email_templates`, `get_ng_awesome_node_auth`.

### Fixed
- `__Host-` / `__Secure-` CSRF and access-token cookie prefix handling in `auth.js`, Angular interceptors, and MCP server.

---

## [1.2.x] — 2026-03-10 to 2026-03-11

### Added
- **Built-in UI** (`<apiPrefix>/ui/`) — zero-dependency HTML/CSS/JS login, register, forgot-password, and reset-password pages served directly by the library.
- Live preview and full customization of the built-in UI (background color, card color, logo, background image) via the admin panel.
- CSS custom properties (`--auth-bg-color`, `--auth-card-bg`, etc.) for theme overrides.
- Spinner and improved loading states in the built-in login page.
- 87 unit tests for `auth.js` browser client API.
- `window.AwesomeNodeAuth` documented browser client API.

### Fixed
- `refreshToken` path auto-derivation now works correctly relative to `apiPrefix`.
- Admin UI XSS/escape bug in dashboard string interpolation.
- Asset loading and auth routing prefix hierarchy.

---

## [1.1.x] — 2026-02-21 to 2026-03-07

### Added
- **Email verification** — three modes: `none` (disabled), `lazy` (grace period configurable), `strict` (login blocked until verified).
- **Change email** — `PATCH /auth/change-email` with re-verification flow.
- **Change password** — `PATCH /auth/change-password`.
- **Admin panel** — HTML-based admin dashboard at `/admin/` with user listing, filtering, pagination, batch operations, and per-user detail view; tabs for metadata, roles, tenants, linked accounts, API keys, webhooks.
- **User metadata** (`IUserMetadataStore`) — arbitrary per-user key/value store surfaced in `/me` and admin panel.
- **Roles & permissions** (`IRolesPermissionsStore`) — RBAC with optional tenant scope; roles/permissions returned in `/me`.
- **Session management** (`ISessionStore`) — interface for listing and revoking sessions; optional `POST /auth/sessions/cleanup` for cron-based expiry.
- **Multi-tenancy** (`ITenantStore`) — isolated multi-tenant applications with tenant-scoped roles.
- **Account deletion** — `DELETE /auth/account` self-service endpoint with full cleanup hooks.
- **CSRF protection** — double-submit cookie pattern, opt-in via `csrf.enabled`.
- **Bearer token strategy** — `X-Auth-Strategy: bearer` header enables JSON body token delivery instead of HttpOnly cookies.
- **Custom JWT claims** — `buildTokenPayload` callback for injecting project-specific claims.
- **Provider parameter in mailer** — pass the auth provider to email templates.
- `IUserStore.updateLastLogin()` optional method.
- Rate limiter support on `GET /me` and other sensitive endpoints via `RouterOptions.rateLimiter`.
- NestJS, Next.js, MySQL/MariaDB, and MongoDB integration examples in `examples/`.

### Fixed
- Admin dashboard HTML interpolation escaping.
- Refresh token cookie path bug.
- Login verification issues distinguishing SMS/magic-link direct login from 2FA mode.
- `deleteUser` implementation.

---

## [1.0.x] — 2026-02-21

### Added (Initial Release)
- **Core JWT authentication** — access + refresh token pair, HttpOnly cookie delivery.
- **Local strategy** — email/password login with bcrypt hashing.
- **Password reset** — `POST /auth/forgot-password` + `POST /auth/reset-password` with time-limited tokens.
- **OAuth 2.0** — Google and GitHub strategies; `GenericOAuthStrategy` base class for custom providers; `success_redirect_path` in OAuth state.
- **Magic links** — passwordless email login; first magic-link also counts as email verification.
- **SMS OTP** — phone-number verification via one-time codes.
- **TOTP 2FA** — time-based OTP compatible with Google Authenticator / Authy; `require2FA` flag per user.
- **`IUserStore` interface** — single decoupling point to any database.
- **`MailerService`** — HTTP transport mailer with Italian and English templates for password reset, magic links, email verification.
- **Express auth router** — all endpoints pre-wired at a configurable `apiPrefix`.
- **`auth.middleware()`** — JWT verification middleware accepting cookie or `Authorization: Bearer`.
- **`POST /auth/register`** — optional registration endpoint via `onRegister` callback.
- **`GET /auth/me`** — user profile endpoint.
- **Rate limiter hook** — `RouterOptions.rateLimiter` integration point.
- Full TypeScript types and exported interfaces.

---

## Version History Quick Reference

| Version | Date | Theme |
|---|---|---|
| 1.0.x | 2026-02-21 | Initial release — JWT, Local, OAuth, Magic Links, SMS, TOTP |
| 1.1.x | 2026-02-21–03-07 | Email verification, admin panel, metadata, RBAC, multi-tenancy, account mgmt |
| 1.2.x | 2026-03-10–11 | Built-in UI, CSS theming, admin UI customization, browser client tests |
| 1.3.0 | 2026-03-14 | CSRF cookie-tossing protection, Angular library, MCP tools expansion |
| 1.4.x | 2026-03-17 | Headless UI mode, origin-based fetch interceptor, `__Host-` cookie path fix |
| 1.5.0 | 2026-03-18 | Hybrid stateful sessions, device management API, SESSION_REVOKED loop fix |
| 1.6.0 | 2026-03-21 | Dynamic email templates, UI i18n, `ITemplateStore`, admin template editor |
| 1.7.0 | 2026-03-30 | Framework-agnostic HTTP types, Fastify adapter |
| 1.8.x | 2026-03-30–04-18 | Multi-channel notify, session-based admin auth, admin UI improvements |
| 1.9.0 | 2026-04-29 | IdP mode (RS256 + JWKS), Resource Server middleware, Flutter client support |
| 1.10.0 | 2026-09-25 | `buildAllRouters()`, admin promote/revoke, automatic event publication, 2FA and admin token hardening |
| 1.10.1 | 2026-09-25 | Published as `@awesome-lang-auth/node`; repository moved to the `awesome-lang-auth` organization |
