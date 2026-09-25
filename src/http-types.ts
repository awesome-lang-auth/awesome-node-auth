/**
 * Framework-agnostic HTTP primitives for awesome-node-auth.
 *
 * These interfaces capture the *minimal* surface that the library needs from
 * an HTTP request / response cycle.  They are intentionally a structural
 * superset of the corresponding Express types so that Express
 * `Request`/`Response` objects satisfy them without any cast.
 *
 * Non-Express adapters (Fastify, Koa, Hapi, …) can implement these interfaces
 * or wrap their native objects with the helpers exported from
 * `@awesome-lang-auth/node/adapters/express` and `@awesome-lang-auth/node/adapters/fastify`.
 *
 * @since 1.7.0
 */

// ─── Request ─────────────────────────────────────────────────────────────────

/**
 * Minimal request contract expected by awesome-node-auth middleware.
 *
 * @since 1.7.0
 */
export interface AuthRequest {
  /** HTTP headers (name → value or array of values). */
  headers: Record<string, string | string[] | undefined>;
  /** Parsed cookies — requires a cookie-parser or equivalent. */
  cookies?: Record<string, string>;
  /** Parsed request body. */
  body?: unknown;
  /** URL path parameters (e.g. `{ id: '42' }`). */
  params?: Record<string, string>;
  /** Parsed query-string parameters. */
  query?: Record<string, unknown>;
  /** User payload — populated by `createAuthMiddleware` after token validation. */
  user?: unknown;
  /** HTTP method in upper case (GET, POST, …). */
  method?: string;
  /** URL path, e.g. `/auth/login`. */
  path?: string;
  /** Full request URL including query string. */
  url?: string;
  /** Remote IP address. */
  ip?: string;
}

// ─── Response ────────────────────────────────────────────────────────────────

/**
 * Minimal response contract expected by awesome-node-auth middleware.
 *
 * @since 1.7.0
 */
export interface AuthResponse {
  /** Set the HTTP status code and return `this` for chaining. */
  status(code: number): this;
  /** Send a JSON body and return `this` for chaining. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  json(body: any): this;
  /** Send a raw body and return `this` for chaining. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  send(body?: any): this;
  /** End the response without sending a body. */
  end(): void;
  /** Set a response cookie. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cookie(name: string, value: any, options?: any): this;
  /** Clear a response cookie. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  clearCookie(name: string, options?: any): this;
  /** Redirect the client. */
  redirect(url: string): void;
  redirect(status: number, url: string): void;
  /** Set a single response header. */
  setHeader(name: string, value: string | string[]): this;
}

// ─── Middleware / Handler ─────────────────────────────────────────────────────

/**
 * Framework-neutral "next function" type.
 *
 * @since 1.7.0
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type AuthNextFunction = (err?: any) => void;

/**
 * Framework-neutral middleware / request-handler type.
 *
 * The parameter types use `any` deliberately so that Express
 * `RequestHandler` values — including third-party rate-limiters,
 * body-parsers, etc. — are directly assignable here without a cast.
 *
 * **Why `any` and not `AuthRequest`/`AuthResponse`?**
 * TypeScript enforces *contravariance* on function parameter types when
 * `strictFunctionTypes` is enabled (the default in strict mode).
 * If the parameters were typed as `AuthRequest`, then
 * `(req: Express.Request) => void` would **not** be assignable to
 * `(req: AuthRequest) => void` — because `Express.Request` is a *subtype*
 * of `AuthRequest` (it has more properties), and subtype parameters fail
 * contravariant checks.  Using `any` bypasses this check, making every
 * Express, Fastify, Koa, or other third-party middleware directly assignable
 * without an explicit cast.
 *
 * Non-Express adapters that wrap their native objects as `AuthRequest` /
 * `AuthResponse` are also assignable.
 *
 * @example
 * ```ts
 * import type { AuthRequestHandler } from '@awesome-lang-auth/node';
 *
 * // Write middleware once — works on Express, Fastify, Koa, …
 * const requestLogger: AuthRequestHandler = (req, _res, next) => {
 *   console.log(req.method, req.url);
 *   next();
 * };
 *
 * // Mount on Express directly (no cast needed):
 * app.use(requestLogger);
 *
 * // Mount on Fastify via adapter:
 * import { fastifyAdapter } from '@awesome-lang-auth/node/adapters/fastify';
 * fastify.addHook('preHandler', fastifyAdapter(requestLogger));
 * ```
 *
 * @since 1.7.0
 */
export type AuthRequestHandler = (
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  req: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  res: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  next: (err?: any) => void,
) => any;

// ─── Router ──────────────────────────────────────────────────────────────────

/**
 * Framework-neutral router interface.
 *
 * The Express `Router` object is structurally assignable to this type, so
 * all existing code that works with Express routers compiles unchanged.
 *
 * The handler parameters use `any[]` for the same contravariance reason as
 * `AuthRequestHandler` — see that type's JSDoc for the full explanation.
 *
 * @since 1.7.0
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
export interface AuthRouter {
  use(path: string, ...handlers: any[]): this;
  use(...handlers: any[]): this;
  get(path: string, ...handlers: any[]): this;
  post(path: string, ...handlers: any[]): this;
  put(path: string, ...handlers: any[]): this;
  patch(path: string, ...handlers: any[]): this;
  delete(path: string, ...handlers: any[]): this;
  options(path: string, ...handlers: any[]): this;
}
/* eslint-enable @typescript-eslint/no-explicit-any */
