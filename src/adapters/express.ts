/**
 * Express adapter for awesome-node-auth.
 *
 * Re-exports the Express `Router` and `RequestHandler` types so that Express
 * applications can import them from a single, well-known path within the
 * library.
 *
 * The `expressAdapter` helper is a zero-overhead cast: it accepts an
 * `AuthRequestHandler` written against the framework-neutral types and returns
 * the same function typed as an Express `RequestHandler`, bridging the two
 * type systems without any runtime cost.
 *
 * @example
 * ```ts
 * import { expressAdapter } from '@awesome-lang-auth/node';
 * import type { AuthRequestHandler } from '@awesome-lang-auth/node';
 *
 * const myMiddleware: AuthRequestHandler = (req, res, next) => {
 *   // logic here
 *   next();
 * };
 *
 * // Mount on an Express app with proper Express types:
 * app.use(expressAdapter(myMiddleware));
 * ```
 *
 * @since 1.7.0
 */

import { Router, RequestHandler, Request, Response, NextFunction } from 'express';
import type { AuthRequestHandler } from '../http-types';

export { Router, RequestHandler };
export type { Request, Response, NextFunction };

/**
 * Cast an `AuthRequestHandler` (framework-neutral) to an Express
 * `RequestHandler`.
 *
 * There is no runtime overhead — the original function reference is returned
 * unchanged; only the TypeScript type is adjusted.  Use this when you write
 * middleware against the neutral `AuthRequestHandler` interface and need to
 * pass it to `app.use()` / `router.use()` with correct Express typing.
 *
 * @since 1.7.0
 */
export function expressAdapter(handler: AuthRequestHandler): RequestHandler {
  return handler as unknown as RequestHandler;
}
