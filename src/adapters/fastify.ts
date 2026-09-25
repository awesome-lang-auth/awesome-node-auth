/**
 * Fastify adapter for awesome-node-auth.
 *
 * Bridges an `AuthRequestHandler` to Fastify's `preHandler` hook by
 * delegating to `req.raw` / `reply.raw` — the underlying Node.js
 * `IncomingMessage` / `ServerResponse` objects that Fastify exposes on
 * every request and reply.
 *
 * **No extra dependencies required.** This adapter works with any Fastify
 * version that exposes `.raw` on its request and reply objects (v3+).
 *
 * For mounting the full auth **router** (not just middleware) you still need
 * `@fastify/express`, because `auth.router()` returns an Express `Router`
 * that relies on Express-specific request decoration.
 *
 * @example
 * ```ts
 * import Fastify from 'fastify';
 * import { fastifyAdapter } from '@awesome-lang-auth/node/adapters/fastify';
 * import { createAuthMiddleware } from '@awesome-lang-auth/node';
 *
 * const fastify = Fastify();
 * const authMiddleware = createAuthMiddleware(authConfig, userStore);
 *
 * // Protect all routes — verify the JWT on every request.
 * fastify.addHook('preHandler', fastifyAdapter(authMiddleware));
 *
 * fastify.get('/profile', async (request) => {
 *   return request.raw.user; // populated by awesome-node-auth middleware
 * });
 * ```
 *
 * @since 1.7.0
 */

import type { AuthRequestHandler } from '../http-types';

/**
 * Minimal duck-typed surface we use from a Fastify request.
 * Avoids a hard dependency on the `fastify` package.
 */
interface FastifyLikeRequest {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  raw: any;
}

/**
 * Minimal duck-typed surface we use from a Fastify reply.
 * Avoids a hard dependency on the `fastify` package.
 */
interface FastifyLikeReply {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  raw: any;
}

/**
 * Wrap an `AuthRequestHandler` as a Fastify `preHandler` hook.
 *
 * The adapter forwards `req.raw` and `reply.raw` (the underlying Node.js
 * `IncomingMessage` and `ServerResponse`) to the handler, so that
 * awesome-node-auth middleware operates on the same objects it would receive
 * from Express.
 *
 * There is no runtime overhead beyond the extra function call; the original
 * handler is invoked directly.
 *
 * @example
 * ```ts
 * import { fastifyAdapter } from '@awesome-lang-auth/node/adapters/fastify';
 *
 * fastify.addHook('preHandler', fastifyAdapter(authMiddleware));
 * ```
 *
 * @since 1.7.0
 */
export function fastifyAdapter(
  handler: AuthRequestHandler,
): (req: FastifyLikeRequest, reply: FastifyLikeReply, done: (err?: Error) => void) => void {
  return (req, reply, done) => {
    handler(req.raw, reply.raw, done);
  };
}
