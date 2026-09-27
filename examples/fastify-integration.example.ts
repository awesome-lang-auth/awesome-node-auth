/**
 * Fastify Integration Example
 * ---------------------------
 * Demonstrates how to integrate awesome-node-auth inside a Fastify application.
 *
 * Installation (in your Fastify project):
 *   npm install @awesome-lang-auth/node fastify
 *
 * NOTE: This file is intentionally NOT compiled by tsconfig.json (it lives in
 * examples/, which is excluded). Treat it as reference documentation.
 *
 * Overview
 * --------
 *  1. lib/auth.ts              — singleton AuthConfigurator shared across routes.
 *  2. Middleware-only setup    — protect routes with auth.middleware() via fastifyAdapter().
 *  3. Full-router setup        — mount the entire auth router via @fastify/express.
 *  4. Token service usage      — validate tokens manually inside a Fastify handler.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

// ---------------------------------------------------------------------------
// 0. Prerequisites
// ---------------------------------------------------------------------------
//
// The fastifyAdapter() helper (src/adapters/fastify.ts) bridges
// AuthRequestHandler to Fastify's preHandler hook by delegating to req.raw /
// reply.raw — the underlying Node.js IncomingMessage / ServerResponse.
//
// For auth.middleware() (JWT validation), fastifyAdapter() is all you need —
// no extra Fastify plugins required.
//
// For auth.router() (full auth router with /login, /register, etc.) you need
// @fastify/express to mount an Express Router inside Fastify:
//
//   npm install @fastify/express
//

// ---------------------------------------------------------------------------
// 1. lib/auth.ts  (singleton)
// ---------------------------------------------------------------------------

import { AuthConfigurator, AuthConfig, IUserStore, BaseUser } from '../src/index';
import { InMemoryUserStore } from './in-memory-user-store';

export const authConfig: AuthConfig = {
  jwtSecret:   process.env.ACCESS_TOKEN_SECRET   ?? 'dev-secret',
  jwtExpiry:   process.env.JWT_EXPIRY   ?? '15m',
  refreshSecret: process.env.REFRESH_SECRET ?? 'dev-refresh-secret',
  refreshExpiry: process.env.REFRESH_EXPIRY ?? '7d',
  cookieSecure: process.env.NODE_ENV === 'production',
};

const userStore: IUserStore = new InMemoryUserStore();

let _auth: AuthConfigurator | null = null;

export function getAuth(): AuthConfigurator {
  if (!_auth) _auth = new AuthConfigurator(authConfig, userStore);
  return _auth;
}

// ---------------------------------------------------------------------------
// 2. Middleware-only setup — protect routes with fastifyAdapter()
// ---------------------------------------------------------------------------
//
// Use this pattern when you write your own Fastify route handlers but want
// awesome-node-auth to validate JWTs and populate req.raw.user before your
// handler runs.
//

import Fastify, { FastifyRequest, FastifyReply } from 'fastify';
import { fastifyAdapter } from '../src/adapters/fastify';

const fastify = Fastify({ logger: true });

const auth = getAuth();

// Protect all routes that are registered *after* this hook.
// createAuthMiddleware() validates the JWT Access Token from either the
// Authorization header (Bearer) or the HttpOnly cookie and sets req.user.
fastify.addHook('preHandler', fastifyAdapter(auth.middleware()));

// Protected route — req.raw.user is populated by the middleware above.
fastify.get('/profile', async (request: FastifyRequest) => {
  const user = (request.raw as any).user as BaseUser;
  if (!user) return { error: 'Unauthorized' };
  return { user };
});

// Public route — add it *before* the global preHandler, or skip the hook
// with a per-route option.
fastify.get('/health', async () => ({ status: 'ok' }));

// ---------------------------------------------------------------------------
// 3. Full-router setup via @fastify/express
// ---------------------------------------------------------------------------
//
// This mounts the entire awesome-node-auth Express router (all /auth/* endpoints)
// inside Fastify via the @fastify/express compatibility plugin.
//
//   npm install @fastify/express
//

async function buildFastifyWithFullRouter() {
  const app = Fastify({ logger: true });

  // Register Express compatibility layer
  await app.register(require('@fastify/express'));

  const router = getAuth().router();

  // Mount the auth router at /auth — all endpoints become available:
  //   POST /auth/login, POST /auth/register, POST /auth/refresh, …
  app.use('/auth', router);

  await app.listen({ port: 3000 });
  console.log('Server listening at http://localhost:3000');
}

// ---------------------------------------------------------------------------
// 4. Token service usage — validate tokens manually in a Fastify handler
// ---------------------------------------------------------------------------
//
// When you prefer to skip the Express router entirely and handle auth
// yourself, use createAuthMiddleware() as a standalone validation function.
//

import type { AuthRequest } from '../src/http-types';

fastify.get('/api/me', async (request: FastifyRequest, reply: FastifyReply) => {
  const rawReq: AuthRequest = request.raw as AuthRequest;

  // If the global preHandler hook is registered, rawReq.user is already set.
  if (!rawReq.user) {
    reply.code(401);
    return { error: 'Unauthorized' };
  }

  return { user: rawReq.user };
});

// ---------------------------------------------------------------------------
// 5. Start the server
// ---------------------------------------------------------------------------

fastify.listen({ port: 3000 }, (err) => {
  if (err) {
    fastify.log.error(err);
    process.exit(1);
  }
});
