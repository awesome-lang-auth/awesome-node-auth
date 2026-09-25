/**
 * Next.js Integration Example (App Router)
 * -----------------------------------------
 * Demonstrates how to integrate awesome-node-auth inside a Next.js 13+ application
 * that uses the App Router.
 *
 * Installation (in your Next.js project):
 *   npm install awesome-node-auth
 *
 * NOTE: This file is intentionally NOT compiled by tsconfig.json (it lives in
 * examples/, which is excluded). Treat it as reference documentation.
 *
 * Because Next.js API Routes run in a Node.js environment, awesome-node-auth works
 * without any special adapters. The steps below are copy-paste ready.
 *
 * Overview
 * --------
 *  1. lib/auth.ts              – singleton AuthConfigurator shared across routes.
 *  2. app/api/auth/[...auth]/route.ts
 *                              – catch-all route that forwards every /api/auth/*
 *                                request to the awesome-node-auth express-compatible router.
 *  3. middleware.ts            – Next.js Edge / Node middleware that protects
 *                                non-public routes using the JWT access token
 *                                stored in the HttpOnly cookie.
 *  4. app/api/profile/route.ts – example protected API route.
 *  5. app/dashboard/page.tsx   – example protected Server Component.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

// ---------------------------------------------------------------------------
// 0. Prerequisites
// ---------------------------------------------------------------------------
//
// Next.js API routes expose `req` / `res` objects that are compatible with
// the Node.js `http` module. The awesome-node-auth router is built on Express, which
// extends these objects. We use a small helper (`runMiddleware`) to bridge the
// two runtimes.
//

// ---------------------------------------------------------------------------
// 1. lib/auth.ts  (singleton)
// ---------------------------------------------------------------------------

import { AuthConfigurator, AuthConfig, IUserStore, createAuthRouter, createAdminRouter, MemoryTemplateStore } from '../src/index';

// Replace InMemoryUserStore with your real IUserStore implementation.
import { InMemoryUserStore, InMemoryLinkedAccountsStore, InMemorySettingsStore, InMemoryTemplateStore } from './in-memory-user-store';

export const authConfig: AuthConfig = {
  accessTokenSecret:  process.env.ACCESS_TOKEN_SECRET  ?? 'change-me-access',
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET ?? 'change-me-refresh',
  accessTokenExpiresIn:  '15m',
  refreshTokenExpiresIn: '7d',
  cookieOptions: {
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  },
  email: {
    siteUrl: process.env.NEXT_PUBLIC_SITE_URL ?? 'http://localhost:3000',
    // Uncomment to enable magic links, email verification, and account linking:
    // sendVerificationEmail: async (email, token, link) => mailer.send({ to: email, … }),
    // sendMagicLink: async (email, token, link) => mailer.send({ to: email, … }),
  },
};

// Create the stores once (swap for real DB stores in production)
export const userStore: IUserStore = new InMemoryUserStore();
export const linkedAccountsStore = new InMemoryLinkedAccountsStore();
export const settingsStore = new InMemorySettingsStore();
// Template store — enables the 📧 Email & UI Templates tab in the admin panel.
export const templateStore = new InMemoryTemplateStore();

// AuthConfigurator is cheap to create but should be a singleton to avoid
// re-creating services on every hot-reload cycle in development.
let _auth: AuthConfigurator | undefined;

export function getAuth(): AuthConfigurator {
  if (!_auth) _auth = new AuthConfigurator({ ...authConfig, templateStore }, userStore);
  return _auth;
}

// ---------------------------------------------------------------------------
// 1b. lib/admin.ts  (admin router singleton — mount separately from auth)
// ---------------------------------------------------------------------------
//
// app.use('/admin', adminRouter);   ← in your Express/NestJS bootstrap, or
// export { GET, POST, DELETE } from this file for an App Router catch-all.
//
// The admin UI is available at /admin in your browser.
// Pass linkedAccountsStore to see linked accounts in the Users table.
// Pass uploadDir + uploadBaseUrl to enable file upload for logo/background.
// Pass templateStore to enable the 📧 Email & UI Templates tab.
//

export const adminRouter = createAdminRouter(userStore as InMemoryUserStore, {
  accessPolicy: 'first-user',
  jwtSecret: process.env.ACCESS_TOKEN_SECRET ?? 'change-me-access-secret',
  linkedAccountsStore,
  settingsStore,
  templateStore,  // enables 📧 Email & UI Templates tab (live editor + preview)
  // Optional: enable file upload in the UI Customization panel.
  // uploadDir: path.join(process.cwd(), 'public', 'uploads'),
  // uploadBaseUrl: '/auth/ui/assets/uploads',
});

// ---------------------------------------------------------------------------
// 2. app/api/auth/[...auth]/route.ts
// ---------------------------------------------------------------------------
//
// The catch-all route delegates every /api/auth/* request to the express
// router provided by awesome-node-auth. It supports both the Pages Router
// (pages/api/auth/[...auth].ts) and the App Router shown here.
//

import { NextRequest, NextResponse } from 'next/server';
import { createServer, IncomingMessage, ServerResponse } from 'http';

/**
 * Adapts a Next.js App-Router request / response pair to work with the
 * awesome-node-auth express router.
 *
 * Under the hood awesome-node-auth uses an Express Router. Express decorates the
 * standard Node.js `IncomingMessage` / `ServerResponse` objects, so we
 * can create lightweight mock objects that delegate to the real Node.js
 * request / response when running inside Next.js.
 */
async function runNodeAuthRouter(
  req: NextRequest,
  params: { auth: string[] },
): Promise<NextResponse> {
  const auth = getAuth();
  const router = auth.router();

  return new Promise<NextResponse>((resolve) => {
    // Build a mock Node.js request from the Next.js request
    const url = '/' + (params.auth ?? []).join('/') + (req.nextUrl.search ?? '');

    // We use a real Node.js HTTP server request cycle to remain compatible
    // with the Express router expectations.
    const server = createServer((nodeReq: IncomingMessage, nodeRes: ServerResponse) => {
      // Forward body
      const contentType = req.headers.get('content-type') ?? '';

      if (contentType.includes('application/json')) {
        req.json().then((body: any) => {
          (nodeReq as any).body = body; // pre-parsed body for Express json()
        }).catch(() => {/* ignore parse errors */});
      }

      // Intercept the response
      const originalEnd = nodeRes.end.bind(nodeRes);
      let responseBody = '';
      const headers: Record<string, string> = {};

      nodeRes.setHeader = (name: string, value: any) => {
        headers[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
        return nodeRes;
      };

      (nodeRes as any).end = (chunk?: any) => {
        if (chunk) responseBody += chunk.toString();
        const nextRes = new NextResponse(responseBody || null, {
          status: nodeRes.statusCode,
          headers,
        });
        // Forward Set-Cookie separately so cookies are preserved
        const setCookie = (nodeRes as any).getHeader?.('set-cookie');
        if (setCookie) {
          const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
          cookies.forEach((c: string) => nextRes.headers.append('Set-Cookie', c));
        }
        resolve(nextRes);
        return originalEnd(chunk);
      };

      // router() expects Express-decorated IncomingMessage / ServerResponse.
      // The `as any` cast is necessary here because TypeScript's contravariance
      // rules (strictFunctionTypes) prevent assigning the plain Node.js types
      // to the Express-specific overloads — the same reason AuthRequestHandler
      // uses `any` for its parameter types.  At runtime both objects are
      // structurally compatible.
      router(nodeReq as any, nodeRes as any, () => {
        resolve(new NextResponse('Not found', { status: 404 }));
      });
    });

    // We never actually listen – just call the request handler directly
    // by using the `emit` pattern
    const nodeReq = Object.assign(
      new IncomingMessage(null as any),
      {
        method:  req.method,
        url,
        headers: Object.fromEntries(req.headers.entries()),
      },
    ) as IncomingMessage;

    const nodeRes = new ServerResponse(nodeReq);
    server.emit('request', nodeReq, nodeRes);
  });
}

export async function GET(
  request: NextRequest,
  { params }: { params: { auth: string[] } },
): Promise<NextResponse> {
  return runNodeAuthRouter(request, params);
}

export async function POST(
  request: NextRequest,
  { params }: { params: { auth: string[] } },
): Promise<NextResponse> {
  return runNodeAuthRouter(request, params);
}

// ---------------------------------------------------------------------------
// Pages Router alternative: pages/api/auth/[...auth].ts
// ---------------------------------------------------------------------------
//
// If you are still on the Pages Router, use this simpler approach instead:
//
//   import type { NextApiRequest, NextApiResponse } from 'next';
//   import { getAuth } from '../../lib/auth';
//
//   export const config = { api: { bodyParser: false } };
//
//   export default function handler(req: NextApiRequest, res: NextApiResponse) {
//     const router = getAuth().router();
//     // Strip /api/auth prefix so the inner router sees paths starting from /
//     req.url = req.url!.replace(/^\/api\/auth/, '') || '/';
//     router(req as any, res as any, () => res.status(404).end());
//   }
//

// ---------------------------------------------------------------------------
// 3. middleware.ts  (Next.js Edge Middleware — file at project root)
// ---------------------------------------------------------------------------
//
// Protects all routes under /dashboard, /profile, etc. by verifying the
// access-token cookie. Because Edge Middleware cannot use `jsonwebtoken`
// (which relies on Node.js crypto), we verify the token using the built-in
// Web Crypto API.
//
// Place this file at the root of your Next.js project (same level as app/).
//

/*
import { NextRequest, NextResponse } from 'next/server';

export const config = {
  matcher: ['/dashboard/:path*', '/profile/:path*', '/api/protected/:path*'],
};

export async function middleware(request: NextRequest): Promise<NextResponse> {
  const token = request.cookies.get('accessToken')?.value;

  if (!token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  try {
    // Verify JWT with Web Crypto (Edge compatible)
    const [headerB64, payloadB64, signatureB64] = token.split('.');
    const secret = process.env.ACCESS_TOKEN_SECRET!;

    const enc     = new TextEncoder();
    const keyData = enc.encode(secret);
    const key     = await crypto.subtle.importKey(
      'raw', keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false, ['verify'],
    );

    const data      = enc.encode(`${headerB64}.${payloadB64}`);
    const signature = Uint8Array.from(
      atob(signatureB64.replace(/-/g, '+').replace(/_/g, '/')),
      c => c.charCodeAt(0),
    );

    const valid = await crypto.subtle.verify('HMAC', key, signature, data);
    if (!valid) throw new Error('Invalid signature');

    // A valid signature is not enough: the token must be unexpired, and must
    // not carry a `purpose` claim, which marks tokens that are not sessions
    // (the 2FA step-up token and the admin console token).
    const payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(
      atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')),
      c => c.charCodeAt(0),
    )));
    if (typeof payload.exp !== 'number' || payload.exp * 1000 <= Date.now()) throw new Error('Expired');
    if (payload.purpose !== undefined) throw new Error('Not a session token');

    return NextResponse.next();
  } catch {
    return NextResponse.redirect(new URL('/login', request.url));
  }
}
*/

// ---------------------------------------------------------------------------
// 4. app/api/profile/route.ts  (protected API route — Pages Router example)
// ---------------------------------------------------------------------------
//
//   import type { NextApiRequest, NextApiResponse } from 'next';
//   import { getAuth } from '../../lib/auth';
//
//   export default function handler(req: NextApiRequest, res: NextApiResponse) {
//     const middleware = getAuth().middleware();
//     middleware(req as any, res as any, (err?: any) => {
//       if (err) return res.status(401).json({ error: 'Unauthorized' });
//       res.json({ user: (req as any).user });
//     });
//   }
//

// ---------------------------------------------------------------------------
// 5. app/dashboard/page.tsx  (Server Component — reads cookie server-side)
// ---------------------------------------------------------------------------
//
//   import { cookies } from 'next/headers';
//   import { redirect } from 'next/navigation';
//   import { TokenService } from 'awesome-node-auth';
//   import { authConfig } from '../../lib/auth';
//
//   export default async function DashboardPage() {
//     const cookieStore = cookies();
//     const token = cookieStore.get('accessToken')?.value;
//
//     if (!token) redirect('/login');
//
//     const tokenService = new TokenService();
//     const payload = tokenService.verifyAccessToken(token, authConfig);
//
//     if (!payload) redirect('/login');
//
//     return <div>Welcome, {payload.email}!</div>;
//   }
//

// ---------------------------------------------------------------------------
// 6. Complete Pages Router example (self-contained)
// ---------------------------------------------------------------------------
//
// pages/api/auth/[...auth].ts
//
//   import type { NextApiRequest, NextApiResponse } from 'next';
//   import { createAuthRouter } from 'awesome-node-auth';
//   import { authConfig, userStore, linkedAccountsStore, settingsStore } from '../../../lib/auth';
//
//   const router = createAuthRouter(userStore, authConfig, { linkedAccountsStore, settingsStore });
//
//   export const config = { api: { bodyParser: false } };
//
//   export default function handler(req: NextApiRequest, res: NextApiResponse) {
//     req.url = req.url!.replace(/^\/api\/auth/, '') || '/';
//     router(req as any, res as any, () => res.status(404).end());
//   }
//
// pages/api/admin/[...admin].ts  (admin panel — protected by accessPolicy: 'first-user')
//
//   import type { NextApiRequest, NextApiResponse } from 'next';
//   import { adminRouter } from '../../../lib/admin';
//
//   export const config = { api: { bodyParser: false } };
//
//   export default function handler(req: NextApiRequest, res: NextApiResponse) {
//     req.url = req.url!.replace(/^\/api\/admin/, '') || '/';
//     adminRouter(req as any, res as any, () => res.status(404).end());
//   }
//

// ---------------------------------------------------------------------------
// 7. Account linking (frontend notes)
// ---------------------------------------------------------------------------
//
// Once the user is logged in, they can link a secondary email address:
//
//   // Step 1 — initiate link (sends a verification email)
//   await fetch('/api/auth/link-request', {
//     method: 'POST',
//     headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
//     body: JSON.stringify({ email: 'secondary@example.com', provider: 'email' }),
//   });
//
//   // Step 2 — user clicks link in email, frontend extracts `?token=` and calls:
//   await fetch('/api/auth/link-verify', {
//     method: 'POST',
//     headers: { 'Content-Type': 'application/json' },
//     body: JSON.stringify({ token }),
//   });
//
// To list or remove linked accounts:
//   GET    /api/auth/linked-accounts           (Authorization: Bearer <token>)
//   DELETE /api/auth/linked-accounts/email/secondary@example.com
//
// NOTE: link-request requires IUserStore to implement updateAccountLinkToken
//       and link-verify requires findByAccountLinkToken.  Both are already
//       implemented in InMemoryUserStore, SqliteUserStore, MySqlUserStore, and
//       MongoDbUserStore.
//

// Prevent TypeScript from treating this file as a script
export {};
