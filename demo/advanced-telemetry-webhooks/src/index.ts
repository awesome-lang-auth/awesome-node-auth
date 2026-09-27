// ============================================================
// Express + MongoDB integration — @awesome-lang-auth/node@^1.10.1
// Advanced demo: full feature set (CSRF, CORS, email verification,
// OAuth Google + GitHub) backed by a real MongoDB database.
//
// Prerequisites:
//   docker compose up -d   (starts MongoDB — see docker-compose.yml)
//   cp .env.example .env   (fill in secrets)
//   npm install
//   npm start
// ============================================================

import express from 'express';
import { MongoClient } from 'mongodb';
import rateLimit from 'express-rate-limit';
import { AuthConfigurator, PasswordService, AuthError, MemoryTemplateStore } from '@awesome-lang-auth/node';
import type { AuthConfig } from '@awesome-lang-auth/node';
import { createAdminRouter } from '@awesome-lang-auth/node';
import type { AdminOptions } from '@awesome-lang-auth/node';

// ---- 1. IUserStore implementation (MongoDB) ----
import { MongoDbUserStore } from './user-store';

// ---- 2. Optional stores (uncomment + provide implementations) ----
// import { MyRbacStore }    from './rbac-store';
// const rbacStore    = new MyRbacStore();
// import { MySessionStore } from './session-store';
// const sessionStore = new MySessionStore();
// import { MyTenantStore }  from './tenant-store';
// const tenantStore  = new MyTenantStore();

// ---- 3. Auth configuration ----

const authConfig: AuthConfig = {
  accessTokenSecret:     process.env.ACCESS_TOKEN_SECRET  ?? 'change-me-access',
  refreshTokenSecret:    process.env.REFRESH_TOKEN_SECRET ?? 'change-me-refresh',
  accessTokenExpiresIn:  '15m',
  refreshTokenExpiresIn: '7d',
  cookieOptions: {
    secure:   process.env.NODE_ENV === 'production',
    // sameSite:'none' is required for cross-origin fetch with credentials:'include'.
    // In production this REQUIRES HTTPS (secure:true above).
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  },
  csrf: { enabled: true },
  email: {
    // Array of allowed front-end origins.  The router picks the one matching
    // the request Origin/Referer header for OAuth redirects; the first entry
    // is used for email links (magic link, password reset, etc.).
    siteUrl: process.env.CORS_ORIGINS?.split(',').map(s => s.trim()).filter(Boolean) ?? ['http://localhost:3000'],
    mailer: {
      endpoint: process.env.MAILER_ENDPOINT ?? '',
      apiKey:   process.env.MAILER_API_KEY   ?? '',
      from:     process.env.MAILER_FROM      ?? 'noreply@example.com',
    },
  },
  emailVerificationMode: 'strict',
  oauth: {
    google: {
      clientId:     process.env.GOOGLE_CLIENT_ID     ?? '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '',
      callbackUrl:  process.env.GOOGLE_CALLBACK_URL  ?? 'http://localhost:3000/auth/oauth/google/callback',
    },
    github: {
      clientId:     process.env.GITHUB_CLIENT_ID     ?? '',
      clientSecret: process.env.GITHUB_CLIENT_SECRET ?? '',
      callbackUrl:  process.env.GITHUB_CALLBACK_URL  ?? 'http://localhost:3000/auth/oauth/github/callback',
    },
  },
};

// ---- 4. Bootstrap (async — MongoDB connection required) ----

async function main(): Promise<void> {
  // Connect to MongoDB (started via docker-compose or a cloud URI)
  const mongoUri = process.env.MONGO_URI ?? 'mongodb://localhost:27017';
  const dbName   = process.env.MONGO_DB  ?? 'awesome-node-auth-demo';

  if (!process.env.MONGO_URI) {
    console.warn('⚠️  MONGO_URI is not set — using default localhost MongoDB. Set it in .env for production.');
  }
  const client = new MongoClient(mongoUri);
  await client.connect();

  const userStore = new MongoDbUserStore(client.db(dbName));
  await userStore.init(); // create indexes

  // Template store — enables the 📧 Email & UI Templates tab in the admin panel.
  // Swap MemoryTemplateStore for a MongoDB-backed implementation in production
  // (see examples/mongodb-user-store.example.ts → MongoDbTemplateStore).
  const templateStore = new MemoryTemplateStore();

  const passwordService = new PasswordService();
  const auth = new AuthConfigurator({ ...authConfig, templateStore }, userStore);
  const app  = express();
  app.use(express.json());

  // Auth routes (POST /auth/login, POST /auth/register, POST /auth/refresh, …)
  app.use('/auth', auth.router({
    onRegister: async (data) => {
      const email    = typeof data.email    === 'string' ? data.email.trim()    : '';
      const password = typeof data.password === 'string' ? data.password.trim() : '';
      if (!email || !password) throw new AuthError('email and password are required', 'VALIDATION_ERROR', 400);
      const existing = await userStore.findByEmail(email);
      if (existing) throw new AuthError('Email already registered', 'EMAIL_EXISTS', 409);
      const hash = await passwordService.hash(password);
      return userStore.create({ email, password: hash, role: 'user' });
    },
    // rbacStore,
    // sessionStore,
    // tenantStore,
    // Dynamic CORS: the router adds Access-Control-* headers automatically
    // for every origin listed in CORS_ORIGINS.  On OAuth flows it also embeds
    // the caller's origin in the state parameter and redirects back to it after
    // a successful login (validated against the same allowlist).
    cors: {
      origins: process.env.CORS_ORIGINS?.split(',').map(s => s.trim()).filter(Boolean) ?? [],
    },
  }));

  // Mount admin UI at /admin  (protect with a strong secret in production)
  const adminOptions: AdminOptions = {
    jwtSecret: process.env.ACCESS_TOKEN_SECRET ?? 'dev-secret',
    accessPolicy: 'first-user',
    templateStore,  // enables 📧 Email & UI Templates tab (live editor + preview)
    // rbacStore,
    // sessionStore,
    // tenantStore,
  };
  app.use('/admin', createAdminRouter(userStore, adminOptions));

  // ---- 5. Protect your own routes ----
  // Rate-limit protected API routes to prevent brute-force / scraping.
  const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });

  app.get('/profile', apiLimiter, auth.middleware(), (req, res) => {
    res.json({ user: (req as any).user });
  });

  const port = Number(process.env.PORT) || 3000;
  app.listen(port, () => {
    console.log(`\n  🔐  awesome-node-auth advanced demo (MongoDB)\n`);
    console.log(`  http://localhost:${port}/auth    → auth endpoints`);
    console.log(`  http://localhost:${port}/profile → protected route (JWT required)`);
    console.log(`  http://localhost:${port}/admin   → admin panel\n`);
  });
}

main().catch((err) => {
  console.error('Failed to start:', err);
  process.exit(1);
});
