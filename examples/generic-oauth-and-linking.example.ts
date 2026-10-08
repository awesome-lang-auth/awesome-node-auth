/**
 * Generic OAuth + Account Linking + Settings — Integration Example
 * ---------------------------------------------------------------
 * Shows how to:
 *
 *  1. Add a custom OAuth provider (Discord) using `GenericOAuthStrategy`.
 *  2. Enable flexible account linking so users can connect multiple OAuth
 *     providers to one account and manage them via the API.
 *  3. Enforce the global 2FA policy from the admin Control panel in the
 *     auth router (so `POST /auth/2fa/disable` respects system settings).
 *  4. Wire everything together with `createAuthRouter` and `createAdminRouter`.
 *
 * NOTE: This file is intentionally NOT compiled by tsconfig.json (it lives in
 * examples/, which is excluded). Treat it as reference documentation.
 *
 * Prerequisites:
 *   npm install express
 *   # plus your DB driver (e.g. better-sqlite3, mysql2, mongodb)
 */

// ---------------------------------------------------------------------------
// 0. Imports
// ---------------------------------------------------------------------------

import express from 'express';
import path from 'path';
import os from 'os';
import {
  createAuthRouter,
  createAdminRouter,
  buildUiRouter,
  AuthConfig,
  BaseUser,
  GenericOAuthStrategy,
  GenericOAuthProviderConfig,
  AuthError,
} from '../src/index';

// Use the in-memory stores for this example — swap for your real DB stores.
import {
  InMemoryUserStore,
  InMemoryLinkedAccountsStore,
  InMemorySettingsStore,
  InMemoryTemplateStore,
} from './in-memory-user-store';

// ---------------------------------------------------------------------------
// 1. Auth configuration
// ---------------------------------------------------------------------------

const config: AuthConfig = {
  accessTokenSecret:  process.env.ACCESS_TOKEN_SECRET  ?? 'change-me-access-secret',
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET ?? 'change-me-refresh-secret',
  accessTokenExpiresIn:  '15m',
  refreshTokenExpiresIn: '7d',
  email: {
    siteUrl: process.env.SITE_URL ?? 'http://localhost:3000',
    // Provide one of these to enable magic links / email verification:
    // sendMagicLink: async (email, token, link) => mailer.send({ to: email, … }),
    // mailer: { host: '…', port: 587, user: '…', pass: '…', from: '…' },
  },
};

// ---------------------------------------------------------------------------
// 2. Stores
// ---------------------------------------------------------------------------

const userStore          = new InMemoryUserStore();
const linkedAccountsStore = new InMemoryLinkedAccountsStore();
const settingsStore      = new InMemorySettingsStore();
// Template store — enables the 📧 Email & UI Templates tab in the admin panel.
// Swap InMemoryTemplateStore for a DB-backed implementation in production.
const templateStore      = new InMemoryTemplateStore();

// ---------------------------------------------------------------------------
// 3. GenericOAuthStrategy — Discord example
// ---------------------------------------------------------------------------

const discordConfig: GenericOAuthProviderConfig = {
  name: 'discord',
  clientId:     process.env.DISCORD_CLIENT_ID     ?? '',
  clientSecret: process.env.DISCORD_CLIENT_SECRET ?? '',
  callbackUrl:  `${config.email?.siteUrl}/auth/oauth/discord/callback`,
  authorizationUrl: 'https://discord.com/api/oauth2/authorize',
  tokenUrl:         'https://discord.com/api/oauth2/token',
  userInfoUrl:      'https://discord.com/api/users/@me',
  scope: 'identify email',
  // Map Discord's response shape to the standard profile object.
  mapProfile: (raw) => ({
    id:    String(raw['id']),
    email: String(raw['email'] ?? ''),
    name:  raw['username'] ? String(raw['username']) : undefined,
    picture: raw['avatar']
      ? `https://cdn.discordapp.com/avatars/${raw['id']}/${raw['avatar']}.png`
      : undefined,
  }),
};

class DiscordStrategy extends GenericOAuthStrategy<BaseUser> {
  async findOrCreateUser(profile: {
    id: string;
    email: string;
    name?: string;
    picture?: string;
  }): Promise<BaseUser> {
    // 1. Check linked accounts first (supports multi-provider per user)
    const link = await linkedAccountsStore.findUserByProviderAccount('discord', profile.id);
    if (link) {
      const user = await userStore.findById(link.userId);
      if (user) return user;
    }

    // 2. Fallback: look up by email (only safe when email is verified by provider)
    const byEmail = await userStore.findByEmail(profile.email);
    if (byEmail) {
      // Email already in use by a different account — signal conflict
      throw new AuthError(
        'An account with this email already exists. Log in with your original method to link Discord.',
        'OAUTH_ACCOUNT_CONFLICT',
        409,
      );
    }

    // 3. Create a brand-new user
    return userStore.create({
      email:           profile.email,
      loginProvider:   'discord',
      providerAccountId: profile.id,
      isEmailVerified: true, // Discord provides verified emails
    });
  }
}

const discordStrategy = new DiscordStrategy(discordConfig);

// ---------------------------------------------------------------------------
// 4. Auth router — mounts all /auth/* endpoints
// ---------------------------------------------------------------------------
//
// New endpoints enabled by the extra stores / strategies:
//   GET  /auth/oauth/discord            — redirect to Discord
//   GET  /auth/oauth/discord/callback   — OAuth callback (2FA enforced if enabled)
//   GET  /auth/linked-accounts          — list linked OAuth accounts (authenticated)
//   DELETE /auth/linked-accounts/:provider/:id  — unlink an account (authenticated)
//   POST /auth/link-request             — request to link a new email address (authenticated)
//   POST /auth/link-verify              — verify the link token (completes the link)
//   POST /auth/2fa/disable              — respects system require2FA policy
//

const authRouter = createAuthRouter(userStore, config, {
  // Register Discord (or any other GenericOAuthStrategy subclass)
  oauthStrategies: [discordStrategy],

  // Flexible account linking — auto-records each OAuth login.
  // Also enables POST /auth/link-request and POST /auth/link-verify when
  // IUserStore implements updateAccountLinkToken / findByAccountLinkToken.
  linkedAccountsStore,

  // Propagate the system 2FA policy to /auth/2fa/disable
  settingsStore,
});

// ---------------------------------------------------------------------------
// 5. Admin router — mounts all /admin/* endpoints
// ---------------------------------------------------------------------------
//
// The ⚙️ Control tab now shows:
//   • Email verification policy — none / lazy (with grace period) / strict
//   • Mandatory 2FA toggle
//
// The 👤 Users tab shows:
//   • Linked Accounts column (preview: first provider + count)
//   • Linked Accounts section in the user detail panel
//
// Changes saved here are also enforced in the auth router via `settingsStore`.
//

const adminRouter = createAdminRouter(userStore, {
  accessPolicy: 'first-user',
  jwtSecret: process.env.ACCESS_TOKEN_SECRET ?? 'change-me-access-secret',
  settingsStore,
  templateStore,    // enables 📧 Email & UI Templates tab (live editor + preview)
  // Pass linkedAccountsStore to show linked accounts in the Users table and
  // detail panel, and to enable GET /admin/api/users/:id/linked-accounts.
  linkedAccountsStore,
  // Enable file upload for logo and background image in the UI Customization panel.
  // Files are stored in UPLOAD_DIR and served by buildUiRouter at /assets/uploads/.
  uploadDir: path.join(os.tmpdir(), 'awesome-node-auth-uploads'),
  // Must match: <where buildUiRouter is mounted> + '/assets/uploads'
  uploadBaseUrl: '/auth/ui/assets/uploads',
});

// ---------------------------------------------------------------------------
// 6. Express application
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());

app.use('/auth',  authRouter);

// Mount the built-in UI router — SSR HTML pages with themed login/register forms.
// Serves: GET /auth/ui/login, GET /auth/ui/register, GET /auth/ui/forgot-password, …
// Features:
//   • CSS custom properties injected server-side (prevents FOUC)
//   • Loading splash-spinner overlay removed on window.onload
//   • window.__AUTH_CONFIG__ injected so auth.js boots synchronously
//   • Runtime theme from settingsStore (changed via admin UI Customization panel)
//   • Uploaded assets served at /auth/ui/assets/uploads/<filename>
app.use('/auth/ui', buildUiRouter({
  authConfig: config,
  routerOptions: { oauthStrategies: [discordStrategy] },
  settingsStore,
  templateStore,    // enables UI i18n injection via stored translations
  uploadDir: path.join(os.tmpdir(), 'awesome-node-auth-uploads'),
  apiPrefix: '/auth',
}));

app.use('/admin', adminRouter);

app.get('/', (_req, res) => res.json({ ok: true }));

const PORT = Number(process.env.PORT ?? 3000);
app.listen(PORT, () => {
  console.log(`node-auth example running on http://localhost:${PORT}`);
  console.log(`  Auth:     http://localhost:${PORT}/auth`);
  console.log(`  Auth UI:  http://localhost:${PORT}/auth/ui/login`);
  console.log(`  Admin:    http://localhost:${PORT}/admin`);
});

// ---------------------------------------------------------------------------
// 7. Frontend integration notes
// ---------------------------------------------------------------------------
//
// ── Browser client (auth.js / window.AwesomeNodeAuth) ────────────────────────────
//
// awesome-node-auth ships a zero-config browser client at /auth/ui/auth.js.
// Include it once in your HTML — it registers window.AwesomeNodeAuth automatically:
//
//   <script src="/auth/ui/auth.js"></script>
//
// Zero-config usage (apiPrefix is auto-detected from the URL):
//   const result = await AwesomeNodeAuth.login(email, password);
//   await AwesomeNodeAuth.guardPage();              // redirect if not logged in
//   await AwesomeNodeAuth.guardRole('admin');       // redirect if wrong role
//   const user = AwesomeNodeAuth.getUser();
//   await AwesomeNodeAuth.logout();
//
// Optional configuration (e.g. in a SPA with a custom router):
//   AwesomeNodeAuth.init({
//     apiPrefix: '/auth',
//     homeUrl: '/dashboard',
//     onSessionExpired: () => router.navigate('/login'),
//     onLogout: () => { clearAppState(); router.navigate('/login'); },
//   });
//
// All auth operations are available: login, register, logout, forgotPassword,
// resetPassword, changePassword, setPassword, sendMagicLink, verifyMagicLink,
// setup2fa, verify2faSetup, validate2fa, sendSmsLogin, verifySmsLogin,
// validateSms, resendVerificationEmail, verifyEmail, requestEmailChange,
// confirmEmailChange, requestLinkingEmail, verifyLinkingToken,
// verifyConflictLinkingToken, getLinkedAccounts, unlinkAccount, deleteAccount.
//
// Every method can also be overridden via AwesomeNodeAuth.init({ methodName: fn }).
//
// ── 2FA / OAuth flow notes ────────────────────────────────────────────────────
//
// After a successful OAuth callback, if the user has 2FA enabled the router
// redirects to:
//   {siteUrl}/auth/2fa?tempToken=<jwt>&methods=totp,sms,magic-link
//
// Your frontend should read `tempToken` and `methods` from the query string
// and present the appropriate 2FA challenge, then call one of:
//   AwesomeNodeAuth.validate2fa(tempToken, totpCode)
//   AwesomeNodeAuth.validateSms(tempToken, smsCode)
//   AwesomeNodeAuth.verifyMagicLink(token)
//
// List and manage linked accounts:
//   const accounts = await AwesomeNodeAuth.getLinkedAccounts();
//   await AwesomeNodeAuth.unlinkAccount('discord', providerAccountId);
//
// Explicitly link a new email address (authenticated flow):
//   1. await AwesomeNodeAuth.requestLinkingEmail('secondary@example.com', 'email')
//      → sends a verification email
//   2. User clicks the link → token arrives in query param
//   3. await AwesomeNodeAuth.verifyLinkingToken(token, 'email')
//      → account linked; appears in getLinkedAccounts()
//
// NOTE: link-request requires IUserStore to implement updateAccountLinkToken
//       and link-verify requires findByAccountLinkToken (both optional methods
//       already implemented in InMemoryUserStore, SqliteUserStore, etc.).
//
// ── Admin panel notes ─────────────────────────────────────────────────────────
//
// Enable the admin control panel by visiting /admin in your browser.
// Note: You must log in as an administrator (e.g., the first created user). From the ⚙️ Control tab you can:
//   - Set email verification policy (none / lazy / strict) with grace period
//   - Toggle mandatory 2FA for all users
//   - Customize the UI: site name, primary/secondary colors, logo, background
//     image and card background. Changes take effect immediately (SSR).
//     Use "Upload Logo" / "Upload Background Image" to store files in uploadDir.
// From the 👤 Users tab you can:
//   - See a preview of each user's linked accounts (e.g. "google +1")
//   - Open the user detail panel to see the full list of linked providers

export {};
