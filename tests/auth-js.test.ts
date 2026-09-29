/**
 * Tests for src/ui/assets/auth.js — the browser-side awesome-node-auth client.
 *
 * Uses a happy-dom environment to simulate the browser (window, document, fetch).
 *
 * Architecture note:
 *   auth.js is an IIFE that captures window.fetch as `originalFetch` at
 *   evaluation time and replaces window.fetch with a CSRF+refresh interceptor.
 *   To test, we set window.fetch = fetchMock BEFORE calling eval() so that the
 *   IIFE captures our mock as originalFetch.  All subsequent fetch calls (both
 *   direct originalFetch calls and AuthService.apiCall which goes through the
 *   interceptor) therefore resolve via fetchMock.
 *
 * @vitest-environment happy-dom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

// ── Setup ────────────────────────────────────────────────────────────────────

const AUTH_JS_SRC = readFileSync(
    join(__dirname, '../src/ui/assets/auth.js'),
    'utf-8',
);

let fetchMock: ReturnType<typeof vi.fn>;

/**
 * Re-run the auth.js IIFE inside the current window context.
 * IMPORTANT: window.fetch MUST be set to fetchMock before calling this so that
 * the IIFE captures fetchMock as its internal `originalFetch`.
 * NOTE: does NOT touch window.__AUTH_CONFIG__ — set it before calling if needed.
 *
 * Why eval()? auth.js is a browser IIFE shipped as a static asset; it
 * deliberately uses closure state (refreshInProgress, isAuthenticated, …) and
 * intercepts window.fetch at load time.  eval() is the only way to re-execute
 * the IIFE with a fresh closure in each test while pointing `originalFetch` at
 * our mock.  This is safe here — it runs only in the vitest/happy-dom process
 * with no untrusted input; the source is a local file read at test startup.
 */
function loadAuthJs() {
    (window as any).AwesomeNodeAuth = undefined;
    (window as any).AuthService = undefined;
    // window.fetch is already set to fetchMock by beforeEach — eval captures it
    eval(AUTH_JS_SRC); // eslint-disable-line no-eval
}

/** Build a minimal fake Response compatible with the fetch API surface. */
function fakeResponse(body: unknown, status = 200): Response {
    return {
        ok: status >= 200 && status < 300,
        status,
        json: () => Promise.resolve(body),
    } as unknown as Response;
}

beforeEach(() => {
    // Reset SSR config before each test
    (window as any).__AUTH_CONFIG__ = undefined;
    // 1. Create a fresh mock
    fetchMock = vi.fn();
    // 2. Install it BEFORE loading auth.js so the IIFE captures it as originalFetch
    window.fetch = fetchMock as unknown as typeof fetch;
    // 3. Stable pathname — no /ui/ prefix, so apiPrefix defaults to /auth
    Object.defineProperty(window, 'location', {
        writable: true,
        configurable: true,
        value: { pathname: '/', href: 'http://localhost/' },
    });
    // 4. Load the IIFE
    loadAuthJs();
});

afterEach(() => {
    vi.restoreAllMocks();
});

// ── Globals ──────────────────────────────────────────────────────────────────

describe('globals registered', () => {
    it('registers window.AwesomeNodeAuth', () => {
        expect((window as any).AwesomeNodeAuth).toBeDefined();
    });

    it('registers window.AuthService', () => {
        expect((window as any).AuthService).toBeDefined();
    });
});

// ── Default config ───────────────────────────────────────────────────────────

describe('AwesomeNodeAuth default config', () => {
    it('defaults apiPrefix to /auth when pathname has no /ui/ segment', () => {
        expect((window as any).AwesomeNodeAuth.config.apiPrefix).toBe('/auth');
    });

    it('defaults homeUrl to /', () => {
        expect((window as any).AwesomeNodeAuth.config.homeUrl).toBe('/');
    });

    it('initial isAuthenticated() returns false', () => {
        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(false);
    });

    it('initial isInitialized() returns false', () => {
        expect((window as any).AwesomeNodeAuth.isInitialized()).toBe(false);
    });

    it('initial getUser() returns null', () => {
        expect((window as any).AwesomeNodeAuth.getUser()).toBeNull();
    });
});

// ── apiPrefix derivation from pathname ───────────────────────────────────────

describe('apiPrefix auto-derivation from /ui/ path', () => {
    it('derives prefix from /myapp/ui/login', () => {
        // Reset with a new pathname before loading the IIFE
        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: { pathname: '/myapp/ui/login', href: 'http://localhost/myapp/ui/login' },
        });
        loadAuthJs();
        expect((window as any).AwesomeNodeAuth.config.apiPrefix).toBe('/myapp');
    });

    it('derives prefix from /auth/ui/register', () => {
        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: { pathname: '/auth/ui/register', href: 'http://localhost/auth/ui/register' },
        });
        loadAuthJs();
        expect((window as any).AwesomeNodeAuth.config.apiPrefix).toBe('/auth');
    });
});

// ── AwesomeNodeAuth.init ─────────────────────────────────────────────────────────

describe('AwesomeNodeAuth.init()', () => {
    it('updates apiPrefix', () => {
        (window as any).AwesomeNodeAuth.init({ apiPrefix: '/api/v1/auth' });
        expect((window as any).AwesomeNodeAuth.config.apiPrefix).toBe('/api/v1/auth');
    });

    it('updates loginUrl', () => {
        (window as any).AwesomeNodeAuth.init({ loginUrl: '/sign-in' });
        expect((window as any).AwesomeNodeAuth.config.loginUrl).toBe('/sign-in');
    });

    it('updates homeUrl', () => {
        (window as any).AwesomeNodeAuth.init({ homeUrl: '/dashboard' });
        expect((window as any).AwesomeNodeAuth.config.homeUrl).toBe('/dashboard');
    });

    it('syncs config change to AuthService', () => {
        (window as any).AwesomeNodeAuth.init({ apiPrefix: '/custom' });
        expect((window as any).AuthService.config.apiPrefix).toBe('/custom');
    });

    it('registers a method override (login)', () => {
        const customLogin = vi.fn().mockResolvedValue({ success: true });
        (window as any).AwesomeNodeAuth.init({ login: customLogin });

        (window as any).AwesomeNodeAuth.login('a@b.com', 'pass');

        expect(customLogin).toHaveBeenCalledWith('a@b.com', 'pass');
    });

    it('ignores non-function method overrides silently', () => {
        // Should not throw
        expect(() => {
            (window as any).AwesomeNodeAuth.init({ login: 'not-a-function' } as any);
        }).not.toThrow();
    });

    it('registers all lifecycle hooks', () => {
        const hooks = {
            onLogout: vi.fn(),
            onSessionExpired: vi.fn(),
            onRefreshSuccess: vi.fn(),
            onRefreshFail: vi.fn(),
        };
        // Should not throw
        expect(() => {
            (window as any).AwesomeNodeAuth.init(hooks);
        }).not.toThrow();
    });
});

// ── checkSession ─────────────────────────────────────────────────────────────

describe('AwesomeNodeAuth.checkSession()', () => {
    it('returns true and sets user when /me responds 200', async () => {
        const user = { id: '1', email: 'a@b.com', role: 'user' };
        fetchMock.mockResolvedValueOnce(fakeResponse(user, 200));

        const result = await (window as any).AwesomeNodeAuth.checkSession();

        expect(result).toBe(true);
        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(true);
        expect((window as any).AwesomeNodeAuth.isInitialized()).toBe(true);
        expect((window as any).AwesomeNodeAuth.getUser()).toEqual(user);
        expect((window as any).AuthService.user).toEqual(user);
    });

    it('returns false and clears user when /me responds 401', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ error: 'Unauthorized' }, 401));

        const result = await (window as any).AwesomeNodeAuth.checkSession();

        expect(result).toBe(false);
        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(false);
        expect((window as any).AwesomeNodeAuth.getUser()).toBeNull();
    });

    it('returns false and clears user on network error', async () => {
        fetchMock.mockRejectedValueOnce(new Error('Network error'));

        const result = await (window as any).AwesomeNodeAuth.checkSession();

        expect(result).toBe(false);
        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(false);
    });

    it('marks isInitialized after the first check (success or failure)', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ error: 'Unauth' }, 401));

        await (window as any).AwesomeNodeAuth.checkSession();

        expect((window as any).AwesomeNodeAuth.isInitialized()).toBe(true);
    });
});

// ── login ────────────────────────────────────────────────────────────────────

describe('AwesomeNodeAuth.login()', () => {
    it('returns { success: true } on successful login and updates session', async () => {
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ success: true }))         // POST /login
            .mockResolvedValueOnce(fakeResponse({ id: '1', email: 'a@b.com' }, 200)); // GET /me

        const result = await (window as any).AwesomeNodeAuth.login('a@b.com', 'pass');

        expect(result.success).toBe(true);
        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(true);
    });

    it('returns { success: false, error } on failed login', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: false, error: 'Invalid credentials' }));

        const result = await (window as any).AwesomeNodeAuth.login('a@b.com', 'wrong');

        expect(result.success).toBe(false);
        expect(result.error).toBe('Invalid credentials');
    });

    it('returns requires2fa when server requests 2FA challenge', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({
            requiresTwoFactor: true,
            tempToken: 'tmp123',
            available2faMethods: ['totp'],
        }));

        const result = await (window as any).AwesomeNodeAuth.login('a@b.com', 'pass');

        expect(result.success).toBe(true);
        expect(result.requires2fa).toBe(true);
        expect(result.tempToken).toBe('tmp123');
        expect(result.availableMethods).toEqual(['totp']);
    });

    it('returns requires2FASetup when server asks for 2FA enrollment', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({
            requires2FASetup: true,
            tempToken: 'tmp456',
            error: '2FA setup required',
        }));

        const result = await (window as any).AwesomeNodeAuth.login('a@b.com', 'pass');

        expect(result.success).toBe(false);
        expect(result.requires2FASetup).toBe(true);
        expect(result.tempToken).toBe('tmp456');
    });

    it('calls custom override when registered via init()', async () => {
        const customLogin = vi.fn().mockResolvedValue({ success: true, custom: true });
        (window as any).AwesomeNodeAuth.init({ login: customLogin });

        const result = await (window as any).AwesomeNodeAuth.login('a@b.com', 'pass');

        expect(customLogin).toHaveBeenCalledWith('a@b.com', 'pass');
        expect(result.custom).toBe(true);
        // Custom override was used; fetchMock should NOT have been called
        expect(fetchMock).not.toHaveBeenCalled();
    });
});

// ── register ─────────────────────────────────────────────────────────────────

describe('AwesomeNodeAuth.register()', () => {
    it('returns { success: true } and authenticates user on success', async () => {
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ success: true }, 201))
            .mockResolvedValueOnce(fakeResponse({ id: '1', email: 'a@b.com' }, 200));

        const result = await (window as any).AwesomeNodeAuth.register('a@b.com', 'pass', 'Alice', 'Smith');

        expect(result.success).toBe(true);
        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(true);
    });

    it('returns { success: false, error } on duplicate email', async () => {
        fetchMock.mockResolvedValueOnce(
            fakeResponse({ success: false, error: 'Email already registered' }),
        );

        const result = await (window as any).AwesomeNodeAuth.register('dup@b.com', 'pass');

        expect(result.success).toBe(false);
        expect(result.error).toBe('Email already registered');
    });

    it('calls custom override when registered via init()', async () => {
        const customRegister = vi.fn().mockResolvedValue({ success: true });
        (window as any).AwesomeNodeAuth.init({ register: customRegister });

        await (window as any).AwesomeNodeAuth.register('a@b.com', 'pass');

        expect(customRegister).toHaveBeenCalled();
        expect(fetchMock).not.toHaveBeenCalled();
    });
});

// ── logout ───────────────────────────────────────────────────────────────────

describe('AwesomeNodeAuth.logout()', () => {
    it('clears session state after logout', async () => {
        // Prime authenticated state
        fetchMock.mockResolvedValueOnce(fakeResponse({ id: '1', email: 'a@b.com' }, 200));
        await (window as any).AwesomeNodeAuth.checkSession();
        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(true);

        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        const redirected: string[] = [];
        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: {
                pathname: '/dashboard',
                get href() { return 'http://localhost/dashboard'; },
                set href(v: string) { redirected.push(v); },
            },
        });

        await (window as any).AwesomeNodeAuth.logout();

        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(false);
        expect((window as any).AwesomeNodeAuth.getUser()).toBeNull();
    });

    it('calls onLogout hook instead of redirect', async () => {
        const onLogout = vi.fn();
        (window as any).AwesomeNodeAuth.init({ onLogout });

        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        await (window as any).AwesomeNodeAuth.logout();

        expect(onLogout).toHaveBeenCalledOnce();
    });

    it('calls custom logout override when registered', async () => {
        const customLogout = vi.fn().mockResolvedValue(undefined);
        (window as any).AwesomeNodeAuth.init({ logout: customLogout });

        await (window as any).AwesomeNodeAuth.logout();

        expect(customLogout).toHaveBeenCalledOnce();
        expect(fetchMock).not.toHaveBeenCalled();
    });
});

// ── password methods ─────────────────────────────────────────────────────────

describe('password methods', () => {
    it('forgotPassword POSTs to /forgot-password with email', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        await (window as any).AwesomeNodeAuth.forgotPassword('a@b.com');

        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/forgot-password');
        expect(JSON.parse(opts.body)).toMatchObject({ email: 'a@b.com' });
    });

    it('resetPassword POSTs to /reset-password with token and password', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        await (window as any).AwesomeNodeAuth.resetPassword('tok123', 'newPass!');

        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/reset-password');
        expect(JSON.parse(opts.body)).toMatchObject({ token: 'tok123', password: 'newPass!' });
    });

    it('changePassword POSTs to /change-password with currentPassword and newPassword', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        await (window as any).AwesomeNodeAuth.changePassword('oldPass', 'newPass');

        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/change-password');
        expect(JSON.parse(opts.body)).toMatchObject({ currentPassword: 'oldPass', newPassword: 'newPass' });
    });

    it('setPassword sends currentPassword="" to /change-password (OAuth accounts)', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        await (window as any).AwesomeNodeAuth.setPassword('brandNew');

        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/change-password');
        expect(JSON.parse(opts.body)).toMatchObject({ currentPassword: '', newPassword: 'brandNew' });
    });

    it('uses custom forgotPassword override when registered', async () => {
        const custom = vi.fn().mockResolvedValue({ success: true });
        (window as any).AwesomeNodeAuth.init({ forgotPassword: custom });

        await (window as any).AwesomeNodeAuth.forgotPassword('a@b.com');

        expect(custom).toHaveBeenCalledWith('a@b.com');
        expect(fetchMock).not.toHaveBeenCalled();
    });
});

// ── magic link ───────────────────────────────────────────────────────────────

describe('magic link methods', () => {
    it('sendMagicLink POSTs to /magic-link/send with mode: login', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        await (window as any).AwesomeNodeAuth.sendMagicLink('a@b.com');

        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/magic-link/send');
        expect(JSON.parse(opts.body)).toMatchObject({ email: 'a@b.com', mode: 'login' });
    });

    it('verifyMagicLink POSTs to /magic-link/verify and authenticates on success', async () => {
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ success: true }))
            .mockResolvedValueOnce(fakeResponse({ id: '1', email: 'a@b.com' }, 200));

        const result = await (window as any).AwesomeNodeAuth.verifyMagicLink('magicTok');

        expect(result.success).toBe(true);
        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(true);
        const [url] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/magic-link/verify');
    });

    it('verifyMagicLink returns error on failure', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: false, error: 'Expired token' }));

        const result = await (window as any).AwesomeNodeAuth.verifyMagicLink('expiredTok');

        expect(result.success).toBe(false);
        expect(result.error).toBe('Expired token');
    });
});

// ── 2FA ──────────────────────────────────────────────────────────────────────

describe('2FA methods', () => {
    it('setup2fa POSTs to /2fa/setup and returns secret + qrCode', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({
            secret: 'JBSWY3DPEHPK3PXP',
            qrCode: 'data:image/png;base64,...',
        }));

        const result = await (window as any).AwesomeNodeAuth.setup2fa();

        const [url] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/2fa/setup');
        expect(result.secret).toBe('JBSWY3DPEHPK3PXP');
    });

    it('verify2faSetup POSTs to /2fa/verify-setup with code and secret', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        await (window as any).AwesomeNodeAuth.verify2faSetup('123456', 'JBSWY3DPEHPK3PXP');

        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/2fa/verify-setup');
        expect(JSON.parse(opts.body)).toMatchObject({
            token: '123456',
            secret: 'JBSWY3DPEHPK3PXP',
        });
    });

    it('validate2fa POSTs to /2fa/verify with tempToken + totpCode and authenticates', async () => {
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ success: true }))
            .mockResolvedValueOnce(fakeResponse({ id: '1' }, 200));

        const result = await (window as any).AwesomeNodeAuth.validate2fa('tmpTok', '654321');

        expect(result.success).toBe(true);
        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(true);
        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/2fa/verify');
        expect(JSON.parse(opts.body)).toMatchObject({ tempToken: 'tmpTok', totpCode: '654321' });
    });
});

// ── SMS ──────────────────────────────────────────────────────────────────────

describe('SMS methods', () => {
    it('sendSmsLogin POSTs to /sms/send with mode: login', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        await (window as any).AwesomeNodeAuth.sendSmsLogin('a@b.com');

        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/sms/send');
        expect(JSON.parse(opts.body)).toMatchObject({ email: 'a@b.com', mode: 'login' });
    });

    it('verifySmsLogin POSTs to /sms/verify with mode: login and authenticates', async () => {
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ success: true }))
            .mockResolvedValueOnce(fakeResponse({ id: '1' }, 200));

        const result = await (window as any).AwesomeNodeAuth.verifySmsLogin('uid1', '123456');

        expect(result.success).toBe(true);
        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(true);
        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/sms/verify');
        expect(JSON.parse(opts.body)).toMatchObject({ userId: 'uid1', code: '123456', mode: 'login' });
    });

    it('validateSms POSTs to /sms/verify with mode: 2fa and authenticates', async () => {
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ success: true }))
            .mockResolvedValueOnce(fakeResponse({ id: '1' }, 200));

        await (window as any).AwesomeNodeAuth.validateSms('tmpTok', '999888');

        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/sms/verify');
        expect(JSON.parse(opts.body)).toMatchObject({ tempToken: 'tmpTok', code: '999888', mode: '2fa' });
    });
});

// ── Email verification ───────────────────────────────────────────────────────

describe('email verification methods', () => {
    it('resendVerificationEmail POSTs to /send-verification-email', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        await (window as any).AwesomeNodeAuth.resendVerificationEmail();

        const [url] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/send-verification-email');
    });

    it('verifyEmail GETs /verify-email with token in query string and authenticates', async () => {
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ success: true }))
            .mockResolvedValueOnce(fakeResponse({ id: '1' }, 200));

        const result = await (window as any).AwesomeNodeAuth.verifyEmail('verifyTok');

        expect(result.success).toBe(true);
        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/verify-email');
        expect(String(url)).toContain('verifyTok');
        expect(opts.method).toBe('GET');
    });

    it('uses custom resendVerificationEmail override', async () => {
        const custom = vi.fn().mockResolvedValue({ success: true });
        (window as any).AwesomeNodeAuth.init({ resendVerificationEmail: custom });

        await (window as any).AwesomeNodeAuth.resendVerificationEmail();

        expect(custom).toHaveBeenCalledOnce();
        expect(fetchMock).not.toHaveBeenCalled();
    });
});

// ── Email change ─────────────────────────────────────────────────────────────

describe('email change methods', () => {
    it('requestEmailChange POSTs to /change-email/request with newEmail', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        await (window as any).AwesomeNodeAuth.requestEmailChange('new@b.com');

        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/change-email/request');
        expect(JSON.parse(opts.body)).toMatchObject({ newEmail: 'new@b.com' });
    });

    it('confirmEmailChange POSTs to /change-email/confirm and re-authenticates', async () => {
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ success: true }))
            .mockResolvedValueOnce(fakeResponse({ id: '1', email: 'new@b.com' }, 200));

        const result = await (window as any).AwesomeNodeAuth.confirmEmailChange('changeTok');

        expect(result.success).toBe(true);
        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(true);
    });
});

// ── Account linking ──────────────────────────────────────────────────────────

describe('account linking methods', () => {
    it('requestLinkingEmail POSTs to /link-request with email and provider', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        await (window as any).AwesomeNodeAuth.requestLinkingEmail('other@b.com', 'email');

        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/link-request');
        expect(JSON.parse(opts.body)).toMatchObject({ email: 'other@b.com', provider: 'email' });
    });

    it('verifyLinkingToken POSTs to /link-verify and authenticates', async () => {
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ success: true }))
            .mockResolvedValueOnce(fakeResponse({ id: '1' }, 200));

        const result = await (window as any).AwesomeNodeAuth.verifyLinkingToken('lnkTok', 'google');

        expect(result.success).toBe(true);
        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/link-verify');
        expect(JSON.parse(opts.body)).toMatchObject({ token: 'lnkTok', provider: 'google' });
    });

    it('verifyConflictLinkingToken POSTs to /link-verify with loginAfterLinking=true', async () => {
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ success: true }))
            .mockResolvedValueOnce(fakeResponse({ id: '1' }, 200));

        await (window as any).AwesomeNodeAuth.verifyConflictLinkingToken('conflictTok');

        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/link-verify');
        expect(JSON.parse(opts.body)).toMatchObject({ token: 'conflictTok', loginAfterLinking: true });
    });

    it('getLinkedAccounts GETs /linked-accounts and returns array', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({
            linkedAccounts: [
                { provider: 'google', email: 'a@gmail.com', providerAccountId: 'gid1' },
            ],
        }));

        const accounts = await (window as any).AwesomeNodeAuth.getLinkedAccounts();

        expect(accounts).toHaveLength(1);
        expect(accounts[0].provider).toBe('google');
        const [url] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/linked-accounts');
    });

    it('getLinkedAccounts returns [] when response has no linkedAccounts', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({}));

        const accounts = await (window as any).AwesomeNodeAuth.getLinkedAccounts();

        expect(accounts).toEqual([]);
    });

    it('unlinkAccount DELETEs /linked-accounts/:provider/:providerAccountId', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        await (window as any).AwesomeNodeAuth.unlinkAccount('google', 'gid123');

        const [url, opts] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/linked-accounts/google/gid123');
        expect(opts.method).toBe('DELETE');
    });
});

// ── deleteAccount ────────────────────────────────────────────────────────────

describe('AwesomeNodeAuth.deleteAccount()', () => {
    it('clears auth state after successful deletion', async () => {
        // Prime authenticated state
        fetchMock.mockResolvedValueOnce(fakeResponse({ id: '1', email: 'a@b.com' }, 200));
        await (window as any).AwesomeNodeAuth.checkSession();

        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        const redirected: string[] = [];
        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: {
                pathname: '/account',
                get href() { return 'http://localhost/account'; },
                set href(v: string) { redirected.push(v); },
            },
        });

        const result = await (window as any).AwesomeNodeAuth.deleteAccount();

        expect(result.success).toBe(true);
        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(false);
        expect((window as any).AwesomeNodeAuth.getUser()).toBeNull();
        expect((window as any).AuthService.user).toBeNull();
    });

    it('calls onLogout hook instead of redirect after deletion', async () => {
        const onLogout = vi.fn();
        (window as any).AwesomeNodeAuth.init({ onLogout });

        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));

        await (window as any).AwesomeNodeAuth.deleteAccount();

        expect(onLogout).toHaveBeenCalledOnce();
    });

    it('returns error info when deletion fails', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ success: false, error: 'Cannot delete' }));

        const result = await (window as any).AwesomeNodeAuth.deleteAccount();

        expect(result.success).toBe(false);
        expect(result.error).toBe('Cannot delete');
        // State not cleared on failure
        expect(fetchMock).toHaveBeenCalledTimes(1);
    });
});

// ── guardPage ────────────────────────────────────────────────────────────────

describe('AwesomeNodeAuth.guardPage()', () => {
    it('does not redirect when session is active', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ id: '1', email: 'a@b.com' }, 200));

        const redirected: string[] = [];
        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: {
                pathname: '/dashboard',
                get href() { return 'http://localhost/dashboard'; },
                set href(v: string) { redirected.push(v); },
            },
        });

        await (window as any).AwesomeNodeAuth.guardPage();

        expect(redirected).toHaveLength(0);
    });

    it('redirects to default loginUrl when session is NOT active', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ error: 'Unauth' }, 401));

        const redirected: string[] = [];
        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: {
                pathname: '/dashboard',
                get href() { return 'http://localhost/dashboard'; },
                set href(v: string) { redirected.push(v); },
            },
        });

        await (window as any).AwesomeNodeAuth.guardPage();

        expect(redirected.length).toBeGreaterThan(0);
        expect(redirected[0]).toContain('login');
    });

    it('redirects to custom login URL when provided', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ error: 'Unauth' }, 401));

        const redirected: string[] = [];
        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: {
                pathname: '/app',
                get href() { return 'http://localhost/app'; },
                set href(v: string) { redirected.push(v); },
            },
        });

        await (window as any).AwesomeNodeAuth.guardPage('/custom-login');

        expect(redirected[0]).toBe('/custom-login');
    });

    it('does not redirect when already on login page', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ error: 'Unauth' }, 401));

        const redirected: string[] = [];
        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: {
                pathname: '/auth/ui/login',
                get href() { return 'http://localhost/auth/ui/login'; },
                set href(v: string) { redirected.push(v); },
            },
        });

        await (window as any).AwesomeNodeAuth.guardPage();

        // Already on login page — no redirect loop
        expect(redirected).toHaveLength(0);
    });
});

// ── guardRole ────────────────────────────────────────────────────────────────

describe('AwesomeNodeAuth.guardRole()', () => {
    it('does not redirect when user has required role (string field)', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ id: '1', role: 'admin' }, 200));

        const redirected: string[] = [];
        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: {
                pathname: '/admin',
                get href() { return 'http://localhost/admin'; },
                set href(v: string) { redirected.push(v); },
            },
        });

        await (window as any).AwesomeNodeAuth.guardRole('admin');

        expect(redirected).toHaveLength(0);
    });

    it('does not redirect when user has required role (roles array)', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ id: '1', roles: ['editor', 'admin'] }, 200));

        const redirected: string[] = [];
        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: {
                pathname: '/admin',
                get href() { return 'http://localhost/admin'; },
                set href(v: string) { redirected.push(v); },
            },
        });

        await (window as any).AwesomeNodeAuth.guardRole('admin');

        expect(redirected).toHaveLength(0);
    });

    it('redirects when user does not have required role', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ id: '1', role: 'user' }, 200));

        const redirected: string[] = [];
        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: {
                pathname: '/admin',
                get href() { return 'http://localhost/admin'; },
                set href(v: string) { redirected.push(v); },
            },
        });

        await (window as any).AwesomeNodeAuth.guardRole('admin');

        expect(redirected.length).toBeGreaterThan(0);
    });

    it('redirects to custom URL when provided', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ id: '1', role: 'user' }, 200));

        const redirected: string[] = [];
        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: {
                pathname: '/admin',
                get href() { return 'http://localhost/admin'; },
                set href(v: string) { redirected.push(v); },
            },
        });

        await (window as any).AwesomeNodeAuth.guardRole('admin', '/no-access');

        expect(redirected[0]).toBe('/no-access');
    });
});

// ── Fetch interceptor — CSRF injection ───────────────────────────────────────

describe('fetch interceptor — CSRF', () => {
    it('adds X-CSRF-Token header when csrf-token cookie is present', async () => {
        Object.defineProperty(document, 'cookie', {
            writable: true,
            configurable: true,
            value: 'csrf-token=test-csrf-value',
        });
        // Reload IIFE so the interceptor is re-registered with the new cookie state
        loadAuthJs();

        fetchMock.mockResolvedValueOnce(fakeResponse({ data: 'ok' }));

        // CSRF headers are only injected for auth backend requests
        await fetch('/auth/me');

        const [, opts] = fetchMock.mock.calls[0];
        expect(opts.headers['X-CSRF-Token']).toBe('test-csrf-value');
    });

    it('does NOT add X-CSRF-Token when cookie is absent', async () => {
        Object.defineProperty(document, 'cookie', {
            writable: true,
            configurable: true,
            value: '',
        });
        loadAuthJs();

        fetchMock.mockResolvedValueOnce(fakeResponse({ data: 'ok' }));

        await fetch('/auth/me');

        const [, opts] = fetchMock.mock.calls[0];
        expect(opts.headers?.['X-CSRF-Token']).toBeUndefined();
    });

    it('adds credentials: include on auth backend requests', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ data: 'ok' }));

        await fetch('/auth/me');

        const [, opts] = fetchMock.mock.calls[0];
        expect(opts.credentials).toBe('include');
    });

    it('does NOT add credentials: include on cross-origin third-party API requests', async () => {
        // Third-party APIs (e.g. LiteLLM, OpenAI, Stripe) return
        // Access-Control-Allow-Origin: * which browsers block if the request
        // includes credentials. The interceptor must leave them untouched.
        fetchMock.mockResolvedValueOnce(fakeResponse({ data: 'ok' }));

        await fetch('https://litellm.external.com/v1/chat/completions');

        const [, opts] = fetchMock.mock.calls[0];
        // credentials must remain unset for cross-origin third-party requests
        expect(opts.credentials).toBeUndefined();
    });

    it('adds credentials: include on same-origin non-auth-prefix requests (e.g. /mcp on the auth server)', async () => {
        // When the SPA and auth backend share the same origin, any request to
        // that origin should receive credentials — including /mcp or other
        // non-/auth-prefixed routes on the same server.
        fetchMock.mockResolvedValueOnce(fakeResponse({ data: 'ok' }));

        await fetch('/mcp/tool');

        const [, opts] = fetchMock.mock.calls[0];
        // same origin as apiPrefix → gets credentials
        expect(opts.credentials).toBe('include');
    });

    it('preserves caller credentials when already set', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ data: 'ok' }));

        await fetch('/api/data', { credentials: 'omit' } as RequestInit);

        const [, opts] = fetchMock.mock.calls[0];
        expect(opts.credentials).toBe('omit');
    });
});

// ── Fetch interceptor — auto-refresh on 401 ──────────────────────────────────

describe('fetch interceptor — auto-refresh', () => {
    it('retries original request after successful token refresh on 401', async () => {
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ error: 'Unauthorized' }, 401))  // 1st call → 401
            .mockResolvedValueOnce(fakeResponse({ success: true }))               // refresh
            .mockResolvedValueOnce(fakeResponse({ data: 'ok' }));                  // retry

        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: { pathname: '/dashboard', href: 'http://localhost/dashboard', set href(v) {} },
        });

        await fetch('/api/protected');

        // 3 calls: original + refresh + retry
        expect(fetchMock).toHaveBeenCalledTimes(3);
    });

    it('retries after refresh when backend returns no explicit success field (lenient check)', async () => {
        // Some backends return { accessToken: "..." } without an explicit success field.
        // The interceptor must treat any truthy response without success:false as a success.
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ error: 'Unauthorized' }, 401))
            .mockResolvedValueOnce(fakeResponse({ accessToken: 'new-token' }))  // no success field
            .mockResolvedValueOnce(fakeResponse({ data: 'ok' }));

        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: { pathname: '/dashboard', href: 'http://localhost/dashboard', set href(v) {} },
        });

        await fetch('/api/protected');

        expect(fetchMock).toHaveBeenCalledTimes(3);
    });

    it('retries original request after successful token refresh on 403 (Forbidden)', async () => {
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ error: 'Forbidden' }, 403))  // 1st call → 403
            .mockResolvedValueOnce(fakeResponse({ success: true }))             // refresh
            .mockResolvedValueOnce(fakeResponse({ data: 'ok' }));               // retry

        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: { pathname: '/dashboard', href: 'http://localhost/dashboard', set href(v) {} },
        });

        await fetch('/api/restricted');

        // 3 calls: original + refresh + retry
        expect(fetchMock).toHaveBeenCalledTimes(3);
    });

    it('calls onRefreshSuccess hook after a successful refresh', async () => {
        const onRefreshSuccess = vi.fn();
        (window as any).AwesomeNodeAuth.init({ onRefreshSuccess });

        fetchMock
            .mockResolvedValueOnce(fakeResponse({ error: 'Unauthorized' }, 401))
            .mockResolvedValueOnce(fakeResponse({ success: true }))
            .mockResolvedValueOnce(fakeResponse({ data: 'ok' }));

        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: { pathname: '/dashboard', href: 'http://localhost/dashboard', set href(v) {} },
        });

        await fetch('/api/protected');

        expect(onRefreshSuccess).toHaveBeenCalledOnce();
    });

    it('calls onRefreshFail and clears session when refresh fails', async () => {
        const onRefreshFail = vi.fn();
        (window as any).AwesomeNodeAuth.init({ onRefreshFail });

        fetchMock
            .mockResolvedValueOnce(fakeResponse({ error: 'Unauthorized' }, 401))
            .mockResolvedValueOnce(fakeResponse({ success: false }));  // refresh fails

        await fetch('/api/protected');

        expect(onRefreshFail).toHaveBeenCalledOnce();
        expect((window as any).AwesomeNodeAuth.isAuthenticated()).toBe(false);
    });

    it('calls onSessionExpired when refresh fails and onRefreshFail is not set', async () => {
        const onSessionExpired = vi.fn();
        (window as any).AwesomeNodeAuth.init({ onSessionExpired });

        fetchMock
            .mockResolvedValueOnce(fakeResponse({ error: 'Unauthorized' }, 401))
            .mockResolvedValueOnce(fakeResponse({ success: false }))  // refresh fails
            .mockResolvedValueOnce(fakeResponse({ success: true }));  // logout call

        await fetch('/api/protected');

        expect(onSessionExpired).toHaveBeenCalledOnce();
    });

    it('does NOT trigger refresh for auth endpoints (avoids infinite loop)', async () => {
        // /auth/login returns 401 (wrong creds) — must NOT trigger refresh
        fetchMock.mockResolvedValueOnce(fakeResponse({ error: 'Bad credentials' }, 401));

        await fetch('/auth/login', { method: 'POST' } as RequestInit);

        // Only 1 call — no refresh or retry
        expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it('does NOT trigger refresh for /auth/me 401', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ error: 'Unauthorized' }, 401));

        await fetch('/auth/me');

        expect(fetchMock).toHaveBeenCalledTimes(1);
    });
});

// ── AuthService.init() — SSR fast-path ──────────────────────────────────────

describe('AuthService.init() — SSR fast-path', () => {
    it('uses window.__AUTH_CONFIG__ and skips the /ui/config fetch', async () => {
        // Simulate SSR: set __AUTH_CONFIG__ before auth.js loads (as ui.router.ts injects it)
        (window as any).__AUTH_CONFIG__ = {
            apiPrefix: '/custom-prefix',
            features: { register: true },
            ui: { primaryColor: '#ff0000', siteName: 'My App' },
        };
        loadAuthJs();

        // Only GET /me is expected (from checkSession inside init)
        fetchMock.mockResolvedValueOnce(fakeResponse({ id: '1', email: 'a@b.com' }, 200));

        await (window as any).AuthService.init();

        const configCalls = fetchMock.mock.calls.filter(([url]: string[]) =>
            String(url).includes('/config'),
        );
        expect(configCalls).toHaveLength(0);
        // Config was merged from window.__AUTH_CONFIG__
        expect((window as any).AwesomeNodeAuth.config.apiPrefix).toBe('/custom-prefix');
        expect((window as any).AwesomeNodeAuth.config.features.register).toBe(true);
    });

    it('fetches /ui/config when __AUTH_CONFIG__ is NOT injected', async () => {
        // __AUTH_CONFIG__ is already undefined (set in beforeEach)
        // Config fetch
        fetchMock.mockResolvedValueOnce(fakeResponse({ apiPrefix: '/from-server', features: {} }));
        // GET /me (checkSession)
        fetchMock.mockResolvedValueOnce(fakeResponse({ id: '1' }, 200));

        await (window as any).AuthService.init();

        const configCalls = fetchMock.mock.calls.filter(([url]: string[]) =>
            String(url).includes('/config'),
        );
        expect(configCalls.length).toBeGreaterThan(0);
        expect((window as any).AwesomeNodeAuth.config.apiPrefix).toBe('/from-server');
    });

    it('updates AuthService.user after init when session is active', async () => {
        // Simulate SSR injection before auth.js loads
        (window as any).__AUTH_CONFIG__ = { apiPrefix: '/auth' };
        loadAuthJs();

        fetchMock.mockResolvedValueOnce(fakeResponse({ id: '1', email: 'me@example.com' }, 200));

        await (window as any).AuthService.init();

        expect((window as any).AuthService.user).toMatchObject({ email: 'me@example.com' });
    });
});

// ── AuthService.apiCall ───────────────────────────────────────────────────────

describe('AuthService.apiCall()', () => {
    it('sets Content-Type: application/json and Accept: application/json', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ ok: true }));

        await (window as any).AuthService.apiCall('/me', 'GET');

        const [, opts] = fetchMock.mock.calls[0];
        expect(opts.headers['Content-Type']).toBe('application/json');
        expect(opts.headers['Accept']).toBe('application/json');
    });

    it('sends JSON body for POST requests', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ ok: true }));

        await (window as any).AuthService.apiCall('/login', 'POST', { email: 'a@b.com' });

        const [, opts] = fetchMock.mock.calls[0];
        expect(opts.body).toBe(JSON.stringify({ email: 'a@b.com' }));
    });

    it('does NOT send body for GET requests', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ users: [] }));

        await (window as any).AuthService.apiCall('/users', 'GET');

        const [, opts] = fetchMock.mock.calls[0];
        expect(opts.body).toBeUndefined();
    });

    it('returns error meta when response is not ok', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({ error: 'Not found' }, 404));

        const result = await (window as any).AuthService.apiCall('/unknown', 'GET');

        expect(result.success).toBe(false);
        expect(result.error).toBe('Not found');
    });

    it('fills default error message when non-ok body has no error field', async () => {
        fetchMock.mockResolvedValueOnce(fakeResponse({}, 500));

        const result = await (window as any).AuthService.apiCall('/crash', 'GET');

        expect(result.success).toBe(false);
        expect(result.error).toMatch(/500/);
    });

    it('builds full URL using configured apiPrefix', async () => {
        (window as any).AwesomeNodeAuth.init({ apiPrefix: '/api/v2' });
        fetchMock.mockResolvedValueOnce(fakeResponse({ ok: true }));

        await (window as any).AuthService.apiCall('/login', 'POST', { email: 'x@y.com' });

        const [url] = fetchMock.mock.calls[0];
        expect(String(url)).toContain('/api/v2/login');
    });
});

// ── Headless mode ────────────────────────────────────────────────────────────
//
// When auth.js runs in headless mode it must NOT redirect window.location on
// session expiry or refresh failure.  Two activation paths exist:
//
//  a) SSR injection: __AUTH_CONFIG__ has headless:true → applied by AuthService.init()
//  b) Explicit init: AwesomeNodeAuth.init({ headless:true }) → applied immediately
//
// All tests below rely on the single interceptor installed by the global beforeEach
// (loadAuthJs is NOT re-called in order to avoid double-interceptor stacking).

describe('headless mode — _applyHeadlessIfNeeded()', () => {
    const redirected: string[] = [];

    beforeEach(() => {
        redirected.length = 0;
        Object.defineProperty(window, 'location', {
            writable: true,
            configurable: true,
            value: {
                pathname: '/docs/intro',
                href: 'http://localhost/docs/intro',
                set href(v: string) { redirected.push(v); },
            },
        });
    });

    // ── Path a: SSR injection (AuthService.init reads __AUTH_CONFIG__) ────────

    it('does NOT redirect on session expiry when __AUTH_CONFIG__ has headless:true', async () => {
        // Set headless config — AuthService.init() will read it and call _applyHeadlessIfNeeded()
        (window as any).__AUTH_CONFIG__ = { apiPrefix: '/auth', headless: true };

        fetchMock.mockResolvedValueOnce(fakeResponse({ id: '1', email: 'u@x.com' }, 200));
        await (window as any).AuthService.init();

        // Protected fetch → 401 → refresh fails → should NOT redirect
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ error: 'Unauthorized' }, 401))
            .mockResolvedValueOnce(fakeResponse({ success: false }));

        await fetch('/api/protected');

        expect(redirected).toHaveLength(0);
    });

    it('does NOT redirect on session expiry when /ui/config returns headless:true', async () => {
        // No SSR injection — config is fetched from /ui/config
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ apiPrefix: '/auth', headless: true }))  // /config
            .mockResolvedValueOnce(fakeResponse({ id: '1', email: 'u@x.com' }, 200));      // /me
        await (window as any).AuthService.init();

        fetchMock
            .mockResolvedValueOnce(fakeResponse({ error: 'Unauthorized' }, 401))
            .mockResolvedValueOnce(fakeResponse({ success: false }));

        await fetch('/api/protected');

        expect(redirected).toHaveLength(0);
    });

    it('allows explicit onSessionExpired override even in headless mode', async () => {
        const onSessionExpired = vi.fn();
        (window as any).__AUTH_CONFIG__ = { apiPrefix: '/auth', headless: true };

        fetchMock.mockResolvedValueOnce(fakeResponse({ id: '1', email: 'u@x.com' }, 200));
        await (window as any).AuthService.init();

        // Register custom handler AFTER init — overrides the headless no-op
        (window as any).AwesomeNodeAuth.init({ onSessionExpired });

        fetchMock
            .mockResolvedValueOnce(fakeResponse({ error: 'Unauthorized' }, 401))
            .mockResolvedValueOnce(fakeResponse({ success: false }));

        await fetch('/api/protected');

        expect(onSessionExpired).toHaveBeenCalledOnce();
        expect(redirected).toHaveLength(0); // custom handler ran, no href redirect
    });

    // ── Path b: Explicit AwesomeNodeAuth.init({ headless: true }) ─────────────

    it('does NOT redirect when AwesomeNodeAuth.init({ headless:true }) is called', async () => {
        // Simulates the Docusaurus inline head script calling init() before components mount
        (window as any).AwesomeNodeAuth.init({ apiPrefix: '/auth', headless: true });

        // Protected fetch → 401 → refresh fails → should NOT redirect
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ error: 'Unauthorized' }, 401))
            .mockResolvedValueOnce(fakeResponse({ success: false }));

        await fetch('/api/protected');

        expect(redirected).toHaveLength(0);
    });

    it('does NOT redirect on logout when headless:true', async () => {
        (window as any).__AUTH_CONFIG__ = { apiPrefix: '/auth', headless: true };

        fetchMock
            .mockResolvedValueOnce(fakeResponse({ id: '1', email: 'u@x.com' }, 200))
            .mockResolvedValueOnce(fakeResponse({ success: true }));
        await (window as any).AuthService.init();
        await (window as any).AwesomeNodeAuth.logout();

        expect(redirected).toHaveLength(0);
    });

    it('still performs token refresh in headless mode (fetch interceptor unchanged)', async () => {
        (window as any).__AUTH_CONFIG__ = { apiPrefix: '/auth', headless: true };

        fetchMock.mockResolvedValueOnce(fakeResponse({ id: '1', email: 'u@x.com' }, 200));
        await (window as any).AuthService.init();

        // 401 → refresh succeeds → retry succeeds
        fetchMock
            .mockResolvedValueOnce(fakeResponse({ error: 'Unauthorized' }, 401))
            .mockResolvedValueOnce(fakeResponse({ success: true }))
            .mockResolvedValueOnce(fakeResponse({ data: 'secret' }));

        await fetch('/api/protected');

        expect(fetchMock).toHaveBeenCalledTimes(4); // init(/me) + 401 + refresh + retry
        expect(redirected).toHaveLength(0);
    });

    it('AwesomeNodeAuth.init({ headless:true }) is idempotent with custom onLogout override', async () => {
        // First pass: headless installs no-op for onLogout
        (window as any).AwesomeNodeAuth.init({ headless: true });
        // Second pass: explicit onLogout override — must win over the no-op
        const customLogout = vi.fn();
        (window as any).AwesomeNodeAuth.init({ onLogout: customLogout });

        fetchMock.mockResolvedValueOnce(fakeResponse({ success: true }));
        await (window as any).AwesomeNodeAuth.logout();

        expect(customLogout).toHaveBeenCalledOnce();
        expect(redirected).toHaveLength(0);
    });
});

// ── headless mode — /config endpoint exposes headless flag ───────────────────
// These tests verify the server-side contract: the /config response must include
// { headless: true } when the UI router is configured in headless mode.
// We test the router-level logic directly without spinning up a real server.

import { buildUiRouter } from '../src/router/ui.router';
import requestLib from 'supertest';
import { listen } from './helpers/listen';
import expressLib from 'express';

describe('buildUiRouter — headless mode', () => {
    const headlessAuthConfig = {
        accessTokenSecret: 'test',
        refreshTokenSecret: 'test',
        ui: { headless: true },
    };

    const fullAuthConfig = {
        accessTokenSecret: 'test',
        refreshTokenSecret: 'test',
        ui: { headless: false },
    };

    it('GET /config returns headless:true when authConfig.ui.headless is true', async () => {
        const app = expressLib();
        app.use('/auth/ui', buildUiRouter({ authConfig: headlessAuthConfig }));

        const res = await requestLib(await listen(app)).get('/auth/ui/config');

        expect(res.status).toBe(200);
        expect(res.body.headless).toBe(true);
    });

    it('GET /config returns headless:false when authConfig.ui.headless is false', async () => {
        const app = expressLib();
        app.use('/auth/ui', buildUiRouter({ authConfig: fullAuthConfig }));

        const res = await requestLib(await listen(app)).get('/auth/ui/config');

        expect(res.status).toBe(200);
        expect(res.body.headless).toBe(false);
    });

    it('GET /login returns 404 in headless mode', async () => {
        const app = expressLib();
        app.use('/auth/ui', buildUiRouter({ authConfig: headlessAuthConfig }));

        const res = await requestLib(await listen(app)).get('/auth/ui/login');

        expect(res.status).toBe(404);
    });

    it('GET /login returns HTML in normal (non-headless) mode — not a 404', async () => {
        const app = expressLib();
        app.use('/auth/ui', buildUiRouter({ authConfig: fullAuthConfig }));

        const res = await requestLib(await listen(app)).get('/auth/ui/login');

        // The response should be 200 (HTML served) — verify it's NOT a headless 404
        expect(res.status).toBe(200);
        expect(res.headers['content-type']).toMatch(/text\/html/);
    });

    it('GET /auth.js is accessible in headless mode (static asset)', async () => {
        const app = expressLib();
        app.use('/auth/ui', buildUiRouter({ authConfig: headlessAuthConfig }));

        const res = await requestLib(await listen(app)).get('/auth/ui/auth.js');

        expect([200, 304]).toContain(res.status);
    });
});
