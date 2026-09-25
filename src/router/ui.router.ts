import { Router, Request, Response, NextFunction, static as expressStatic } from 'express';
import path from 'path';
import fs from 'fs';
import { AuthConfig } from '../models/auth-config.model';
import { ISettingsStore } from '../interfaces/settings-store.interface';
import { ITemplateStore } from '../interfaces/template-store.interface';
import { RouterOptions, resolveApiPrefix } from './auth.router';

/*
 * End-user login UI lives here at /auth/ui/login. Admin login lives in
 * admin.router.ts (typically /auth/admin/login when mounted together).
 * Keep the two flows distinct: this router is for application users only.
 */

export interface UiRouterOptions {
    /**
     * Optional path to a directory containing custom UI assets.
     * If not provided, the internal Vanilla JS UI will be served.
     */
    uiAssetsDir?: string;

    /**
     * Optional directory where uploaded assets (like logos) are stored.
     * If provided, files in this directory will be served under `/ assets / logo / `.
     */
    uploadDir?: string;

    /**
     * Optional settings store to fetch real-time UI customization (colors, site name).
     * If not provided, defaults from `authConfig.ui` or hardcoded values are used.
     */
    settingsStore?: ISettingsStore;

    /**
     * Core authentication configuration.
     * Used to determine which features (OAuth, Register, etc.) are enabled.
     */
    authConfig: AuthConfig;

    /**
     * Optional router options (where strategies and onRegister are defined).
     */
    routerOptions?: RouterOptions;

    /**
     * The base path where the main auth router is mounted.
     * Used by the UI to know where to send API requests.
     * @default '/auth'
     */
    apiPrefix?: string;

    /**
     * Optional template store for UI translations.
     */
    templateStore?: ITemplateStore;
}

/**
 * Builds a router that serves the static UI assets and provides a
 * `/ config` endpoint for dynamic UI behavior and theming.
 *
 * @param options Configuration for the UI router.
 */
export function buildUiRouter(options: UiRouterOptions): Router {
    const router = Router();
    const { uploadDir, settingsStore, templateStore, authConfig, routerOptions } = options;
    const apiPrefix = resolveApiPrefix(authConfig, routerOptions);

    // In some environments (like ESM bundling), __dirname may not be available.
    let _dirname = '';
    try {
        _dirname = __dirname;
    } catch (e) {
        // Fallback for ESM if needed - though in CJS context this is rarely hit
        _dirname = process.cwd();
    }

    const candidates = [
        path.resolve(_dirname, '../ui-assets'), // dist
        path.resolve(_dirname, '../../ui-assets'), // alternate dist
        path.resolve(_dirname, '../ui/assets'), // src
        path.resolve(_dirname, '../../src/ui/assets'), // alternate src
        path.resolve(process.cwd(), 'node_modules/awesome-node-auth/dist/ui-assets'), // dependency
        path.resolve(process.cwd(), 'node_modules/awesome-node-auth/src/ui/assets'), // dependency src
    ];

    let uiAssetsDir = options.uiAssetsDir;
    if (!uiAssetsDir) {
        for (const candidate of candidates) {
            if (fs.existsSync(candidate)) {
                uiAssetsDir = candidate;
                break;
            }
        }
    }

    if (!uiAssetsDir) {
        uiAssetsDir = candidates[0];
    }

    async function getUiConfig(req: Request) {
        try {
            const reqBaseUrl = req.baseUrl;
            const resolvedApiPrefix = reqBaseUrl.replace(/\/ui$/, '') || apiPrefix;
            const settings = settingsStore ? await settingsStore.getSettings() : {};

            // Resolve language
            const queryLang = req.query.lang as string | undefined;
            const lang = queryLang || authConfig.email?.mailer?.defaultLang || 'en';

            let translations: Record<string, string> = {};
            if (templateStore) {
                const page = req.path.replace(/^\//, '') || 'login';
                const res = await templateStore.getUiTranslations(page);
                if (res) {
                    translations = res.translations[lang] || res.translations['en'] || {};
                }
            }

            const features = {
                register: !!routerOptions?.onRegister,
                magicLink: !!authConfig.email?.sendMagicLink || !!authConfig.email?.mailer,
                sms: !!authConfig.sms,
                google: !!authConfig.oauth?.google,
                github: !!authConfig.oauth?.github,
                forgotPassword: !!authConfig.email?.sendPasswordReset || !!authConfig.email?.mailer,
                verifyEmail: (!!authConfig.email?.sendVerificationEmail || !!authConfig.email?.mailer) && (authConfig.emailVerificationMode !== 'none' || authConfig.requireEmailVerification),
                twoFactor: !!authConfig.twoFactor,
            };

            const ui = {
                primaryColor: settings.ui?.primaryColor || authConfig.ui?.primaryColor || '#4a90d9',
                secondaryColor: settings.ui?.secondaryColor || authConfig.ui?.secondaryColor || '#6c757d',
                logoUrl: settings.ui?.logoUrl || authConfig.ui?.customLogo || authConfig.ui?.logoUrl,
                siteName: settings.ui?.siteName || authConfig.ui?.siteName || 'Awesome Node Auth',
                customCss: authConfig.ui?.customCss,
                bgColor: settings.ui?.bgColor || authConfig.ui?.bgColor,
                bgImage: settings.ui?.bgImage || authConfig.ui?.bgImage,
                cardBg: settings.ui?.cardBg || authConfig.ui?.cardBg,
            };

            return {
                apiPrefix: resolvedApiPrefix,
                features,
                ui,
                translations,
                lang,
            };
        } catch (err) {
            const fallbackApiPrefix = req.baseUrl.replace(/\/ui$/, '') || apiPrefix;
            return {
                apiPrefix: fallbackApiPrefix,
                features: { register: false, google: false, github: false },
                ui: {
                    primaryColor: '#4a90d9',
                    secondaryColor: '#6c757d',
                    siteName: 'Awesome Node Auth',
                    logoUrl: undefined,
                    customCss: undefined,
                    bgColor: undefined,
                    bgImage: undefined,
                    cardBg: undefined
                },
                translations: {},
                lang: 'en'
            };
        }
    }

    // 1. Configuration endpoint for the UI (still available for dynamic fetching)
    router.get('/config', async (req: Request, res: Response) => {
        const config = await getUiConfig(req);
        // Include headless flag so auth.js can auto-configure itself
        (config as any).headless = !!(authConfig.ui?.headless);
        res.json(config);
    });

    // In headless mode the HTML pages are not served (the hosting SPA provides
    // its own login UI). We still serve /config and static assets (auth.js, CSS)
    // so SPAs can load auth.js via <script> and use the fetch interceptor.
    if (authConfig.ui?.headless) {
        // Serve static assets (JS, CSS) — needed for the <script> tag integration
        router.use('/', expressStatic(uiAssetsDir, {
            maxAge: 0,
            index: false,
        }));
        return router;
    }

    // 2. Serve custom uploaded assets (e.g. logo, background images)
    if (uploadDir) {
        // Legacy path for backwards compatibility with existing logo URLs
        router.use('/assets/logo', expressStatic(uploadDir));
        // New unified path for all uploaded UI assets
        router.use('/assets/uploads', expressStatic(uploadDir));
    }

    // Helper to perform Server-Side Rendering (SSR) of Config and CSS
    async function serveSsrHtml(req: Request, res: Response, htmlPath: string) {
        console.log('[AwesomeNodeAuth] process SSR for', htmlPath);
        try {
            let htmlContent = await fs.promises.readFile(htmlPath, 'utf8');
            console.log('[AwesomeNodeAuth] read file length:', htmlContent.length);
            const config = await getUiConfig(req);

            // Construct style snippet to prevent FOUC (Flash of Unstyled Content)
            let styleTags = '<style>:root {';
            if (config.ui?.primaryColor) {
                styleTags += `--primary-color: ${config.ui.primaryColor};`;
                styleTags += `--input-focus: ${config.ui.primaryColor};`;
            }
            if (config.ui?.secondaryColor) styleTags += `--secondary-color: ${config.ui.secondaryColor};`;
            if (config.ui?.bgColor) styleTags += `--bg-color: ${config.ui.bgColor};`;
            if (config.ui?.cardBg) styleTags += `--card-bg: ${config.ui.cardBg};`;
            if (config.ui?.bgImage) {
                const safeUrl = config.ui.bgImage.replace(/['"\\]/g, m => encodeURIComponent(m));
                styleTags += `--bg-image: url("${safeUrl}");`;
            }
            styleTags += '}</style>';

            // Handle custom CSS and Site Name
            if (config.ui?.customCss) styleTags += `<style>${config.ui.customCss}</style>`;
            if (config.ui?.siteName) {
                const safeSiteName = config.ui.siteName
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#39;');
                htmlContent = htmlContent.replace(/<title>.*?<\/title>/s, `<title>${safeSiteName}</title>`);
                htmlContent = htmlContent.replace(/(<h1[^>]*class="site-name"[^>]*>).*?(<\/h1>)/s, `$1${safeSiteName}$2`);
            }
            if (config.ui?.logoUrl) {
                htmlContent = htmlContent.replace(/<img src=".*?" alt="Logo" class="logo hidden">/, `<img src="${config.ui.logoUrl}" alt="Logo" class="logo">`);
            }

            // Readiness Splash Screen Injection
            const splashCss = `
            <style>
                body { background-color: var(--bg-color, #f8fafc); margin: 0; }
                #global-splash {
                    position: fixed;
                    top: 0; left: 0; width: 100vw; height: 100vh;
                    background-color: var(--bg-color, #f8fafc);
                    z-index: 999999;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    transition: opacity 0.3s ease-out;
                }
                .splash-spinner {
                    width: 40px; height: 40px;
                    border: 4px solid var(--secondary-color, #cbd5e1);
                    border-top: 4px solid var(--primary-color, #4a90d9);
                    border-radius: 50%;
                    animation: splash-spin 1s linear infinite;
                }
                @keyframes splash-spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            </style>`;

            const splashHtml = `
            <div id="global-splash">
                <div class="splash-spinner"></div>
            </div>`;

            const splashJs = `
            <script>
                window.onload = function() {
                    const splash = document.getElementById('global-splash');
                    if (splash) {
                        splash.style.opacity = '0';
                        setTimeout(() => splash.remove(), 300);
                    }
                };
            </script>`;

            // Construct script injection for fast synchronous auth.js booting
            const scriptTag = `<script>window.__AUTH_CONFIG__ = ${JSON.stringify(config)};</script>`;

            // Inject just before </head>
            htmlContent = htmlContent.replace('</head>', `${styleTags}\n${splashCss}\n${scriptTag}\n</head>`);

            // Inject splash html right after <body>
            htmlContent = htmlContent.replace('<body>', `<body>\n${splashHtml}`);

            // Inject splash js parser right before </body>
            htmlContent = htmlContent.replace('</body>', `${splashJs}\n</body>`);

            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
            res.send(htmlContent);
        } catch (err) {
            console.error('[AwesomeNodeAuth UI Router] SSR Error:', err);
            // Fallback to static sending if reading/parsing fails
            res.sendFile(htmlPath);
        }
    }

    // 3. Vanilla UI Route Mapping & SPA fallback
    // Matches all extensionless paths and renders the corresponding HTML file with SSR config
    router.use(async (req: Request, res: Response, next: NextFunction) => {
        if (req.method !== 'GET') {
            return next();
        }

        if (path.extname(req.path)) {
            // Let expressStatic handle real files (css, js, images)
            return next();
        }

        // Map clean routes to internal HTML files if they exist
        const page = req.path.replace(/^\//, '') || 'login';
        const htmlFile = `${page}.html`;
        const htmlPath = path.join(uiAssetsDir, htmlFile);

        if (fs.existsSync(htmlPath)) {
            await serveSsrHtml(req, res, htmlPath);
            return;
        }

        // Default fallback to login or index
        const fallbackFiles = ['login.html', 'index.html', 'index.csr.html'];
        for (const file of fallbackFiles) {
            const fallbackPath = path.join(uiAssetsDir, file);
            if (fs.existsSync(fallbackPath)) {
                await serveSsrHtml(req, res, fallbackPath);
                return;
            }
        }

        next(); // Let it fall through if nothing works
    });

    // 4. Serve UI assets (css, js, static files)
    router.use('/', expressStatic(uiAssetsDir, {
        maxAge: 0,
        index: false
    }));



    return router;
}
