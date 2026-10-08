/**
 * The browser client `auth.js` and `<prefix>/ui/config` are served as soon as
 * the auth router is mounted, whatever `ui.enabled` says.  `ui.enabled` only
 * adds the HTML pages and the other static assets; `ui.headless` keeps the
 * assets and drops the pages, as before.
 *
 * Covered for `auth.router()` mounted by the host, `createAuthRouter()`, and
 * `buildAllRouters()`, with the default `/auth` prefix and with a custom one.
 */

import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';
import type http from 'node:http';
import { readFileSync } from 'fs';
import { join } from 'path';
import { listen } from './helpers/listen';
import { AuthConfigurator } from '../src/auth-configurator';
import { createAuthRouter } from '../src/router/auth.router';
import { buildUiRouter } from '../src/router/ui.router';
import type { AuthConfig } from '../src/models/auth-config.model';
import { InMemoryUserStore } from '../examples/in-memory-user-store';

/** The file the router serves, read as raw bytes (CRLF-safe on any checkout). */
const AUTH_JS = readFileSync(join(__dirname, '../src/ui/assets/auth.js'));

const BASE: AuthConfig = {
  accessTokenSecret: 'ui-authjs-access-secret-at-least-32-chars',
  refreshTokenSecret: 'ui-authjs-refresh-secret-at-least-32-chars',
};

const ADMIN = { admin: { accessPolicy: 'open' as const } };

type Ui = AuthConfig['ui'];

/** `app.use(prefix, auth.router())`: the documented host mount. */
function viaRouter(ui: Ui, prefix = '/auth'): Promise<http.Server> {
  const app = express();
  const config: AuthConfig = ui === undefined ? BASE : { ...BASE, ui };
  app.use(prefix, new AuthConfigurator(config, new InMemoryUserStore()).router());
  return listen(app);
}

/** `app.use(auth.buildAllRouters(...))`: the configurator mounts at its own prefix. */
function viaBuildAll(config: AuthConfig, configuratorPrefix?: string): Promise<http.Server> {
  const app = express();
  const auth = new AuthConfigurator(
    config,
    new InMemoryUserStore(),
    configuratorPrefix ? { apiPrefix: configuratorPrefix } : {},
  );
  app.use(auth.buildAllRouters(ADMIN));
  return listen(app);
}

/** GET with the raw body as a Buffer, whatever the content type. */
function getRaw(server: http.Server, path: string) {
  return request(server)
    .get(path)
    .buffer(true)
    .parse((res, cb) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => cb(null, Buffer.concat(chunks)));
    });
}

async function expectAuthJs(server: http.Server, path: string) {
  const res = await getRaw(server, path);
  expect(res.status, `GET ${path}`).toBe(200);
  expect(res.headers['content-type']).toMatch(/javascript/);
  expect(Buffer.compare(res.body as Buffer, AUTH_JS), `${path} serves src/ui/assets/auth.js byte for byte`).toBe(0);
}

async function expectStatus(server: http.Server, path: string, status: number) {
  const res = await request(server).get(path);
  expect(res.status, `GET ${path}`).toBe(status);
  return res;
}

async function expectConfig(server: http.Server, prefix: string, headless: boolean) {
  const res = await expectStatus(server, `${prefix}/ui/config`, 200);
  expect(res.headers['content-type']).toMatch(/json/);
  expect(res.body.apiPrefix).toBe(prefix);
  expect(res.body.headless).toBe(headless);
  expect(typeof res.body.features).toBe('object');
  expect(typeof res.body.ui).toBe('object');
  expect(res.body.ui.siteName).toBeTypeOf('string');
  expect(res.body).toHaveProperty('lang');
  expect(res.body).toHaveProperty('translations');
  return res;
}

/** Everything `ui.enabled` adds: pages (plus the unknown-page fallback) and the other assets. */
const PAGES = ['/ui', '/ui/', '/ui/login', '/ui/register', '/ui/no-such-page'];
const OTHER_ASSETS = ['/ui/base.css', '/ui/admin.js', '/ui/admin.css', '/ui/login.html', '/ui/ui-i18n-keys.json'];

describe('auth.js and /ui/config without ui.enabled (default config)', () => {
  it('serves auth.js at /auth/ui/auth.js, byte for byte, with no ui key at all', async () => {
    const server = await viaRouter(undefined);
    await expectAuthJs(server, '/auth/ui/auth.js');
    const head = await request(server).head('/auth/ui/auth.js');
    expect(head.status).toBe(200);
  });

  it('serves a node-shaped /auth/ui/config that reports headless: false (the ui.headless option)', async () => {
    const server = await viaRouter(undefined);
    await expectConfig(server, '/auth', false);
  });

  it('answers 404 for every page and every other UI asset', async () => {
    const server = await viaRouter(undefined);
    for (const p of [...PAGES, ...OTHER_ASSETS]) await expectStatus(server, `/auth${p}`, 404);
  });

  it('behaves the same with an explicit ui: { enabled: false }', async () => {
    const server = await viaRouter({ enabled: false, siteName: 'Branded' });
    await expectAuthJs(server, '/auth/ui/auth.js');
    const res = await expectStatus(server, '/auth/ui/config', 200);
    expect(res.body.ui.siteName).toBe('Branded');
    expect(res.body.headless).toBe(false);
    for (const p of [...PAGES, ...OTHER_ASSETS]) await expectStatus(server, `/auth${p}`, 404);
  });

  it('ui: { headless: true } alone serves auth.js and /config, still no pages or other assets', async () => {
    const server = await viaRouter({ headless: true });
    await expectAuthJs(server, '/auth/ui/auth.js');
    await expectConfig(server, '/auth', true);
    for (const p of [...PAGES, ...OTHER_ASSETS]) await expectStatus(server, `/auth${p}`, 404);
  });

  it('createAuthRouter() mounted directly serves them too', async () => {
    const app = express();
    app.use('/auth', createAuthRouter(new InMemoryUserStore(), BASE));
    const server = await listen(app);
    await expectAuthJs(server, '/auth/ui/auth.js');
    await expectConfig(server, '/auth', false);
    await expectStatus(server, '/auth/ui/login', 404);
  });

  it('buildAllRouters() serves them at /auth by default', async () => {
    const server = await viaBuildAll(BASE);
    await expectAuthJs(server, '/auth/ui/auth.js');
    await expectConfig(server, '/auth', false);
    for (const p of [...PAGES, ...OTHER_ASSETS]) await expectStatus(server, `/auth${p}`, 404);
  });
});

describe('ui.enabled: pages and assets as before', () => {
  it('serves auth.js, /config, the pages and the other assets', async () => {
    const server = await viaRouter({ enabled: true });
    await expectAuthJs(server, '/auth/ui/auth.js');
    await expectConfig(server, '/auth', false);
    for (const p of PAGES) {
      const res = await expectStatus(server, `/auth${p}`, 200);
      expect(res.headers['content-type']).toMatch(/html/);
    }
    for (const p of OTHER_ASSETS) await expectStatus(server, `/auth${p}`, 200);
  });

  it('ui.enabled + ui.headless: auth.js and assets 200, pages 404 (unchanged)', async () => {
    const server = await viaRouter({ enabled: true, headless: true });
    await expectAuthJs(server, '/auth/ui/auth.js');
    await expectConfig(server, '/auth', true);
    for (const p of OTHER_ASSETS) await expectStatus(server, `/auth${p}`, 200);
    for (const p of ['/ui/login', '/ui/register', '/ui/no-such-page']) await expectStatus(server, `/auth${p}`, 404);
  });

  it('buildAllRouters() serves the full UI when enabled', async () => {
    const server = await viaBuildAll({ ...BASE, ui: { enabled: true } });
    await expectAuthJs(server, '/auth/ui/auth.js');
    await expectConfig(server, '/auth', false);
    await expectStatus(server, '/auth/ui/login', 200);
    await expectStatus(server, '/auth/ui/base.css', 200);
  });
});

describe('a custom prefix moves auth.js, /ui/config and the pages together', () => {
  it('app.use("/api/auth", auth.router()), UI off', async () => {
    const server = await viaRouter(undefined, '/api/auth');
    await expectAuthJs(server, '/api/auth/ui/auth.js');
    await expectConfig(server, '/api/auth', false);
    await expectStatus(server, '/api/auth/ui/login', 404);
    await expectStatus(server, '/auth/ui/auth.js', 404);
    await expectStatus(server, '/auth/ui/config', 404);
  });

  it('app.use("/api/auth", auth.router()), UI on', async () => {
    const server = await viaRouter({ enabled: true }, '/api/auth');
    await expectAuthJs(server, '/api/auth/ui/auth.js');
    await expectConfig(server, '/api/auth', false);
    await expectStatus(server, '/api/auth/ui/login', 200);
    await expectStatus(server, '/api/auth/ui/base.css', 200);
    await expectStatus(server, '/auth/ui/auth.js', 404);
    await expectStatus(server, '/auth/ui/login', 404);
  });

  it('buildAllRouters() with config.apiPrefix', async () => {
    const off = await viaBuildAll({ ...BASE, apiPrefix: '/api/auth' });
    await expectAuthJs(off, '/api/auth/ui/auth.js');
    await expectConfig(off, '/api/auth', false);
    await expectStatus(off, '/api/auth/ui/login', 404);
    await expectStatus(off, '/auth/ui/auth.js', 404);

    const on = await viaBuildAll({ ...BASE, apiPrefix: '/api/auth', ui: { enabled: true } });
    await expectAuthJs(on, '/api/auth/ui/auth.js');
    await expectConfig(on, '/api/auth', false);
    await expectStatus(on, '/api/auth/ui/login', 200);
    await expectStatus(on, '/auth/ui/login', 404);
  });

  it('buildAllRouters() with the configurator apiPrefix option', async () => {
    const server = await viaBuildAll(BASE, '/v1/auth');
    await expectAuthJs(server, '/v1/auth/ui/auth.js');
    await expectConfig(server, '/v1/auth', false);
    await expectStatus(server, '/auth/ui/auth.js', 404);
  });

  it('buildAllRouters() with RouterOptions.apiPrefix', async () => {
    const app = express();
    const auth = new AuthConfigurator({ ...BASE, ui: { enabled: true } }, new InMemoryUserStore());
    app.use(auth.buildAllRouters({ ...ADMIN, auth: { apiPrefix: '/id' } }));
    const server = await listen(app);
    await expectAuthJs(server, '/id/ui/auth.js');
    await expectConfig(server, '/id', false);
    await expectStatus(server, '/id/ui/login', 200);
    await expectStatus(server, '/auth/ui/auth.js', 404);
  });
});

describe('buildUiRouter() used directly', () => {
  it('still serves the full UI whatever ui.enabled says (clientOnly is opt-in)', async () => {
    const app = express();
    app.use('/auth/ui', buildUiRouter({ authConfig: BASE, apiPrefix: '/auth' }));
    const server = await listen(app);
    await expectAuthJs(server, '/auth/ui/auth.js');
    await expectConfig(server, '/auth', false);
    await expectStatus(server, '/auth/ui/login', 200);
    await expectStatus(server, '/auth/ui/base.css', 200);
  });

  it('clientOnly: true serves only auth.js and /config', async () => {
    const app = express();
    app.use('/auth/ui', buildUiRouter({ authConfig: { ...BASE, ui: { enabled: true } }, clientOnly: true }));
    const server = await listen(app);
    await expectAuthJs(server, '/auth/ui/auth.js');
    await expectConfig(server, '/auth', false);
    for (const p of [...PAGES, ...OTHER_ASSETS]) await expectStatus(server, `/auth${p}`, 404);
  });
});

describe('a host UI router mounted next to auth.router() (demo pattern, ui.enabled unset)', () => {
  const settingsStore = {
    async getSettings() { return { ui: { siteName: 'From settings' } }; },
    async updateSettings() { /* not used */ },
  };

  it('mounted after: auth.router() answers auth.js and /config, the host router still serves the pages', async () => {
    const app = express();
    app.use('/auth', new AuthConfigurator(BASE, new InMemoryUserStore()).router({ settingsStore }));
    app.use('/auth/ui', buildUiRouter({ authConfig: BASE, settingsStore, apiPrefix: '/auth' }));
    const server = await listen(app);
    await expectAuthJs(server, '/auth/ui/auth.js');
    const cfg = await expectConfig(server, '/auth', false);
    expect(cfg.body.ui.siteName).toBe('From settings');
    await expectStatus(server, '/auth/ui/login', 200);
    await expectStatus(server, '/auth/ui/base.css', 200);
  });

  it('mounted before: the host router answers everything, as before', async () => {
    const app = express();
    app.use('/auth/ui', buildUiRouter({ authConfig: BASE, settingsStore, apiPrefix: '/auth' }));
    app.use('/auth', new AuthConfigurator(BASE, new InMemoryUserStore()).router());
    const server = await listen(app);
    await expectAuthJs(server, '/auth/ui/auth.js');
    const cfg = await expectConfig(server, '/auth', false);
    expect(cfg.body.ui.siteName).toBe('From settings');
    await expectStatus(server, '/auth/ui/login', 200);
  });
});
