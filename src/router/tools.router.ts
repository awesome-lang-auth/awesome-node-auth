import { Router, Request, Response, RequestHandler } from 'express';
import vm from 'node:vm';
import { AuthTools } from '../tools/auth-tools';
import { ITelemetryStore } from '../interfaces/telemetry-store.interface';
import { IWebhookStore } from '../interfaces/webhook-store.interface';
import { AuthSettings, ISettingsStore } from '../interfaces/settings-store.interface';
import { ActionRegistry } from '../tools/webhook-action';
import { buildOpenApiSpec, buildSwaggerUiHtml } from './openapi';

/**
 * Options for the optional tools router.
 */
export interface ToolsRouterOptions {
  /**
   * Enable the `POST /tools/track/:eventName` endpoint.
   * @default true
   */
  telemetry?: boolean;

  /**
   * Enable the `POST /tools/notify/:target` endpoint.
   * @default true
   */
  notify?: boolean;

  /**
   * Enable the `GET /tools/stream` SSE endpoint.
   * Only useful when `AuthTools` was created with `sse: true`.
   * @default true
   */
  stream?: boolean;

  /**
   * Enable the `POST /tools/webhook/:provider` inbound webhook endpoint.
   * @default true
   */
  webhook?: boolean;

  /**
   * Optional middleware applied to all routes that write/read telemetry data.
   * Use this to restrict access to authenticated/admin requests.
   */
  authMiddleware?: RequestHandler;

  /**
   * Optional telemetry store — when provided, a `GET /tools/telemetry`
   * query endpoint is exposed.
   */
  telemetryStore?: ITelemetryStore;

  /**
   * Called for every inbound webhook received at
   * `POST /tools/webhook/:provider`.
   *
   * The handler receives the raw request and must map the inbound payload
   * to an internal event name and data object.  When it returns `null` the
   * webhook is silently accepted but not forwarded to the event bus.
   *
   * When `webhookStore` is also provided and the matching `WebhookConfig`
   * has a `jsScript`, the script is executed first via the `vm` sandbox.
   * `onWebhook` acts as a fallback when no dynamic script is configured.
   */
  onWebhook?: (
    provider: string,
    body: unknown,
    req: Request,
  ) => Promise<{ event: string; data?: unknown; userId?: string; tenantId?: string } | null>;

  /**
   * Optional webhook store.  When provided together with `webhook: true`,
   * the tools router will look up the matching `WebhookConfig` (via
   * `findByProvider`) for each inbound webhook request and execute its
   * `jsScript` inside a `vm` sandbox (if present).
   */
  webhookStore?: IWebhookStore;

  /**
   * Optional settings store.  Used to read `enabledWebhookActions` when
   * executing dynamic inbound webhook scripts in the `vm` sandbox.
   */
  settingsStore?: ISettingsStore;

  /**
   * Enable Swagger UI (`GET /tools/docs`) and the raw OpenAPI spec
   * (`GET /tools/openapi.json`).
   *
   * - `true`  — always enable
   * - `false` — always disable
   * - `'auto'` (default) — enable when `NODE_ENV` is **not** `'production'`
   *
   * @default 'auto'
   */
  swagger?: boolean | 'auto';

  /**
   * Base path where the tools router is mounted.
   * Used to build accurate path entries in the OpenAPI spec.
   *
   * @default '/tools'
   */
  swaggerBasePath?: string;
}

/**
 * Mount the optional `/tools` HTTP router.
 *
 * All endpoints are opt-in.  The router only mounts routes whose feature flag
 * is enabled (`telemetry`, `notify`, `stream`, `webhook`).
 *
 * @example
 * ```ts
 * import { createToolsRouter } from '@awesome-lang-auth/node';
 *
 * app.use('/tools', createToolsRouter(tools, { authMiddleware: auth.middleware() }));
 * ```
 */
export function createToolsRouter(tools: AuthTools, options: ToolsRouterOptions = {}): Router {
  const router = Router();

  const {
    telemetry = true,
    notify = true,
    stream = true,
    webhook = true,
    authMiddleware,
    swagger = 'auto',
    swaggerBasePath = '/tools',
  } = options;

  // Resolve swagger flag: 'auto' means enabled outside production
  const swaggerEnabled =
    swagger === true ||
    (swagger === 'auto' && process.env['NODE_ENV'] !== 'production');

  const protect: RequestHandler[] = authMiddleware ? [authMiddleware] : [];

  // -------------------------------------------------------------------------
  // POST /tools/track/:eventName
  // -------------------------------------------------------------------------
  if (telemetry) {
    router.post('/track/:eventName', ...protect, async (req: Request, res: Response) => {
      const eventName = req.params['eventName'] as string;
      const { data, userId, tenantId, sessionId, correlationId } = req.body as Record<string, unknown>;
      const ip = req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() ?? req.socket.remoteAddress;
      const userAgent = req.headers['user-agent'];
      const reqUser = (req as Request & { user?: { id?: string; sub?: string } }).user;
      const resolvedUserId = (userId as string | undefined) ?? reqUser?.id ?? reqUser?.sub;

      await tools.track(eventName, data, {
        userId: resolvedUserId,
        tenantId: tenantId as string | undefined,
        sessionId: sessionId as string | undefined,
        correlationId: correlationId as string | undefined,
        ip,
        userAgent,
      });

      res.status(202).json({ ok: true });
    });
  }

  // -------------------------------------------------------------------------
  // POST /tools/notify/:target
  // -------------------------------------------------------------------------
  if (notify) {
    router.post('/notify/:target', ...protect, (req: Request, res: Response) => {
      const target = req.params['target'] as string;
      const { data, type, tenantId, userId, metadata } = req.body as Record<string, unknown>;

      tools.notify(target, data, {
        type: type as string | undefined,
        tenantId: tenantId as string | undefined,
        userId: userId as string | undefined,
        metadata: metadata as Record<string, unknown> | undefined,
      });

      res.status(202).json({ ok: true });
    });
  }

  // -------------------------------------------------------------------------
  // GET /tools/stream  — SSE
  // -------------------------------------------------------------------------
  if (stream) {
    const extractSseToken: RequestHandler = (req, _res, next) => {
      if (req.query['token'] && typeof req.query['token'] === 'string') {
        req.headers['authorization'] = `Bearer ${req.query['token']}`;
      }
      next();
    };

    router.get('/stream', extractSseToken, ...protect, (req: Request, res: Response) => {
      if (!tools.sseManager) {
        res.status(503).json({ error: 'SSE not enabled' });
        return;
      }

      // Determine authorised topics based on authenticated user context
      const user = (req as Request & { user?: { id?: string; sub?: string; tenantId?: string } }).user;
      const userId = user?.id ?? user?.sub;
      const tenantId = user?.tenantId;

      const requestedTopics = typeof req.query.topics === 'string'
        ? req.query.topics.split(',').map((t) => t.trim()).filter(Boolean)
        : [];

      // Build server-authorised topic list — clients cannot self-declare
      const authorisedTopics = ['global'];
      if (tenantId) authorisedTopics.push(`tenant:${tenantId}`);
      if (userId) authorisedTopics.push(`user:${userId}`);

      // Allow explicitly requested topics only if they are a subset of the
      // authorised ones (prevents unauthorised channel subscription).
      const finalTopics = requestedTopics.length > 0
        ? requestedTopics.filter((t) => authorisedTopics.includes(t))
        : authorisedTopics;

      tools.sseManager.connect(res, finalTopics, { userId, tenantId });
      // Response is kept alive; no further action needed here.
    });
  }

  // -------------------------------------------------------------------------
  // GET /tools/telemetry  — query persisted events
  // -------------------------------------------------------------------------
  if (telemetry && options.telemetryStore?.query) {
    router.get('/telemetry', ...protect, async (req: Request, res: Response) => {
      const store = options.telemetryStore!;
      if (!store.query) {
        res.status(501).json({ error: 'Telemetry query not supported by the configured store' });
        return;
      }
      const { event, userId, tenantId, from, to, limit, offset } = req.query as Record<string, string | undefined>;
      const results = await store.query({
        event,
        userId,
        tenantId,
        from: from ? new Date(from) : undefined,
        to: to ? new Date(to) : undefined,
        limit: limit ? parseInt(limit, 10) : undefined,
        offset: offset ? parseInt(offset, 10) : undefined,
      });
      res.json({ data: results });
    });
  }

  // -------------------------------------------------------------------------
  // POST /tools/webhook/:provider  — inbound webhooks
  // -------------------------------------------------------------------------
  if (webhook && (options.onWebhook || options.webhookStore?.findByProvider)) {
    router.post('/webhook/:provider', async (req: Request, res: Response) => {
      const provider = req.params['provider'] as string;
      try {
        let result: { event: string; data?: unknown; userId?: string; tenantId?: string } | null = null;

        // --- Dynamic vm sandbox (when webhookStore.findByProvider is available) ---
        if (options.webhookStore?.findByProvider) {
          const config = await options.webhookStore.findByProvider(provider);
          if (config?.jsScript) {
            // Resolve the intersection of globally-enabled and per-webhook-allowed actions
            const settings: AuthSettings = options.settingsStore
              ? await options.settingsStore.getSettings().catch(() => ({}))
              : {};
            const enabledIds: string[] = settings.enabledWebhookActions ?? [];
            const allowedIds: string[] = config.allowedActions ?? [];
            const actions = ActionRegistry.buildContext(enabledIds, allowedIds);

            // Wrap in async IIFE to support await inside the script
            const wrappedScript = `(async () => { ${config.jsScript} })()`;
            // Provide a console that emits to stderr in development only,
            // prefixed with provider context for easier debugging.
            const isDev = process.env['NODE_ENV'] !== 'production';
            const sandboxConsole = isDev
              ? {
                log: (...args: unknown[]) => process.stderr.write(`[webhook:${provider}] ${args.join(' ')}\n`),
                warn: (...args: unknown[]) => process.stderr.write(`[webhook:${provider}] WARN ${args.join(' ')}\n`),
                error: (...args: unknown[]) => process.stderr.write(`[webhook:${provider}] ERR  ${args.join(' ')}\n`),
              }
              : { log: () => { }, warn: () => { }, error: () => { } };

            const sandbox = vm.createContext({
              body: req.body,
              actions,
              result: null,
              console: sandboxConsole,
            });

            try {
              const returnValue = vm.runInContext(wrappedScript, sandbox, { timeout: 5_000 });
              if (returnValue instanceof Promise) {
                // Attach .catch() *synchronously* before any await to prevent
                // Node.js from emitting an unhandledRejection event.
                let scriptErr: unknown;
                await returnValue.catch((e: unknown) => { scriptErr = e; });
                if (scriptErr) {
                  console.error('[tools-router] vm script error for provider', provider, scriptErr);
                }
              }
            } catch (scriptErr) {
              // Synchronous errors from the vm script (e.g. timeout, syntax)
              console.error('[tools-router] vm script error for provider', provider, scriptErr);
            }

            if (sandbox['result'] && typeof (sandbox['result'] as Record<string, unknown>)['event'] === 'string') {
              result = sandbox['result'] as { event: string; data?: unknown; userId?: string; tenantId?: string };
            }
          }
        }

        // --- Legacy / manual onWebhook callback (fallback) ---
        if (result === null && options.onWebhook) {
          result = await options.onWebhook(provider, req.body, req);
        }

        if (result) {
          await tools.track(result.event, result.data, {
            userId: result.userId,
            tenantId: result.tenantId,
          });
        }
        res.status(200).json({ ok: true });
      } catch {
        res.status(400).json({ error: 'Webhook processing failed' });
      }
    });
  }

  // -------------------------------------------------------------------------
  // GET /tools/openapi.json  — OpenAPI 3.0 spec (swagger enabled only)
  // GET /tools/docs          — Swagger UI HTML (swagger enabled only)
  // -------------------------------------------------------------------------
  if (swaggerEnabled) {
    router.get('/openapi.json', (_req: Request, res: Response) => {
      const spec = buildOpenApiSpec(
        {
          telemetry,
          notify,
          stream,
          webhook,
          telemetryStore: options.telemetryStore,
        },
        swaggerBasePath,
      );
      res.setHeader('Content-Type', 'application/json');
      res.json(spec);
    });

    router.get('/docs', (_req: Request, res: Response) => {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(buildSwaggerUiHtml(`${swaggerBasePath}/openapi.json`));
    });
  }

  return router;
}
