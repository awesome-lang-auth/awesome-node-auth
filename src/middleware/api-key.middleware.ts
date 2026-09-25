import { Request, Response, NextFunction, RequestHandler } from 'express';
import { ApiKeyStrategy, ApiKeyStrategyOptions } from '../strategies/api-key/api-key.strategy';
import { IApiKeyStore } from '../interfaces/api-key-store.interface';
import { ApiKeyContext } from '../models/api-key.model';
import { AuthError } from '../models/errors';

declare global {
  namespace Express {
    interface Request {
      /** Populated by `createApiKeyMiddleware` after successful API key authentication. */
      apiKey?: ApiKeyContext;
    }
  }
}

/**
 * Create an Express middleware that authenticates incoming requests using an
 * API Key / Service Token.
 *
 * The middleware accepts the key via:
 *  - `Authorization: ApiKey <key>` header
 *  - `X-Api-Key: <key>` header
 *
 * On success, the validated `ApiKeyContext` is attached to `req.apiKey` and
 * `next()` is called.  On failure a `401` or `403` JSON error is returned.
 *
 * @param store    Implementation of `IApiKeyStore` for persistence.
 * @param options  Optional validation rules (scopes, IP allowlist, audit log).
 *
 * @example
 * ```ts
 * import { createApiKeyMiddleware } from '@awesome-lang-auth/node';
 *
 * app.use('/tools', createApiKeyMiddleware(myApiKeyStore, { requiredScopes: ['tools:read'] }));
 * ```
 */
export function createApiKeyMiddleware(
  store: IApiKeyStore,
  options: ApiKeyStrategyOptions = {},
): RequestHandler {
  const strategy = new ApiKeyStrategy(store, options);

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const context = await strategy.authenticate(req.headers as Record<string, string | string[] | undefined>, req.ip);
      req.apiKey = context;
      next();
    } catch (err) {
      if (err instanceof AuthError) {
        res.status(err.statusCode).json({ error: err.message, code: err.code });
      } else {
        res.status(500).json({ error: 'Internal server error' });
      }
    }
  };
}
