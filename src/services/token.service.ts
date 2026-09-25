import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { Request, Response } from 'express';
import { AccessTokenPayload, TokenPair } from '../models/token.model';
import { AuthConfig } from '../models/auth-config.model';
import { AuthError } from '../models/errors';
import { JwksClient, JwksService } from './jwks.service';

let ephemeralWarningEmitted = false;

/**
 * Claim that marks a token signed with the access-token secret which is **not**
 * an application session token.  Session (access) tokens carry no `purpose`.
 * @internal
 */
export const TOKEN_PURPOSE_CLAIM = 'purpose';
/** `purpose` of the 2FA step-up token (`tempToken`) issued after a password. @internal */
export const TEMP_TOKEN_PURPOSE = '2fa';
/** `purpose` of the admin console token issued by `POST <admin>/login`. @internal */
export const ADMIN_TOKEN_PURPOSE = 'admin';

/** Lifetime of the 2FA step-up token. */
const TEMP_TOKEN_EXPIRES_IN = '5m';

function invalidAccessToken(): AuthError {
  return new AuthError('Invalid or expired access token', 'INVALID_ACCESS_TOKEN', 401);
}

/**
 * Lifetime of a signed JWT in milliseconds (`exp - iat`), or `undefined` when
 * the token has no usable `iat`/`exp`.  The tokens are signed with the
 * configured `accessTokenExpiresIn` / `refreshTokenExpiresIn`, parsed by
 * jsonwebtoken itself, so this is the configured lifetime in every format
 * jsonwebtoken accepts.
 */
function tokenLifetimeMs(token: string): number | undefined {
  const decoded = jwt.decode(token);
  if (decoded && typeof decoded === 'object'
    && typeof decoded.iat === 'number' && typeof decoded.exp === 'number'
    && decoded.exp > decoded.iat) {
    return (decoded.exp - decoded.iat) * 1000;
  }
  return undefined;
}

/** Cookie lifetimes used when a token carries no `iat`/`exp` (the 1.9.0 values). */
const DEFAULT_ACCESS_COOKIE_MAX_AGE_MS = 15 * 60 * 1000;
const DEFAULT_REFRESH_COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/** Reset ephemeral-warning flag. Exported for testing only. */
export function _resetEphemeralWarning(): void {
  ephemeralWarningEmitted = false;
}

export class TokenService {
  generateTokenPair(payload: AccessTokenPayload, config: AuthConfig): TokenPair {
    // Exclude jwt-managed fields; spread remaining claims (including any custom ones).
    // `purpose` is reserved for tokens that are not sessions (the 2FA step-up
    // token, the admin console token): drop it, so a custom claim from
    // `buildTokenPayload` can never mark a session token as one of them.
    const { iat, exp, [TOKEN_PURPOSE_CLAIM]: _purpose, ...claims } = payload;
    const accessToken = jwt.sign(
      claims,
      config.accessTokenSecret,
      { expiresIn: config.accessTokenExpiresIn ?? '15m' } as jwt.SignOptions
    );
    const refreshToken = jwt.sign(
      claims,
      config.refreshTokenSecret,
      { expiresIn: config.refreshTokenExpiresIn ?? '7d' } as jwt.SignOptions
    );
    return { accessToken, refreshToken };
  }

  /**
   * Generate an RS256-signed token pair for IdP mode.
   *
   * IdP mode activates when `config.idProvider.privateKey` is present **or**
   * `config.idProvider.enabled === true`. A keypair is auto-generated at the
   * first call if no `privateKey` is configured (for dev; emits a warning).
   */
  generateIdProviderTokenPair(payload: AccessTokenPayload, config: AuthConfig): TokenPair {
    const idp = config.idProvider;
    const isActive = !!idp?.privateKey || idp?.enabled === true;
    if (!isActive) {
      throw new AuthError('IdP mode is not enabled', 'IDP_NOT_ENABLED', 500);
    }

    let privateKeyPem = idp!.privateKey;
    let publicKeyPem = idp!.publicKey;

    if (!privateKeyPem) {
      if (!ephemeralWarningEmitted) {
        console.warn(
          '[awesome-node-auth] IdP mode: no privateKey configured — ' +
          'auto-generating an ephemeral RSA keypair. ' +
          'All tokens will be invalidated on restart. ' +
          'Set idProvider.privateKey in production.'
        );
        ephemeralWarningEmitted = true;
      }
      // Auto-generate ephemeral keypair (dev only)
      const kp = JwksService.generateKeypair();
      privateKeyPem = kp.privateKey;
      publicKeyPem = kp.publicKey;
      // Persist into the config object so subsequent calls reuse the same keypair
      idp!.privateKey = privateKeyPem;
      idp!.publicKey = publicKeyPem;
    } else if (!publicKeyPem) {
      publicKeyPem = JwksService.derivePublicKey(privateKeyPem);
      idp!.publicKey = publicKeyPem;
    }

    // `iat`, `exp` and `kid` are managed by jsonwebtoken (header claim, not payload)
    const { iat, exp, kid: _kid, ...claims } = payload;
    const idpClaims = {
      ...claims,
      ...(idp!.issuer ? { iss: idp!.issuer } : {}),
    };
    const keyId = 'provisioner-key-1';

    const expiresIn = (idp.tokenExpiry ?? '30d') as jwt.SignOptions['expiresIn'];
    const accessToken = jwt.sign(idpClaims, privateKeyPem, {
      algorithm: 'RS256',
      expiresIn,
      keyid: keyId,
    } as jwt.SignOptions);

    // Refresh token also RS256-signed, with a longer expiry.
    // Priority: idProvider.refreshTokenExpiry → config.refreshTokenExpiresIn → '90d'
    const refreshToken = jwt.sign(idpClaims, privateKeyPem, {
      algorithm: 'RS256',
      expiresIn: (idp.refreshTokenExpiry ?? config.refreshTokenExpiresIn ?? '90d') as jwt.SignOptions['expiresIn'],
      keyid: keyId,
    } as jwt.SignOptions);

    return { accessToken, refreshToken };
  }

  /**
   * Verify a JWT against a remote JWKS endpoint.
   * The `kid` header claim is used to select the correct public key.
   */
  async verifyWithJwks(token: string, jwksClient: JwksClient, expectedIssuer?: string): Promise<AccessTokenPayload> {
    try {
      // Decode without verifying to extract `kid`
      const decoded = jwt.decode(token, { complete: true });
      if (!decoded || typeof decoded === 'string') {
        throw new AuthError('Invalid token format', 'INVALID_TOKEN', 401);
      }

      const kid = (decoded.header as { kid?: string }).kid;
      if (!kid) {
        throw new AuthError('Token missing kid header', 'INVALID_TOKEN', 401);
      }

      const jwk = await jwksClient.getKey(kid);
      if (!jwk) {
        // Key not found — try once more after cache invalidation (supports key rotation)
        jwksClient.invalidateCache();
        const retried = await jwksClient.getKey(kid);
        if (!retried) {
          throw new AuthError('Unknown signing key', 'INVALID_TOKEN', 401);
        }
        const publicKey = JwksService.jwkToPublicKey(retried);
        return this._verifyRsaToken(token, publicKey, expectedIssuer);
      }

      const publicKey = JwksService.jwkToPublicKey(jwk);
      return this._verifyRsaToken(token, publicKey, expectedIssuer);
    } catch (err) {
      if (err instanceof AuthError) throw err;
      throw new AuthError('Invalid or expired token', 'INVALID_TOKEN', 401);
    }
  }

  private _verifyRsaToken(token: string, publicKeyPem: string, expectedIssuer?: string): AccessTokenPayload {
    const payload = jwt.verify(token, publicKeyPem, { algorithms: ['RS256'] }) as AccessTokenPayload;
    if (expectedIssuer && payload.iss !== expectedIssuer) {
      throw new AuthError('Token issuer mismatch', 'INVALID_TOKEN', 401);
    }
    return payload;
  }

  /**
   * Sign the short-lived 2FA step-up token (`tempToken`) handed out after a
   * correct password when a second factor is required.  It carries
   * `purpose: '2fa'`, set after the payload claims so a custom claim cannot
   * remove it: `verifyAccessToken` refuses it, and only `verifyTempToken`
   * (the 2FA completion endpoints) accepts it.
   */
  generateTempToken(payload: AccessTokenPayload, config: AuthConfig): string {
    const { iat, exp, ...claims } = payload;
    return jwt.sign(
      { ...claims, [TOKEN_PURPOSE_CLAIM]: TEMP_TOKEN_PURPOSE },
      config.accessTokenSecret,
      { expiresIn: TEMP_TOKEN_EXPIRES_IN } as jwt.SignOptions,
    );
  }

  /**
   * Verify a 2FA step-up token.  Only a token minted by `generateTempToken`
   * passes: an application access token is refused.  Throws the same
   * `INVALID_ACCESS_TOKEN` error as `verifyAccessToken`.
   */
  verifyTempToken(token: string, config: AuthConfig): AccessTokenPayload {
    let payload: AccessTokenPayload;
    try {
      payload = jwt.verify(token, config.accessTokenSecret) as AccessTokenPayload;
    } catch {
      throw invalidAccessToken();
    }
    if (payload?.[TOKEN_PURPOSE_CLAIM] !== TEMP_TOKEN_PURPOSE) throw invalidAccessToken();
    return payload;
  }

  /**
   * Verify an application session (access) token.  A token signed with the
   * same secret for another purpose is refused: the 2FA step-up token, and
   * the admin console token (when the admin `jwtSecret` is the access-token
   * secret, as `buildAllRouters()` sets it by default).
   */
  verifyAccessToken(token: string, config: AuthConfig): AccessTokenPayload {
    let payload: AccessTokenPayload;
    try {
      payload = jwt.verify(token, config.accessTokenSecret) as AccessTokenPayload;
    } catch {
      throw invalidAccessToken();
    }
    const purpose = payload?.[TOKEN_PURPOSE_CLAIM];
    if (purpose === TEMP_TOKEN_PURPOSE || purpose === ADMIN_TOKEN_PURPOSE) throw invalidAccessToken();
    return payload;
  }

  verifyRefreshToken(token: string, config: AuthConfig): AccessTokenPayload {
    try {
      const payload = jwt.verify(token, config.refreshTokenSecret) as AccessTokenPayload;
      return payload;
    } catch {
      throw new AuthError('Invalid or expired refresh token', 'INVALID_REFRESH_TOKEN', 401);
    }
  }

  private getCookieName(name: string, config: AuthConfig): string {
    if (!config.cookieOptions?.secure) return name;

    // __Host- needs Secure, Path=/, and NO Domain.
    // We use it if path is '/' (default) and domain is not set.
    const isPathRoot = !config.cookieOptions?.path || config.cookieOptions.path === '/';
    if (isPathRoot && !config.cookieOptions?.domain) {
      return `__Host-${name}`;
    }

    return `__Secure-${name}`;
  }

  setTokenCookies(res: Response, tokens: TokenPair, config: AuthConfig): void {
    const commonOpts = {
      httpOnly: true,
      secure: config.cookieOptions?.secure ?? false,
      sameSite: (config.cookieOptions?.sameSite ?? 'lax') as 'strict' | 'lax' | 'none',
      path: config.cookieOptions?.path ?? '/',
    };

    const setCookie = (name: string, value: string, extraOpts: any = {}) => {
      const finalName = this.getCookieName(name, config);
      const opts = { ...commonOpts, ...extraOpts };
      if (finalName.startsWith('__Host-')) {
        delete opts.domain;
        opts.path = '/'; // __Host- requires path=/
        opts.secure = true; // __Host- requires Secure
      } else {
        opts.domain = config.cookieOptions?.domain;
      }
      res.cookie(finalName, value, opts);
    };

    // Each cookie lives as long as the token it carries, i.e. the configured
    // accessTokenExpiresIn / refreshTokenExpiresIn.
    setCookie('accessToken', tokens.accessToken, {
      maxAge: tokenLifetimeMs(tokens.accessToken) ?? DEFAULT_ACCESS_COOKIE_MAX_AGE_MS,
    });

    const refreshPath = config.cookieOptions?.refreshTokenPath
      ?? (config.apiPrefix ? `${config.apiPrefix}/refresh` : '/auth/refresh');
    setCookie('refreshToken', tokens.refreshToken, {
      maxAge: tokenLifetimeMs(tokens.refreshToken) ?? DEFAULT_REFRESH_COOKIE_MAX_AGE_MS,
      path: refreshPath
    });

    if (config.csrf?.enabled) {
      setCookie('csrf-token', this.generateSecureToken(16), {
        httpOnly: false,
        maxAge: 15 * 60 * 1000
      });
    }
  }

  initCsrfToken(res: Response, config: AuthConfig): void {
    if (!config.csrf?.enabled) return;
    const name = this.getCookieName('csrf-token', config);
    const opts: any = {
      httpOnly: false,
      secure: config.cookieOptions?.secure ?? false,
      sameSite: (config.cookieOptions?.sameSite ?? 'lax') as 'strict' | 'lax' | 'none',
      path: config.cookieOptions?.path ?? '/',
      maxAge: 15 * 60 * 1000,
    };
    if (name.startsWith('__Host-')) {
      delete opts.domain;
      opts.path = '/'; // __Host- requires path=/
      opts.secure = true; // __Host- requires Secure
    } else {
      opts.domain = config.cookieOptions?.domain;
    }
    res.cookie(name, this.generateSecureToken(16), opts);
  }

  clearTokenCookies(res: Response, config?: AuthConfig): void {
    const commonOpts: any = {
      secure: config?.cookieOptions?.secure ?? false,
      sameSite: (config?.cookieOptions?.sameSite ?? 'lax') as 'strict' | 'lax' | 'none',
      path: config?.cookieOptions?.path ?? '/',
    };

    const clearCookie = (name: string, extraOpts: any = {}) => {
      // For maximum robustness, we try to clear the primary name AND prefixed variants.
      // Cookies are only cleared if BOTH name, path, and domain match exactly.
      const primaryName = this.getCookieName(name, config || {} as AuthConfig);
      const possibleNames = new Set([primaryName, `__Host-${name}`, `__Secure-${name}`, name]);

      for (const finalName of possibleNames) {
        const opts = { ...commonOpts, ...extraOpts };
        if (finalName.startsWith('__Host-')) {
          delete opts.domain;
          opts.path = '/'; // __Host- requires path=/
          opts.secure = true;
        } else {
          opts.domain = config?.cookieOptions?.domain;
        }
        res.clearCookie(finalName, opts);
      }
    };

    clearCookie('accessToken');

    // Mirror the path logic from setTokenCookies so the cookie is found and deleted.
    const refreshPath = config?.cookieOptions?.refreshTokenPath
      ?? (config?.apiPrefix ? `${config?.apiPrefix}/refresh` : '/auth/refresh');
    clearCookie('refreshToken', { path: refreshPath });

    if (config?.csrf?.enabled) {
      clearCookie('csrf-token');
    }
  }

  generateSecureToken(bytes: number = 32): string {
    return crypto.randomBytes(bytes).toString('hex');
  }

  extractTokenFromCookie(req: Request, cookieName: string): string | null {
    // List of possible prefixed names in order of preference
    const possibleNames = [
      `__Host-${cookieName}`,
      `__Secure-${cookieName}`,
      cookieName
    ];

    for (const name of possibleNames) {
      // First try cookie-parser parsed cookies
      if (req.cookies && req.cookies[name]) {
        return req.cookies[name] as string;
      }
    }

    // Fallback: parse raw Cookie header
    const cookieHeader = req.headers?.cookie;
    if (!cookieHeader) return null;
    const cookies = cookieHeader.split(';').reduce<Record<string, string>>((acc, part) => {
      const [key, ...val] = part.trim().split('=');
      if (key) acc[key.trim()] = decodeURIComponent(val.join('='));
      return acc;
    }, {});

    for (const name of possibleNames) {
      if (cookies[name]) return cookies[name];
    }
    return null;
  }
}
