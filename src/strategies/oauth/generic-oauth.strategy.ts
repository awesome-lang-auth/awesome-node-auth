import { BaseOAuthStrategy } from '../../abstract/base-oauth-strategy.abstract';
import { BaseUser } from '../../models/user.model';
import { AuthError } from '../../models/errors';

/**
 * Configuration for a generic OAuth 2.0 provider.
 *
 * Use this to implement OAuth login for any provider that follows the
 * standard OAuth 2.0 Authorization Code flow with a JSON user-info endpoint.
 *
 * @example
 * ```typescript
 * import { GenericOAuthStrategy, GenericOAuthProviderConfig } from '@awesome-lang-auth/node';
 *
 * const microsoftConfig: GenericOAuthProviderConfig = {
 *   name: 'microsoft',
 *   clientId: process.env.MS_CLIENT_ID!,
 *   clientSecret: process.env.MS_CLIENT_SECRET!,
 *   callbackUrl: 'https://yourapp.com/auth/oauth/microsoft/callback',
 *   authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
 *   tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
 *   userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
 *   scope: 'openid email profile',
 *   mapProfile: (data) => ({
 *     id: data.id,
 *     email: data.mail ?? data.userPrincipalName,
 *     name: data.displayName,
 *   }),
 * };
 *
 * class MicrosoftStrategy extends GenericOAuthStrategy {
 *   async findOrCreateUser(profile) {
 *     return userStore.findOrCreate({ provider: 'microsoft', ...profile });
 *   }
 * }
 * const msStrategy = new MicrosoftStrategy(microsoftConfig);
 * ```
 */
export interface GenericOAuthProviderConfig {
  /** Provider identifier, e.g. `'microsoft'`, `'facebook'`, `'discord'`. */
  name: string;
  /** OAuth application client ID. */
  clientId: string;
  /** OAuth application client secret. */
  clientSecret: string;
  /** Full URL where the provider redirects back after authorization. */
  callbackUrl: string;
  /** Provider's OAuth authorization endpoint URL. */
  authorizationUrl: string;
  /** Provider's token exchange endpoint URL. */
  tokenUrl: string;
  /** Provider's user-info (profile) endpoint URL. */
  userInfoUrl: string;
  /**
   * Space-separated scope string (e.g. `'openid email profile'`) or an
   * array of scope strings (joined with a space).
   */
  scope: string | string[];
  /**
   * Optional additional query parameters to append to the authorization URL.
   * Useful for provider-specific parameters such as `access_type`, `prompt`, etc.
   */
  additionalAuthParams?: Record<string, string>;
  /**
   * Map the raw JSON profile returned by `userInfoUrl` to the normalized
   * profile shape expected by `findOrCreateUser`.
   *
   * When omitted, the library assumes the profile already contains `id` and
   * `email` fields at the top level.
   */
  mapProfile?: (raw: Record<string, unknown>) => {
    id: string;
    email: string;
    emailVerified?: boolean;
    name?: string;
    picture?: string;
  };
}

/**
 * Generic OAuth 2.0 strategy.
 *
 * Extend this class to add OAuth login support for any provider that
 * follows the standard Authorization Code flow with a JSON user-info
 * endpoint.  Only `findOrCreateUser` needs to be implemented.
 *
 * @example
 * ```typescript
 * class MicrosoftStrategy extends GenericOAuthStrategy<MyUser> {
 *   async findOrCreateUser(profile) {
 *     let user = await userStore.findByProviderAccount('microsoft', profile.id);
 *     if (!user) user = await userStore.create({ email: profile.email, loginProvider: 'microsoft' });
 *     return user as MyUser;
 *   }
 * }
 * ```
 */
export abstract class GenericOAuthStrategy<TUser extends BaseUser = BaseUser> extends BaseOAuthStrategy<TUser> {
  readonly name: string;

  private readonly config: GenericOAuthProviderConfig;

  constructor(config: GenericOAuthProviderConfig) {
    super();
    this.name = config.name;
    this.config = config;
  }

  getAuthorizationUrl(state?: string): string {
    const scope = Array.isArray(this.config.scope)
      ? this.config.scope.join(' ')
      : this.config.scope;
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.callbackUrl,
      response_type: 'code',
      scope,
      ...this.config.additionalAuthParams,
      ...(state ? { state } : {}),
    });
    return `${this.config.authorizationUrl}?${params.toString()}`;
  }

  protected async exchangeCodeForTokens(code: string): Promise<{ accessToken: string; idToken?: string }> {
    const res = await fetch(this.config.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({
        code,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
        redirect_uri: this.config.callbackUrl,
        grant_type: 'authorization_code',
      }).toString(),
    });
    if (!res.ok) {
      throw new AuthError(`${this.name} token exchange failed`, 'OAUTH_TOKEN_EXCHANGE_FAILED', 401);
    }
    const data = await res.json() as { access_token: string; id_token?: string };
    return { accessToken: data.access_token, idToken: data.id_token };
  }

  protected async getUserProfile(accessToken: string): Promise<{ id: string; email: string; emailVerified?: boolean; name?: string; picture?: string }> {
    const res = await fetch(this.config.userInfoUrl, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new AuthError(`Failed to get ${this.name} user profile`, 'OAUTH_PROFILE_FAILED', 401);
    }
    const raw = await res.json() as Record<string, unknown>;
    if (this.config.mapProfile) {
      return this.config.mapProfile(raw);
    }
    return {
      id: String(raw['id'] ?? raw['sub'] ?? ''),
      email: String(raw['email'] ?? ''),
      emailVerified: raw['email_verified'] as boolean | undefined,
      name: raw['name'] as string | undefined,
      picture: raw['picture'] as string | undefined,
    };
  }

  async handleCallback(code: string, state?: string): Promise<TUser> {
    const { accessToken } = await this.exchangeCodeForTokens(code);
    const profile = await this.getUserProfile(accessToken);
    return this.findOrCreateUser(profile, state);
  }

  abstract findOrCreateUser(
    profile: { id: string; email: string; emailVerified?: boolean; name?: string; picture?: string },
    state?: string,
  ): Promise<TUser>;
}
