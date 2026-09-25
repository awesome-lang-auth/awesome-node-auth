import { Router, RequestHandler } from 'express';
import { AuthConfig } from './models/auth-config.model';
import { IUserStore } from './interfaces/user-store.interface';
import { TokenService } from './services/token.service';
import { PasswordService } from './services/password.service';
import { LocalStrategy } from './strategies/local/local.strategy';
import { GoogleStrategy } from './strategies/oauth/google.strategy';
import { GithubStrategy } from './strategies/oauth/github.strategy';
import { createAuthMiddleware } from './middleware/auth.middleware';
import { createAuthRouter, resolveApiPrefix, RouterOptions } from './router/auth.router';
import { ISessionStore } from './interfaces/session-store.interface';
import { createAdminRouter, AdminOptions } from './router/admin.router';
import { AuthEventBus } from './events/auth-event-bus';
import { AuthEventNames } from './events/auth-event-names';
import { IRolesPermissionsStore } from './interfaces/roles-permissions-store.interface';
import { BaseUser } from './models/user.model';

export interface AuthConfiguratorOptions {
  eventBus?: AuthEventBus;
}

export interface BuildAllRoutersOptions {
  auth?: RouterOptions;
  admin: Omit<AdminOptions, 'jwtSecret' | 'apiPrefix' | 'eventBus'> & {
    jwtSecret?: string;
    apiPrefix?: string;
    eventBus?: AuthEventBus;
  };
}

type WritableUserStore = IUserStore & {
  update?: (userId: string, patch: Partial<BaseUser>) => Promise<void>;
};

export class AuthConfigurator {
  private readonly _tokenService: TokenService;
  private readonly _passwordService: PasswordService;
  private _sessionStore?: ISessionStore;

  constructor(
    private readonly config: AuthConfig,
    private readonly userStore: IUserStore,
    private readonly options: AuthConfiguratorOptions = {},
  ) {
    this._tokenService = new TokenService();
    this._passwordService = new PasswordService();
  }

  middleware(options?: { sessionStore?: ISessionStore }): RequestHandler {
    return createAuthMiddleware(this.config, options?.sessionStore || this._sessionStore);
  }

  router(options?: RouterOptions): Router {
    if (options?.sessionStore) {
      this._sessionStore = options.sessionStore;
    }
    return createAuthRouter(this.userStore, this.config, {
      ...options,
      eventBus: options?.eventBus ?? this.options.eventBus,
    });
  }

  buildAllRouters(options: BuildAllRoutersOptions): Router {
    const composite = Router();
    const authOptions = options.auth;
    const authPrefix = resolveApiPrefix(this.config, authOptions);
    const normalizedPrefix = authPrefix.endsWith('/') ? authPrefix.slice(0, -1) : authPrefix;
    composite.use(
      `${normalizedPrefix}/admin`,
      createAdminRouter(this.userStore, {
        ...options.admin,
        apiPrefix: normalizedPrefix,
        jwtSecret: options.admin.jwtSecret ?? this.config.accessTokenSecret,
        eventBus: options.admin.eventBus ?? this.options.eventBus,
      }),
    );
    composite.use(normalizedPrefix, this.router(authOptions));
    return composite;
  }

  async promoteToAdmin(
    userId: string,
    options: { method?: 'flag' | 'role'; rbacStore?: IRolesPermissionsStore } = {},
  ): Promise<void> {
    const method = options.method ?? 'role';
    if (method === 'flag') {
      const writableUserStore = this.userStore as WritableUserStore;
      if (typeof writableUserStore.update !== 'function') {
        throw new Error('IUserStore.update is required for promoteToAdmin({ method: "flag" })');
      }
      await writableUserStore.update(userId, { isAdmin: true });
      this.options.eventBus?.publish(AuthEventNames.ROLE_ASSIGNED, {
        userId,
        data: { role: 'admin', method: 'flag' },
      });
      return;
    }

    if (!options.rbacStore) {
      throw new Error('rbacStore is required for promoteToAdmin({ method: "role" })');
    }
    await options.rbacStore.createRole('admin');
    await options.rbacStore.addRoleToUser(userId, 'admin');
    this.options.eventBus?.publish(AuthEventNames.ROLE_ASSIGNED, {
      userId,
      data: { role: 'admin', method: 'role' },
    });
  }

  async revokeAdmin(
    userId: string,
    options: { method?: 'flag' | 'role' | 'both'; rbacStore?: IRolesPermissionsStore } = {},
  ): Promise<void> {
    const method = options.method ?? 'role';
    if ((method === 'flag' || method === 'both')) {
      const writableUserStore = this.userStore as WritableUserStore;
      if (typeof writableUserStore.update !== 'function') {
        if (method === 'flag') {
          throw new Error('IUserStore.update is required for revokeAdmin({ method: "flag" })');
        }
      } else {
        await writableUserStore.update(userId, { isAdmin: false });
      }
    }

    if ((method === 'role' || method === 'both')) {
      if (!options.rbacStore) {
        throw new Error(`rbacStore is required for revokeAdmin({ method: "${method}" })`);
      }
      await options.rbacStore.removeRoleFromUser(userId, 'admin');
    }

    this.options.eventBus?.publish(AuthEventNames.ROLE_REVOKED, {
      userId,
      data: { role: 'admin', method },
    });
  }

  get tokenService(): TokenService {
    return this._tokenService;
  }

  get passwordService(): PasswordService {
    return this._passwordService;
  }

  strategy(name: 'local'): LocalStrategy;
  strategy(name: 'google'): GoogleStrategy;
  strategy(name: 'github'): GithubStrategy;
  strategy(name: string): LocalStrategy | GoogleStrategy | GithubStrategy {
    switch (name) {
      case 'local':
        return new LocalStrategy(this.userStore, this._passwordService);
      case 'google':
        throw new Error('GoogleStrategy is abstract - extend it and pass via RouterOptions');
      case 'github':
        throw new Error('GithubStrategy is abstract - extend it and pass via RouterOptions');
      default:
        throw new Error(`Unknown strategy: ${name}`);
    }
  }
}
