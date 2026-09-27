/**
 * NestJS Integration Example
 * --------------------------
 * Demonstrates how to integrate awesome-node-auth inside a NestJS application.
 *
 * Installation (in your NestJS project):
 *   npm install @awesome-lang-auth/node
 *
 * NOTE: This file is intentionally NOT compiled by tsconfig.json (it lives in
 * examples/, which is excluded). Treat it as reference documentation.
 *
 * Copy the relevant pieces into your own NestJS project and adapt them to
 * your module structure and user-store implementation.
 *
 * Overview
 * --------
 *  1. AuthModule     – wraps AuthConfigurator, exports it as a provider.
 *  2. JwtAuthGuard   – NestJS Guard that calls auth.middleware() under the hood.
 *  3. CurrentUser    – parameter decorator that extracts req.user.
 *  4. AuthController – thin controller that delegates to auth.router().
 *  5. AppModule      – root module wiring everything together.
 *  6. main.ts        – bootstrap function.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

// ---------------------------------------------------------------------------
// 0. Peer dependencies (already available in a NestJS project)
// ---------------------------------------------------------------------------
//
//   npm install @nestjs/common @nestjs/core @nestjs/platform-express reflect-metadata rxjs
//

// ---------------------------------------------------------------------------
// 1. auth.module.ts
// ---------------------------------------------------------------------------

import {
  Module,
  Global,
  DynamicModule,
  Provider,
  CanActivate,
  ExecutionContext,
  Injectable,
  createParamDecorator,
  Controller,
  All,
  Req,
  Res,
  Next,
  NestFactory,
} from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { AuthConfigurator, AuthConfig, IUserStore, createAuthRouter, createAdminRouter, MemoryTemplateStore } from '../src/index';
import type { AuthRequest } from '../src/http-types';

// ---- Token / constants ----------------------------------------------------

const AUTH_CONFIGURATOR = 'AUTH_CONFIGURATOR' as const;
const AUTH_CONFIG       = 'AUTH_CONFIG'       as const;
const USER_STORE        = 'USER_STORE'        as const;

// ---- Module options -------------------------------------------------------

interface NodeAuthModuleOptions {
  config: AuthConfig;
  userStore: IUserStore;
}

// ---------------------------------------------------------------------------

@Global()
@Module({})
export class AuthModule {
  /**
   * Register awesome-node-auth at the root level.
   *
   * Usage (AppModule):
   *   AuthModule.forRoot({
   *     config: authConfig,
   *     userStore: new MyUserStore(),
   *   })
   */
  static forRoot(options: NodeAuthModuleOptions): DynamicModule {
    const configuratorProvider: Provider = {
      provide: AUTH_CONFIGURATOR,
      useFactory: () => new AuthConfigurator(options.config, options.userStore),
    };

    return {
      module: AuthModule,
      providers: [
        { provide: AUTH_CONFIG, useValue: options.config },
        { provide: USER_STORE,  useValue: options.userStore },
        configuratorProvider,
      ],
      exports: [AUTH_CONFIGURATOR, AUTH_CONFIG, USER_STORE],
    };
  }
}

// ---------------------------------------------------------------------------
// 2. jwt-auth.guard.ts
// ---------------------------------------------------------------------------

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly auth: AuthConfigurator,
  ) {}

  canActivate(context: ExecutionContext): Promise<boolean> {
    // AuthRequest is the framework-neutral type — no need to import from 'express' here.
    const req  = context.switchToHttp().getRequest<AuthRequest>();
    const res  = context.switchToHttp().getResponse<Response>();

    return new Promise<boolean>((resolve, reject) => {
      const middleware = this.auth.middleware();
      middleware(req, res, (err?: any) => {
        if (err) return reject(err);
        resolve(true);
      });
    });
  }
}

// ---------------------------------------------------------------------------
// 3. current-user.decorator.ts
// ---------------------------------------------------------------------------

/**
 * Parameter decorator that extracts the authenticated user from the request.
 *
 * Usage:
 *   @Get('profile')
 *   @UseGuards(JwtAuthGuard)
 *   getProfile(@CurrentUser() user: BaseUser) { return user; }
 */
export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    // AuthRequest already includes the `user` field populated by awesome-node-auth.
    const request = ctx.switchToHttp().getRequest<AuthRequest>();
    return request.user;
  },
);

// ---------------------------------------------------------------------------
// 4. auth.controller.ts
// ---------------------------------------------------------------------------
//
// The simplest integration is to delegate ALL /auth/* traffic to the
// express router provided by awesome-node-auth. This avoids duplicating every
// endpoint definition in NestJS while still benefiting from NestJS DI.
//

@Controller('auth')
export class AuthController {
  private readonly router: ReturnType<AuthConfigurator['router']>;

  constructor(auth: AuthConfigurator) {
    // Build the express router once and cache it
    this.router = auth.router();
  }

  /**
   * Forward every request under /auth/** to the awesome-node-auth express router.
   * NestJS will match any HTTP method and any sub-path.
   */
  @All('*')
  handle(@Req() req: Request, @Res() res: Response, @Next() next: NextFunction): void {
    // Strip the /auth prefix so the inner router sees paths starting from /
    req.url = req.url.replace(/^\/auth/, '') || '/';
    this.router(req, res, next);
  }
}

// ---------------------------------------------------------------------------
// 5. app.module.ts
// ---------------------------------------------------------------------------

// Replace InMemoryUserStore with your real IUserStore implementation
import { InMemoryUserStore, InMemoryLinkedAccountsStore, InMemorySettingsStore } from './in-memory-user-store';

const authConfig: AuthConfig = {
  accessTokenSecret:  process.env.ACCESS_TOKEN_SECRET  ?? 'change-me-access',
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET ?? 'change-me-refresh',
  accessTokenExpiresIn:  '15m',
  refreshTokenExpiresIn: '7d',
  email: {
    siteUrl: process.env.SITE_URL ?? 'http://localhost:3000',
    // Uncomment to enable magic links, link-request, etc.:
    // sendVerificationEmail: async (email, token, link) => mailer.send({ to: email, … }),
  },
};

const _userStore = new InMemoryUserStore();
const _linkedAccountsStore = new InMemoryLinkedAccountsStore();
const _settingsStore = new InMemorySettingsStore();
// Template store — enables the 📧 Email & UI Templates tab in the admin panel.
// Swap MemoryTemplateStore for a DB-backed implementation in production.
const _templateStore = new MemoryTemplateStore();

@Module({
  imports: [
    AuthModule.forRoot({
      config:    authConfig,
      userStore: _userStore,
    }),
  ],
  controllers: [AuthController],
})
export class AppModule {}

// ---------------------------------------------------------------------------
// 5b. Admin controller (optional — exposes /admin)
// ---------------------------------------------------------------------------
//
// @Controller('admin')
// export class AdminController {
//   private readonly adminRouter: ReturnType<typeof createAdminRouter>;
//
//   constructor() {
//     this.adminRouter = createAdminRouter(_userStore, {
//       accessPolicy: 'first-user',
//       jwtSecret: process.env.ACCESS_TOKEN_SECRET ?? 'change-me-access-secret',
//       linkedAccountsStore: _linkedAccountsStore,
//       settingsStore: _settingsStore,
//       templateStore: _templateStore,  // enables 📧 Email & UI Templates tab
//     });
//   }
//
//   @All('*')
//   handle(@Req() req: Request, @Res() res: Response, @Next() next: NextFunction): void {
//     req.url = req.url.replace(/^\/admin/, '') || '/';
//     this.adminRouter(req, res, next);
//   }
// }
//
// Remember to also configure the auth router with the linked-accounts store
// so that POST /auth/link-request and POST /auth/link-verify are available:
//
// auth.router({ linkedAccountsStore: _linkedAccountsStore, settingsStore: _settingsStore })
//   → but since AuthModule builds the router internally you can extend it:
//
// @Module({
//   imports: [AuthModule.forRoot({ config: authConfig, userStore: _userStore })],
//   controllers: [AuthController, AdminController],
// })
// export class AppModule {}
//
// Or bypass AuthConfigurator and use createAuthRouter directly in a dedicated
// controller (same pattern as AuthController above, using createAuthRouter).
//

// ---------------------------------------------------------------------------
// 6. main.ts
// ---------------------------------------------------------------------------

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  app.enableCors();
  await app.listen(3000);
  console.log('NestJS + awesome-node-auth running on http://localhost:3000');
}

bootstrap();

// ---------------------------------------------------------------------------
// 7. Protecting individual routes with JwtAuthGuard
// ---------------------------------------------------------------------------
//
// import { UseGuards, Get } from '@nestjs/common';
//
// @Controller('profile')
// export class ProfileController {
//   @Get()
//   @UseGuards(JwtAuthGuard)
//   getProfile(@CurrentUser() user: BaseUser) {
//     return user;
//   }
// }
//
// ---------------------------------------------------------------------------
// 8. Dependency injection in services
// ---------------------------------------------------------------------------
//
// If you need direct access to awesome-node-auth internals (e.g. TokenService) in
// your own NestJS services, inject AUTH_CONFIGURATOR:
//
// @Injectable()
// export class TokenIssuerService {
//   constructor(
//     @Inject(AUTH_CONFIGURATOR) private readonly auth: AuthConfigurator,
//   ) {}
//
//   issueTokens(user: BaseUser) {
//     return this.auth.tokenService.generateTokenPair(
//       { sub: user.id, email: user.email },
//       authConfig,
//     );
//   }
// }

// ---------------------------------------------------------------------------
// 9. Account linking (frontend / client notes)
// ---------------------------------------------------------------------------
//
// POST /auth/link-request   Authorization: Bearer <accessToken>
//   Body: { email: "secondary@example.com", provider: "email" }
//   → sends a verification email (requires sendVerificationEmail in authConfig.email)
//
// POST /auth/link-verify    (public)
//   Body: { token: "<token-from-email>" }
//   → completes the link; the address now appears in GET /auth/linked-accounts
//
// GET    /auth/linked-accounts               (Authorization: Bearer <token>)
// DELETE /auth/linked-accounts/email/secondary@example.com
//
// NOTE: link-request and link-verify are only mounted when linkedAccountsStore
// is provided AND IUserStore implements updateAccountLinkToken /
// findByAccountLinkToken.  InMemoryUserStore already includes both.
