/**
 * NestJS + awesome-node-auth fullstack demo
 * ----------------------------------
 * Demonstrates a complete NestJS application using awesome-node-auth with:
 *   - AuthModule (forRoot pattern) with in-memory user store
 *   - JwtAuthGuard wrapping the awesome-node-auth middleware
 *   - @CurrentUser() parameter decorator
 *   - AuthController delegating to awesome-node-auth's Express router
 *   - Admin panel at GET /admin  (first user auto-granted access)
 *   - Static HTML frontend at GET /
 *
 * Run:
 *   npm install
 *   npm start
 *
 * Then open http://localhost:3000
 */

import 'reflect-metadata';
import * as path from 'path';
import { Request, Response, NextFunction } from 'express';

import {
  Module,
  Global,
  DynamicModule,
  Provider,
  CanActivate,
  ExecutionContext,
  Injectable,
  Inject,
  createParamDecorator,
  Controller,
  All,
  Req,
  Res,
  Next,
  Get,
  UseGuards,
} from '@nestjs/common';

import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';

import {
  AuthConfigurator,
  AuthConfig,
  IUserStore,
  PasswordService,
  AuthError,
  createAdminRouter,
  MemoryTemplateStore,
} from '@awesome-lang-auth/node';

import { InMemoryUserStore } from './user-store';

// ── Shared instances ──────────────────────────────────────────────────────────

const userStore = new InMemoryUserStore();
const passwordService = new PasswordService();

// Template store — enables the 📧 Email & UI Templates tab in the admin panel.
const templateStore = new MemoryTemplateStore();

const authConfig: AuthConfig = {
  accessTokenSecret:  process.env['ACCESS_TOKEN_SECRET']  ?? 'demo-access-secret-change-in-production',
  refreshTokenSecret: process.env['REFRESH_TOKEN_SECRET'] ?? 'demo-refresh-secret-change-in-production',
  accessTokenExpiresIn:  '15m',
  refreshTokenExpiresIn: '7d',
  cookieOptions: {
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  },
  templateStore,  // enables email template overrides via MailerService
};

// ── 1. AuthModule ─────────────────────────────────────────────────────────────

const AUTH_CONFIGURATOR = 'AUTH_CONFIGURATOR';

interface NodeAuthModuleOptions {
  config: AuthConfig;
  userStore: IUserStore;
}

@Global()
@Module({})
class AuthModule {
  static forRoot(options: NodeAuthModuleOptions): DynamicModule {
    const configuratorProvider: Provider = {
      provide: AUTH_CONFIGURATOR,
      useFactory: () => new AuthConfigurator(options.config, options.userStore),
    };
    return {
      module: AuthModule,
      providers: [configuratorProvider],
      exports: [AUTH_CONFIGURATOR],
    };
  }
}

// ── 2. JwtAuthGuard ───────────────────────────────────────────────────────────

@Injectable()
class JwtAuthGuard implements CanActivate {
  constructor(@Inject(AUTH_CONFIGURATOR) private readonly auth: AuthConfigurator) {}

  canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();
    return new Promise<boolean>((resolve, reject) => {
      const middleware = this.auth.middleware();
      // NestJS req/res are compatible with Express but have slightly different
      // TypeScript types; `as any` is the standard bridging pattern.
      middleware(req as any, res as any, (err?: any) => {
        if (err) return reject(err);
        resolve(true);
      });
    });
  }
}

// ── 3. @CurrentUser() decorator ───────────────────────────────────────────────

const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    return ctx.switchToHttp().getRequest<Request & { user?: any }>().user;
  },
);

// ── 4. AuthController ─────────────────────────────────────────────────────────

@Controller('auth')
class AuthController {
  private readonly router: ReturnType<AuthConfigurator['router']>;

  constructor(@Inject(AUTH_CONFIGURATOR) auth: AuthConfigurator) {
    // Build the router with registration support
    this.router = auth.router({
      onRegister: async (data: any) => {
        const email    = typeof data.email    === 'string' ? data.email.trim()    : '';
        const password = typeof data.password === 'string' ? data.password.trim() : '';
        if (!email || !password) throw new AuthError('email and password are required', 'VALIDATION_ERROR', 400);
        const existing = await userStore.findByEmail(email);
        if (existing) throw new AuthError('Email already registered', 'EMAIL_EXISTS', 409);
        const hash = await passwordService.hash(password);
        return userStore.create({ email, password: hash, role: 'user' });
      },
    });
  }

  @All('*')
  handle(@Req() req: Request, @Res() res: Response, @Next() next: NextFunction): void {
    req.url = req.url.replace(/^\/auth/, '') || '/';
    // The awesome-node-auth router is Express-compatible; NestJS uses the same underlying
    // request/response objects so `as any` safely bridges the type gap.
    this.router(req as any, res as any, next);
  }
}

// ── 5. ProfileController (protected route example) ───────────────────────────

@Controller('api')
class ProfileController {
  @Get('profile')
  @UseGuards(JwtAuthGuard)
  getProfile(@CurrentUser() user: any) {
    return user;
  }
}

// ── 6. AppModule ──────────────────────────────────────────────────────────────

@Module({
  imports: [
    AuthModule.forRoot({ config: authConfig, userStore }),
  ],
  providers: [JwtAuthGuard],
  controllers: [AuthController, ProfileController],
})
class AppModule {}

// ── 7. Bootstrap ─────────────────────────────────────────────────────────────

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { logger: ['error', 'warn'] });

  // Cookie parser (required for HttpOnly JWT cookies)
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  app.use(require('cookie-parser')());

  // CORS — allow the preview iframe / StackBlitz origin
  app.enableCors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  });

  // Admin panel (HTML UI + REST API) at /admin
  const adminRouter = createAdminRouter(userStore, {
    jwtSecret: process.env['ACCESS_TOKEN_SECRET'] ?? 'dev-secret',
    accessPolicy: 'first-user',
    templateStore,  // enables 📧 Email & UI Templates tab (live editor + preview)
  });
  app.use('/admin', adminRouter as any);

  // Serve static demo frontend
  app.useStaticAssets(path.join(__dirname, '..', 'public'));

  const port = Number(process.env['PORT']) || 3000;
  await app.listen(port);

  console.log(`\n  🔐  awesome-node-auth NestJS demo\n`);
  console.log(`  http://localhost:${port}         → demo frontend`);
  console.log(`  http://localhost:${port}/admin   → admin panel (auto-granted to first registered user)\n`);
}

bootstrap();
