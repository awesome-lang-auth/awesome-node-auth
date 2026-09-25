export { AuthConfigurator } from './auth-configurator';
export type { AuthConfiguratorOptions, BuildAllRoutersOptions } from './auth-configurator';

// ---- Framework-agnostic HTTP types ------------------------------------------
export type { AuthRequest, AuthResponse, AuthNextFunction, AuthRequestHandler, AuthRouter } from './http-types';

// ---- Framework adapters -------------------------------------------------------
export { expressAdapter } from './adapters/express';
export { fastifyAdapter } from './adapters/fastify';

export type { IUserStore } from './interfaces/user-store.interface';
export type { ITokenStore } from './interfaces/token-store.interface';
export type { IAuthStrategy } from './interfaces/auth-strategy.interface';
export type { IUserMetadataStore } from './interfaces/user-metadata-store.interface';
export type { IRolesPermissionsStore, IRoleDocument, IRoleUserDocument } from './interfaces/roles-permissions-store.interface';
export type { ISessionStore } from './interfaces/session-store.interface';
export type { ITenantStore } from './interfaces/tenant-store.interface';
export type { ISettingsStore, AuthSettings } from './interfaces/settings-store.interface';
export type { ILinkedAccountsStore, LinkedAccount } from './interfaces/linked-accounts-store.interface';
export type { IPendingLinkStore, IPendingLink } from './interfaces/pending-link-store.interface';
export type { IApiKeyStore, ApiKeyAuditEntry } from './interfaces/api-key-store.interface';
export type { ITemplateStore, MailTemplate, UiTranslation } from './interfaces/template-store.interface';

export { MemoryTemplateStore } from './stores/memory-template.store';

export type { BaseUser } from './models/user.model';
export type { TokenPair, AccessTokenPayload } from './models/token.model';
export type { AuthConfig } from './models/auth-config.model';
export type { SessionInfo } from './models/session.model';
export type { Tenant } from './models/tenant.model';
export { AuthError } from './models/errors';
export type { ApiKey, ApiKeyContext } from './models/api-key.model';

export { BaseAuthStrategy } from './abstract/base-auth-strategy.abstract';
export { BaseOAuthStrategy } from './abstract/base-oauth-strategy.abstract';

export { LocalStrategy } from './strategies/local/local.strategy';
export { GoogleStrategy } from './strategies/oauth/google.strategy';
export { GithubStrategy } from './strategies/oauth/github.strategy';
export { GenericOAuthStrategy } from './strategies/oauth/generic-oauth.strategy';
export type { GenericOAuthProviderConfig } from './strategies/oauth/generic-oauth.strategy';
export { MagicLinkStrategy } from './strategies/magic-link/magic-link.strategy';
export { SmsStrategy } from './strategies/sms/sms.strategy';
export { TotpStrategy } from './strategies/two-factor/totp.strategy';
export { ApiKeyStrategy } from './strategies/api-key/api-key.strategy';
export type { ApiKeyStrategyOptions } from './strategies/api-key/api-key.strategy';

export { TokenService } from './services/token.service';
export { PasswordService } from './services/password.service';
export { SmsService } from './services/sms.service';
export { MailerService } from './services/mailer.service';
export { NotificationService } from './services/notification.service';
export type { EmailNotificationConfig, SmsNotificationConfig, SendEmailOptions, SendSmsOptions } from './services/notification.service';
export type { MailerConfig } from './models/auth-config.model';
export { ApiKeyService } from './services/api-key.service';
export type { CreateApiKeyOptions, CreatedApiKey } from './services/api-key.service';
export { JwksService } from './services/jwks.service';
export type { JWK, JwksDocument, JwksClientOptions } from './services/jwks.service';
export { JwksClient } from './services/jwks.service';
export type { IdProviderConfig, ResourceServerConfig } from './models/auth-config.model';

export { createAuthMiddleware } from './middleware/auth.middleware';
export { createApiKeyMiddleware } from './middleware/api-key.middleware';
export { createJwksAuthMiddleware } from './middleware/jwks-auth.middleware';
export { createAuthRouter, buildUiLink } from './router/auth.router';
export type { RouterOptions } from './router/auth.router';
export { createAdminRouter } from './router/admin.router';
export type { AdminOptions, AdminAccessPolicy, AuthorizedAdminUser } from './router/admin.router';
export { buildUiRouter } from './router/ui.router';
export type { UiRouterOptions } from './router/ui.router';

// ---- Event-driven tools system -------------------------------------------
export { AuthEventBus } from './events/auth-event-bus';
export type { AuthEventPayload } from './events/auth-event-bus';
export { AuthEventNames } from './events/auth-event-names';
export type { AuthEventName } from './events/auth-event-names';
export type { ITelemetryStore, TelemetryEvent, TelemetryFilter } from './interfaces/telemetry-store.interface';
export type { IWebhookStore, WebhookConfig, OutgoingWebhookEvent } from './interfaces/webhook-store.interface';
export { SseManager } from './tools/sse-manager';
export type { StreamEvent, SseManagerOptions } from './tools/sse-manager';
export type { ISseDistributor } from './interfaces/sse-distributor.interface';
export { WebhookSender } from './tools/webhook-sender';
export { AuthTools } from './tools/auth-tools';
export type { AuthToolsOptions, TrackOptions, NotifyOptions } from './tools/auth-tools';
export { ActionRegistry, webhookAction } from './tools/webhook-action';
export type { WebhookActionMeta, RegisteredAction } from './tools/webhook-action';
export { SseNotifyRegistry, sseNotify } from './tools/sse-notify.decorator';
export type { SseNotifyOptions } from './tools/sse-notify.decorator';
export { createToolsRouter } from './router/tools.router';
export type { ToolsRouterOptions } from './router/tools.router';
export { buildOpenApiSpec, buildSwaggerUiHtml, buildAuthOpenApiSpec, buildAdminOpenApiSpec } from './router/openapi';
export type { OpenApiDocument, AuthOpenApiOptions, AdminOpenApiOptions } from './router/openapi';
