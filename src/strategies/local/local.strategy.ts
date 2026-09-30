import { BaseAuthStrategy } from '../../abstract/base-auth-strategy.abstract';
import { AuthConfig } from '../../models/auth-config.model';
import { BaseUser } from '../../models/user.model';
import { IUserStore } from '../../interfaces/user-store.interface';
import { PasswordService } from '../../services/password.service';
import { AuthError } from '../../models/errors';

export class LocalStrategy extends BaseAuthStrategy<{ email: string; password: string }, BaseUser> {
  name = 'local';

  constructor(
    private readonly userStore: IUserStore,
    private readonly passwordService: PasswordService,
  ) {
    super();
  }

  async authenticate(input: { email: string; password: string }, config: AuthConfig): Promise<BaseUser> {
    const user = await this.userStore.findByEmail(input.email);
    if (!user) {
      throw new AuthError('Invalid credentials', 'INVALID_CREDENTIALS', 401);
    }
    if (!user.password) {
      throw new AuthError('Invalid credentials', 'INVALID_CREDENTIALS', 401);
    }
    const valid = await this.passwordService.compare(input.password, user.password);
    if (!valid) {
      throw new AuthError('Invalid credentials', 'INVALID_CREDENTIALS', 401);
    }

    assertEmailVerificationAllowsLogin(user, config);

    return user;
  }
}

/**
 * Effective email-verification mode: `emailVerificationMode` takes
 * precedence; fall back to the legacy `requireEmailVerification` boolean.
 */
export function effectiveEmailVerificationMode(config: AuthConfig): 'none' | 'lazy' | 'strict' {
  return config.emailVerificationMode ??
    (config.requireEmailVerification ? 'strict' : 'none');
}

/**
 * The login's email-verification gate.  Throws the 403 `AuthError` the login
 * answers when the policy blocks this (unverified) account; returns when the
 * account may log in.  `POST /register` uses it too, so that
 * `issueSessionOnRegister` never bypasses the gate.
 */
export function assertEmailVerificationAllowsLogin(user: BaseUser, config: AuthConfig): void {
  const verificationMode = effectiveEmailVerificationMode(config);

  if (!user.isEmailVerified) {
    if (verificationMode === 'strict') {
      throw new AuthError('Email address is not verified', 'EMAIL_NOT_VERIFIED', 403);
    } else if (verificationMode === 'lazy') {
      // Block only after the grace-period deadline has passed.
      if (user.emailVerificationDeadline && new Date() > user.emailVerificationDeadline) {
        throw new AuthError('Email verification required', 'EMAIL_VERIFICATION_REQUIRED', 403);
      }
    }
    // 'none' → fall through, allow login
  }
}
