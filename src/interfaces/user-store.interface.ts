import { BaseUser } from '../models/user.model';

export interface IUserStore<U extends BaseUser = BaseUser> {
  findByEmail(email: string): Promise<U | null>;
  findById(id: string): Promise<U | null>;
  create(data: Partial<U>): Promise<U>;
  updateRefreshToken(userId: string, token: string | null, expiry: Date | null): Promise<void>;
  updateLastLogin(userId: string): Promise<void>;
  updateResetToken(userId: string, token: string | null, expiry: Date | null): Promise<void>;
  updatePassword(userId: string, hashedPassword: string): Promise<void>;
  updateTotpSecret(userId: string, secret: string | null): Promise<void>;
  updateMagicLinkToken(userId: string, token: string | null, expiry: Date | null): Promise<void>;
  updateSmsCode(userId: string, code: string | null, expiry: Date | null): Promise<void>;

  /**
   * Find a user by their password-reset token.
   * Required to support the POST /auth/reset-password endpoint.
   */
  findByResetToken?(token: string): Promise<U | null>;

  /**
   * Find a user by their magic-link token.
   * Required to support the POST /auth/magic-link/verify endpoint.
   */
  findByMagicLinkToken?(token: string): Promise<U | null>;

  // ---- Email Verification -----------------------------------------------

  /**
   * Set (or clear) the email-verification token and its expiry.
   * Required to support POST /auth/send-verification-email and GET /auth/verify-email.
   */
  updateEmailVerificationToken?(
    userId: string,
    token: string | null,
    expiry: Date | null,
  ): Promise<void>;

  /**
   * Mark the user's primary email as verified (or unverified).
   * Required to support GET /auth/verify-email.
   */
  updateEmailVerified?(userId: string, isVerified: boolean): Promise<void>;

  /**
   * Find a user by their email-verification token.
   * Required to support GET /auth/verify-email.
   */
  findByEmailVerificationToken?(token: string): Promise<U | null>;

  // ---- Change Email -------------------------------------------------------

  /**
   * Store the pending new email address together with a confirmation token
   * and expiry.  Set all three to `null` to cancel an in-progress change.
   * Required to support POST /auth/change-email/request and
   * POST /auth/change-email/confirm.
   */
  updateEmailChangeToken?(
    userId: string,
    pendingEmail: string | null,
    token: string | null,
    expiry: Date | null,
  ): Promise<void>;

  /**
   * Commit the pending email change: overwrite the user's primary email with
   * `newEmail` and clear the change-token fields.
   * Required to support POST /auth/change-email/confirm.
   */
  updateEmail?(userId: string, newEmail: string): Promise<void>;

  /**
   * Find a user by their email-change confirmation token.
   * Required to support POST /auth/change-email/confirm.
   */
  findByEmailChangeToken?(token: string): Promise<U | null>;

  // ---- Account Linking ----------------------------------------------------

  /**
   * Store the pending link details (target email, provider, token, expiry)
   * for an in-progress account-link flow.
   * Set all four mutable args to `null` to cancel an in-progress link request.
   * Required to support POST /auth/link-request and POST /auth/link-verify.
   */
  updateAccountLinkToken?(
    userId: string,
    pendingEmail: string | null,
    pendingProvider: string | null,
    token: string | null,
    expiry: Date | null,
  ): Promise<void>;

  /**
   * Find the user who initiated a link request by their pending link token.
   * Required to support POST /auth/link-verify.
   */
  findByAccountLinkToken?(token: string): Promise<U | null>;

  /**
   * Set or clear the "2FA required" flag for a single user.
   * Required to support `POST /admin/api/2fa-policy` (batch 2FA enforcement).
   */
  updateRequire2FA?(userId: string, required: boolean): Promise<void>;

  /**
   * Look up a user by their OAuth provider name and provider-specific user ID.
   *
   * Use this in your `findOrCreateUser` implementation instead of (or in
   * addition to) `findByEmail` to avoid account-takeover attacks: two
   * different OAuth providers can have the same email address without
   * representing the same person.
   *
   * @param provider        The provider name, e.g. `'google'` or `'github'`.
   * @param providerAccountId  The unique user ID returned by the provider
   *                           (stored in `BaseUser.providerAccountId`).
   */
  findByProviderAccount?(provider: string, providerAccountId: string): Promise<U | null>;

  // ---- Admin / listing ---------------------------------------------------

  /**
   * Return a paginated list of users.
   * Used by the optional admin router to display the users table.
   *
   * @param limit  Maximum number of records to return.
   * @param offset Zero-based offset for pagination.
   */
  listUsers?(limit: number, offset: number): Promise<U[]>;

  /**
   * Update the user's profile information (first name, last name).
   * Required to support the PATCH /auth/profile endpoint.
   */
  updateProfile?(userId: string, data: { firstName?: string | null; lastName?: string | null }): Promise<void>;

  /**
   * Update the user's phone number.
   * Required to support the POST /auth/add-phone endpoint.
   */
  updatePhoneNumber?(userId: string, phoneNumber: string | null): Promise<void>;

  /**
   * Apply a partial update to the user record.
   * Optional helper used by admin bootstrap utilities such as promote/revoke.
   */
  update?(userId: string, patch: Partial<U>): Promise<void>;
}
