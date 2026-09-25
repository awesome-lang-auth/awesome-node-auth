/**
 * Shared in-memory user store for the Next.js demo.
 * Swap this for a real database store in production.
 */

import type { IUserStore, ILinkedAccountsStore, ISettingsStore, LinkedAccount, AuthSettings } from '@awesome-lang-auth/node';

export interface DemoUser {
  id: string;
  email: string;
  password?: string;
  role?: string;
  refreshToken?: string | null;
  refreshTokenExpiry?: Date | null;
  resetToken?: string | null;
  resetTokenExpiry?: Date | null;
  totpSecret?: string | null;
  isTotpEnabled?: boolean;
  magicLinkToken?: string | null;
  magicLinkTokenExpiry?: Date | null;
  smsCode?: string | null;
  smsCodeExpiry?: Date | null;
  emailVerificationToken?: string | null;
  emailVerificationTokenExpiry?: Date | null;
  isEmailVerified?: boolean;
  pendingEmail?: string | null;
  emailChangeToken?: string | null;
  emailChangeTokenExpiry?: Date | null;
  accountLinkPendingEmail?: string | null;
  accountLinkPendingProvider?: string | null;
  accountLinkToken?: string | null;
  accountLinkTokenExpiry?: Date | null;
  loginProvider?: string;
  providerAccountId?: string;
  require2FA?: boolean;
  lastLogin?: Date;
}

export class InMemoryUserStore implements IUserStore {
  private _users = new Map<string, DemoUser>();
  private _nextId = 1;

  async findByEmail(email: string) {
    return [...this._users.values()].find(u => u.email === email) ?? null;
  }

  async findById(id: string) {
    return this._users.get(id) ?? null;
  }

  async create(data: Partial<DemoUser>) {
    const id = String(this._nextId++);
    const user: DemoUser = { id, email: '', ...data };
    this._users.set(id, user);
    return user;
  }

  async updateRefreshToken(userId: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u.refreshToken = token; u.refreshTokenExpiry = expiry; }
  }

  async updateLastLogin(userId: string) {
    const u = this._users.get(userId);
    if (u) u.lastLogin = new Date();
  }

  async updateResetToken(userId: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u.resetToken = token; u.resetTokenExpiry = expiry; }
  }

  async updatePassword(userId: string, hashedPassword: string) {
    const u = this._users.get(userId);
    if (u) u.password = hashedPassword;
  }

  async updateTotpSecret(userId: string, secret: string | null) {
    const u = this._users.get(userId);
    if (u) { u.totpSecret = secret; u.isTotpEnabled = secret !== null; }
  }

  async updateMagicLinkToken(userId: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u.magicLinkToken = token; u.magicLinkTokenExpiry = expiry; }
  }

  async updateSmsCode(userId: string, code: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u.smsCode = code; u.smsCodeExpiry = expiry; }
  }

  async findByResetToken(token: string) {
    return [...this._users.values()].find(u => u.resetToken === token) ?? null;
  }

  async findByMagicLinkToken(token: string) {
    return [...this._users.values()].find(u => u.magicLinkToken === token) ?? null;
  }

  async updateEmailVerificationToken(userId: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u.emailVerificationToken = token; u.emailVerificationTokenExpiry = expiry; }
  }

  async updateEmailVerified(userId: string, isVerified: boolean) {
    const u = this._users.get(userId);
    if (u) u.isEmailVerified = isVerified;
  }

  async findByEmailVerificationToken(token: string) {
    return [...this._users.values()].find(u => u.emailVerificationToken === token) ?? null;
  }

  async updateEmailChangeToken(userId: string, pendingEmail: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) { u.pendingEmail = pendingEmail; u.emailChangeToken = token; u.emailChangeTokenExpiry = expiry; }
  }

  async updateEmail(userId: string, newEmail: string) {
    const u = this._users.get(userId);
    if (u) { u.email = newEmail; u.pendingEmail = null; u.emailChangeToken = null; u.emailChangeTokenExpiry = null; }
  }

  async findByEmailChangeToken(token: string) {
    return [...this._users.values()].find(u => u.emailChangeToken === token) ?? null;
  }

  async updateAccountLinkToken(userId: string, pendingEmail: string, pendingProvider: string, token: string | null, expiry: Date | null) {
    const u = this._users.get(userId);
    if (u) {
      u.accountLinkPendingEmail = pendingEmail;
      u.accountLinkPendingProvider = pendingProvider;
      u.accountLinkToken = token;
      u.accountLinkTokenExpiry = expiry;
    }
  }

  async findByAccountLinkToken(token: string) {
    return [...this._users.values()].find(u => u.accountLinkToken === token) ?? null;
  }

  async findByProviderAccount(provider: string, providerAccountId: string) {
    return [...this._users.values()].find(
      u => u.loginProvider === provider && u.providerAccountId === providerAccountId,
    ) ?? null;
  }

  async updateRequire2FA(userId: string, required: boolean) {
    const u = this._users.get(userId);
    if (u) u.require2FA = required;
  }

  async listUsers(limit: number, offset: number) {
    return [...this._users.values()].slice(offset, offset + limit);
  }

  async deleteUser(userId: string) {
    this._users.delete(userId);
  }
}

export class InMemoryLinkedAccountsStore implements ILinkedAccountsStore {
  private _links = new Map<string, LinkedAccount[]>();

  async getLinkedAccounts(userId: string): Promise<LinkedAccount[]> {
    return this._links.get(userId) ?? [];
  }

  async linkAccount(userId: string, account: LinkedAccount): Promise<void> {
    const existing = this._links.get(userId) ?? [];
    const idx = existing.findIndex(
      a => a.provider === account.provider && a.providerAccountId === account.providerAccountId,
    );
    if (idx >= 0) { existing[idx] = account; } else { existing.push(account); }
    this._links.set(userId, existing);
  }

  async unlinkAccount(userId: string, provider: string, providerAccountId: string): Promise<void> {
    const existing = this._links.get(userId) ?? [];
    this._links.set(
      userId,
      existing.filter(a => !(a.provider === provider && a.providerAccountId === providerAccountId)),
    );
  }

  async findUserByProviderAccount(provider: string, providerAccountId: string): Promise<{ userId: string } | null> {
    for (const [userId, accounts] of this._links.entries()) {
      if (accounts.some(a => a.provider === provider && a.providerAccountId === providerAccountId)) {
        return { userId };
      }
    }
    return null;
  }
}

export class InMemorySettingsStore implements ISettingsStore {
  private _settings: AuthSettings = {};

  async getSettings(): Promise<AuthSettings> { return { ...this._settings }; }
  async updateSettings(updates: Partial<AuthSettings>): Promise<void> { this._settings = { ...this._settings, ...updates }; }
}
