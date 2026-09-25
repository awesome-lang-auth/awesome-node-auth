// ============================================================
// MongoDB IUserStore — @awesome-lang-auth/node@^1.10.1
// Uses the official mongodb Node.js driver.
// Install: npm install mongodb
// ============================================================

import type { IUserStore, BaseUser } from '@awesome-lang-auth/node';

// ---- Document shape -------------------------------------------------------

interface DbUserDoc {
  _id: string;
  email: string;
  password?: string | null;
  role?: string | null;
  firstName?: string | null;
  lastName?: string | null;
  loginProvider?: string | null;
  providerAccountId?: string | null;
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
  phoneNumber?: string | null;
  require2FA?: boolean;
  isEmailVerified?: boolean;
  emailVerificationToken?: string | null;
  emailVerificationTokenExpiry?: Date | null;
  emailVerificationDeadline?: Date | null;
  pendingEmail?: string | null;
  emailChangeToken?: string | null;
  emailChangeTokenExpiry?: Date | null;
  accountLinkPendingEmail?: string | null;
  accountLinkPendingProvider?: string | null;
  accountLinkToken?: string | null;
  accountLinkTokenExpiry?: Date | null;
  lastLogin?: Date | null;
  createdAt?: Date;
  updatedAt?: Date;
}

// ---- Mapper ---------------------------------------------------------------

function toBaseUser(doc: DbUserDoc): BaseUser {
  return {
    id:                           doc._id,
    email:                        doc.email,
    password:                     doc.password    ?? undefined,
    role:                         doc.role        ?? undefined,
    firstName:                    doc.firstName   ?? null,
    lastName:                     doc.lastName    ?? null,
    loginProvider:                doc.loginProvider    ?? null,
    providerAccountId:            doc.providerAccountId ?? null,
    refreshToken:                 doc.refreshToken ?? null,
    refreshTokenExpiry:           doc.refreshTokenExpiry ?? null,
    resetToken:                   doc.resetToken   ?? null,
    resetTokenExpiry:             doc.resetTokenExpiry ?? null,
    totpSecret:                   doc.totpSecret  ?? null,
    isTotpEnabled:                doc.isTotpEnabled ?? false,
    magicLinkToken:               doc.magicLinkToken ?? null,
    magicLinkTokenExpiry:         doc.magicLinkTokenExpiry ?? null,
    smsCode:                      doc.smsCode     ?? null,
    smsCodeExpiry:                doc.smsCodeExpiry ?? null,
    phoneNumber:                  doc.phoneNumber ?? null,
    require2FA:                   doc.require2FA  ?? false,
    isEmailVerified:              doc.isEmailVerified ?? false,
    emailVerificationToken:       doc.emailVerificationToken ?? null,
    emailVerificationTokenExpiry: doc.emailVerificationTokenExpiry ?? null,
    emailVerificationDeadline:    doc.emailVerificationDeadline ?? null,
    pendingEmail:                 doc.pendingEmail ?? null,
    emailChangeToken:             doc.emailChangeToken ?? null,
    emailChangeTokenExpiry:       doc.emailChangeTokenExpiry ?? null,
    accountLinkPendingEmail:      doc.accountLinkPendingEmail ?? null,
    accountLinkPendingProvider:   doc.accountLinkPendingProvider ?? null,
    accountLinkToken:             doc.accountLinkToken ?? null,
    accountLinkTokenExpiry:       doc.accountLinkTokenExpiry ?? null,
    lastLogin:                    doc.lastLogin ?? null,
  };
}

// ---- Store ----------------------------------------------------------------

export class MongoDbUserStore implements IUserStore {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private col: any; // mongodb.Collection<DbUserDoc>

  constructor(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    private readonly db: any, // mongodb.Db
    collectionName = 'users',
  ) {
    this.col = this.db.collection(collectionName);
  }

  /** Call once at application start to create indexes. */
  async init(): Promise<void> {
    await this.col.createIndex({ email: 1 }, { unique: true });
    await this.col.createIndex({ resetToken: 1 }, { sparse: true });
    await this.col.createIndex({ magicLinkToken: 1 }, { sparse: true });
    await this.col.createIndex({ emailVerificationToken: 1 }, { sparse: true });
    await this.col.createIndex({ emailChangeToken: 1 }, { sparse: true });
    await this.col.createIndex({ accountLinkToken: 1 }, { sparse: true });
    await this.col.createIndex({ loginProvider: 1, providerAccountId: 1 }, { sparse: true });
  }

  async findByEmail(email: string): Promise<BaseUser | null> {
    const doc: DbUserDoc | null = await this.col.findOne({ email });
    return doc ? toBaseUser(doc) : null;
  }
  async findById(id: string): Promise<BaseUser | null> {
    const doc: DbUserDoc | null = await this.col.findOne({ _id: id });
    return doc ? toBaseUser(doc) : null;
  }
  async create(data: Partial<BaseUser>): Promise<BaseUser> {
    const _id = data.id ?? crypto.randomUUID();
    const now  = new Date();
    await this.col.insertOne({
      _id,
      email:                     data.email ?? '',
      password:                  data.password ?? null,
      role:                      data.role ?? 'user',
      firstName:                 data.firstName ?? null,
      lastName:                  data.lastName  ?? null,
      loginProvider:             data.loginProvider ?? null,
      providerAccountId:         data.providerAccountId ?? null,
      isEmailVerified:           data.isEmailVerified ?? false,
      emailVerificationDeadline: data.emailVerificationDeadline ?? null,
      phoneNumber:               data.phoneNumber ?? null,
      require2FA:                data.require2FA ?? false,
      isTotpEnabled:             false,
      createdAt:                 now,
      updatedAt:                 now,
    } as DbUserDoc);
    return (await this.findById(_id))!;
  }

  private async set(userId: string, fields: Partial<DbUserDoc>): Promise<void> {
    await this.col.updateOne({ _id: userId }, { $set: { ...fields, updatedAt: new Date() } });
  }

  async updateRefreshToken(userId: string, token: string | null, expiry: Date | null): Promise<void> {
    await this.set(userId, { refreshToken: token, refreshTokenExpiry: expiry });
  }
  async updateLastLogin(userId: string): Promise<void> {
    await this.set(userId, { lastLogin: new Date() });
  }
  async updateResetToken(userId: string, token: string | null, expiry: Date | null): Promise<void> {
    await this.set(userId, { resetToken: token, resetTokenExpiry: expiry });
  }
  async updatePassword(userId: string, hashedPassword: string): Promise<void> {
    await this.set(userId, { password: hashedPassword });
  }
  async updateTotpSecret(userId: string, secret: string | null): Promise<void> {
    await this.set(userId, { totpSecret: secret, isTotpEnabled: secret !== null });
  }
  async updateMagicLinkToken(userId: string, token: string | null, expiry: Date | null): Promise<void> {
    await this.set(userId, { magicLinkToken: token, magicLinkTokenExpiry: expiry });
  }
  async updateSmsCode(userId: string, code: string | null, expiry: Date | null): Promise<void> {
    await this.set(userId, { smsCode: code, smsCodeExpiry: expiry });
  }
  async findByResetToken(token: string): Promise<BaseUser | null> {
    const doc = await this.col.findOne({ resetToken: token });
    return doc ? toBaseUser(doc) : null;
  }
  async findByMagicLinkToken(token: string): Promise<BaseUser | null> {
    const doc = await this.col.findOne({ magicLinkToken: token });
    return doc ? toBaseUser(doc) : null;
  }
  async updateEmailVerificationToken(userId: string, token: string | null, expiry: Date | null): Promise<void> {
    await this.set(userId, { emailVerificationToken: token, emailVerificationTokenExpiry: expiry });
  }
  async updateEmailVerified(userId: string, isVerified: boolean): Promise<void> {
    await this.set(userId, { isEmailVerified: isVerified });
  }
  async findByEmailVerificationToken(token: string): Promise<BaseUser | null> {
    const doc = await this.col.findOne({ emailVerificationToken: token });
    return doc ? toBaseUser(doc) : null;
  }
  async updateEmailChangeToken(userId: string, pendingEmail: string | null, token: string | null, expiry: Date | null): Promise<void> {
    await this.set(userId, { pendingEmail, emailChangeToken: token, emailChangeTokenExpiry: expiry });
  }
  async updateEmail(userId: string, newEmail: string): Promise<void> {
    await this.set(userId, { email: newEmail, pendingEmail: null, emailChangeToken: null, emailChangeTokenExpiry: null });
  }
  async findByEmailChangeToken(token: string): Promise<BaseUser | null> {
    const doc = await this.col.findOne({ emailChangeToken: token });
    return doc ? toBaseUser(doc) : null;
  }
  async updateAccountLinkToken(userId: string, pendingEmail: string | null, pendingProvider: string | null, token: string | null, expiry: Date | null): Promise<void> {
    await this.set(userId, { accountLinkPendingEmail: pendingEmail, accountLinkPendingProvider: pendingProvider, accountLinkToken: token, accountLinkTokenExpiry: expiry });
  }
  async findByAccountLinkToken(token: string): Promise<BaseUser | null> {
    const doc = await this.col.findOne({ accountLinkToken: token });
    return doc ? toBaseUser(doc) : null;
  }
  async updateRequire2FA(userId: string, required: boolean): Promise<void> {
    await this.set(userId, { require2FA: required });
  }
  async findByProviderAccount(provider: string, providerAccountId: string): Promise<BaseUser | null> {
    const doc = await this.col.findOne({ loginProvider: provider, providerAccountId });
    return doc ? toBaseUser(doc) : null;
  }
  async listUsers(limit: number, offset: number): Promise<BaseUser[]> {
    const docs: DbUserDoc[] = await this.col.find({}).skip(offset).limit(limit).toArray();
    return docs.map(toBaseUser);
  }
  async deleteUser(id: string): Promise<void> {
    await this.col.deleteOne({ _id: id });
  }
}
