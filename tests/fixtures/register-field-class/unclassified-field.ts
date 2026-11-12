/*
 * Compiled by tests/register-sanitize.types.test.ts (never run, never part of
 * `tsc -p .`).  Negative fixture: BaseUser gains a field (through declaration
 * merging) that BASE_USER_FIELD_CLASS does not classify.  The
 * `satisfies Record<keyof BaseUser, ...>` clause in register-sanitize.ts must
 * then fail to compile, so a future privileged field cannot silently become
 * mass-assignable through POST /auth/register.
 */
import '../../../src/router/register-sanitize';

declare module '../../../src/models/user.model' {
  interface BaseUser {
    isSuperAdmin?: boolean;
  }
}
