/*
 * Compiled by tests/register-sanitize.types.test.ts (never run, never part of
 * `tsc -p .`).  Positive control: with the real BaseUser, register-sanitize.ts
 * compiles and BASE_USER_FIELD_CLASS has exactly the keys of BaseUser.
 */
import { BASE_USER_FIELD_CLASS } from '../../../src/router/register-sanitize';
import type { BaseUser } from '../../../src/models/user.model';

type SameKeys<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

export const keysMatch: SameKeys<keyof typeof BASE_USER_FIELD_CLASS, keyof BaseUser> = true;
