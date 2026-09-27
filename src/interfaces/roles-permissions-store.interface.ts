/**
 * Base interface for a role document stored in a database.
 * Use this as the foundation for Mongoose schemas or other ORM models.
 *
 * @example
 * ```typescript
 * // Mongoose example
 * import { IRoleDocument } from '@awesome-lang-auth/node';
 * import { Schema, model, Document } from 'mongoose';
 *
 * interface IRoleDoc extends IRoleDocument, Document {}
 *
 * const roleSchema = new Schema<IRoleDoc>({
 *   name:        { type: String, required: true, unique: true },
 *   permissions: [{ type: String }],
 * });
 * ```
 */
export interface IRoleDocument {
  name: string;
  permissions: string[];
}

/**
 * Base interface for a user-role assignment document stored in a database.
 * Supports both single-tenant and multi-tenant role assignments via the
 * optional `tenantId` field.
 *
 * @example
 * ```typescript
 * // Mongoose example
 * import { IRoleUserDocument } from '@awesome-lang-auth/node';
 * import { Schema, model, Document } from 'mongoose';
 *
 * interface IRoleUserDoc extends IRoleUserDocument, Document {}
 *
 * const roleUserSchema = new Schema<IRoleUserDoc>({
 *   userId:   { type: String, required: true, index: true },
 *   role:     { type: String, required: true, index: true },
 *   tenantId: { type: String, index: true },
 * });
 * ```
 */
export interface IRoleUserDocument {
  userId: string;
  role: string;
  tenantId?: string;
}

/**
 * Optional store for role-based access control (RBAC).
 *
 * Implement this interface to assign roles to users, attach fine-grained
 * permissions to roles, and perform permission checks.  All tenant-aware
 * methods accept an optional `tenantId` parameter so the same interface
 * works for both single-tenant and multi-tenant applications.
 *
 * @example
 * ```typescript
 * import { IRolesPermissionsStore } from '@awesome-lang-auth/node';
 *
 * export class MyRbacStore implements IRolesPermissionsStore {
 *   async addRoleToUser(userId, role, tenantId?) { ... }
 *   async removeRoleFromUser(userId, role, tenantId?) { ... }
 *   async getRolesForUser(userId, tenantId?) { ... }
 *   async createRole(role, permissions?) { ... }
 *   async deleteRole(role) { ... }
 *   async addPermissionToRole(role, permission) { ... }
 *   async removePermissionFromRole(role, permission) { ... }
 *   async getPermissionsForRole(role) { ... }
 *   async getPermissionsForUser(userId, tenantId?) { ... }
 *   async userHasPermission(userId, permission, tenantId?) { ... }
 * }
 * ```
 */
export interface IRolesPermissionsStore {
  // ------------------------------------------------------------------
  // User ↔ Role assignments
  // ------------------------------------------------------------------

  /**
   * Assign `role` to the given user.
   * When `tenantId` is provided the assignment is scoped to that tenant.
   */
  addRoleToUser(userId: string, role: string, tenantId?: string): Promise<void>;

  /**
   * Remove `role` from the given user.
   * When `tenantId` is provided only the tenant-scoped assignment is removed.
   */
  removeRoleFromUser(userId: string, role: string, tenantId?: string): Promise<void>;

  /**
   * Return the list of roles assigned to the given user.
   * When `tenantId` is provided only roles scoped to that tenant are returned.
   */
  getRolesForUser(userId: string, tenantId?: string): Promise<string[]>;

  // ------------------------------------------------------------------
  // Role management
  // ------------------------------------------------------------------

  /**
   * Create a new role, optionally pre-loading it with a set of permissions.
   * Idempotent — calling it on an existing role should not throw.
   */
  createRole(role: string, permissions?: string[]): Promise<void>;

  /**
   * Delete a role and all its permission assignments.
   * User ↔ role assignments for this role should also be removed.
   */
  deleteRole(role: string): Promise<void>;

  // ------------------------------------------------------------------
  // Role ↔ Permission assignments
  // ------------------------------------------------------------------

  /**
   * Add `permission` to `role`.
   * Idempotent — adding an already-assigned permission should not throw.
   */
  addPermissionToRole(role: string, permission: string): Promise<void>;

  /**
   * Remove `permission` from `role`.
   */
  removePermissionFromRole(role: string, permission: string): Promise<void>;

  /**
   * Return all permissions assigned to `role`.
   */
  getPermissionsForRole(role: string): Promise<string[]>;

  // ------------------------------------------------------------------
  // Convenience helpers
  // ------------------------------------------------------------------

  /**
   * Return all permissions the user has, aggregated across all their roles.
   * When `tenantId` is provided only roles scoped to that tenant are considered.
   */
  getPermissionsForUser(userId: string, tenantId?: string): Promise<string[]>;

  /**
   * Check whether the user has a specific permission (across any of their roles).
   * When `tenantId` is provided only roles scoped to that tenant are checked.
   */
  userHasPermission(userId: string, permission: string, tenantId?: string): Promise<boolean>;

  /**
   * Return all role names defined in the store.
   * Used by the optional admin router to display the roles & permissions table.
   */
  getAllRoles?(): Promise<string[]>;
}
