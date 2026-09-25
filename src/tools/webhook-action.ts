/**
 * @webhookAction decorator and ActionRegistry.
 *
 * Developers annotate service methods with `@webhookAction` to expose them
 * safely inside the `vm` sandbox when an inbound webhook fires.  The admin UI
 * can then:
 *   1. Globally enable / disable each action (via `ISettingsStore.enabledWebhookActions`).
 *   2. Assign a per-webhook subset of those enabled actions to each inbound
 *      webhook config (`WebhookConfig.allowedActions`).
 *
 * The sandbox only receives the **intersection** of both sets, enforcing the
 * Principle of Least Privilege.
 *
 * @example
 * ```typescript
 * import { webhookAction } from '@awesome-lang-auth/node';
 *
 * class UserService {
 *   \@webhookAction({
 *     id: 'user.suspend',
 *     label: 'Suspend user',
 *     category: 'Users',
 *     description: 'Set isActive=false on a user record.',
 *   })
 *   async suspendUser(userId: string): Promise<void> { ... }
 * }
 *
 * const svc = new UserService();
 * ActionRegistry.register({ id: 'user.suspend', ..., fn: svc.suspendUser.bind(svc) });
 * ```
 */

/** Metadata for a single webhook action. */
export interface WebhookActionMeta {
  /** Stable machine identifier, e.g. `'user.suspend'`. */
  id: string;
  /** Human-readable label shown in the Admin UI. */
  label: string;
  /** Grouping category shown in the Admin UI. */
  category: string;
  /** Short description shown in the Admin UI. */
  description: string;
  /**
   * Other action IDs that must be globally enabled for this action to be
   * available.  The UI will disable this action's toggle if any dependency
   * is not met.
   */
  dependsOn?: string[];
}

/** Registered action entry (metadata + callable function reference). */
export interface RegisteredAction extends WebhookActionMeta {
  fn: (...args: unknown[]) => unknown;
}

// Module-level registry (populated at boot time via `@webhookAction` or manual calls)
const _registry = new Map<string, RegisteredAction>();

/**
 * Registry of all webhook-exposed actions.
 *
 * All methods are static so the registry is accessible anywhere without
 * instantiation.
 */
export class ActionRegistry {
  /**
   * Register an action.  Called automatically by the `@webhookAction`
   * decorator, but can also be called manually (useful when the action
   * function is not on a class instance at decoration time).
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static register(entry: RegisteredAction): void {    _registry.set(entry.id, entry);
  }

  /** Return all registered actions (metadata + function). */
  static getAll(): RegisteredAction[] {
    return [..._registry.values()];
  }

  /** Return metadata for all registered actions (no function references). */
  static getAllMeta(): WebhookActionMeta[] {
    return [..._registry.values()].map(({ fn: _fn, ...meta }) => meta);
  }

  /**
   * Look up a single registered action by ID.
   * Returns `undefined` when not found.
   */
  static get(id: string): RegisteredAction | undefined {
    return _registry.get(id);
  }

  /**
   * Build the `actions` context object injected into the `vm` sandbox.
   *
   * Only includes actions that satisfy **all three** conditions:
   *  1. Registered in the registry.
   *  2. Listed in `enabledIds` (globally enabled by the admin).
   *  3. Listed in `allowedIds`  (assigned to this specific webhook).
   *
   * Additionally, a registered action is excluded if any of its `dependsOn`
   * entries are not in the effective allowed set.
   *
   * @param enabledIds  Globally enabled action IDs (`AuthSettings.enabledWebhookActions`).
   * @param allowedIds  Per-webhook allowed action IDs (`WebhookConfig.allowedActions`).
   * @returns           A `Record<id, fn>` object safe to pass as the `actions` sandbox variable.
   */
  static buildContext(enabledIds: string[], allowedIds: string[]): Record<string, (...args: unknown[]) => unknown> {
    const effectiveSet = new Set(allowedIds.filter((id) => enabledIds.includes(id)));
    const ctx: Record<string, (...args: unknown[]) => unknown> = {};
    for (const [id, entry] of _registry) {
      if (!effectiveSet.has(id)) continue;
      const depsOk = (entry.dependsOn ?? []).every((dep) => effectiveSet.has(dep));
      if (depsOk) ctx[id] = entry.fn;
    }
    return ctx;
  }

  /** Remove all entries (useful in tests). */
  static clear(): void {
    _registry.clear();
  }
}

/**
 * Method decorator that registers the decorated method in the `ActionRegistry`
 * using the provided metadata.
 *
 * Uses the **TC39 Stage 3** decorator syntax (TypeScript 5.x without
 * `experimentalDecorators`).
 *
 * The function reference stored in the registry is the **unbound** method.
 * For instance methods, pass a bound function when calling
 * `ActionRegistry.register` at runtime, or bind the instance manually:
 *
 * ```typescript
 * const svc = new BillingService();
 * ActionRegistry.register({
 *   id: 'billing.cancelSubscription',
 *   label: 'Cancel subscription',
 *   category: 'Billing',
 *   description: 'Cancel a subscription.',
 *   fn: svc.cancelSubscription.bind(svc),
 * });
 * ```
 *
 * @example
 * ```typescript
 * class BillingService {
 *   \@webhookAction({
 *     id: 'billing.cancelSubscription',
 *     label: 'Cancel subscription',
 *     category: 'Billing',
 *     description: 'Cancel a user subscription in the billing system.',
 *   })
 *   async cancelSubscription(subscriptionId: string): Promise<void> { ... }
 * }
 * ```
 */
export function webhookAction(meta: WebhookActionMeta) {
  return function <This, Args extends unknown[], Return>(
    value: (this: This, ...args: Args) => Return,
    _context: ClassMethodDecoratorContext,
  ): (this: This, ...args: Args) => Return {
    // Register the unbound method
    ActionRegistry.register({ ...meta, fn: value as (...args: unknown[]) => unknown });
    return value;
  };
}
