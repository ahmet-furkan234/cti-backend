import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { IUserRepository } from '../../../domain/user/user.repository.interface.js';
import {
  allowedKeys,
  computeEffectivePermissions,
  type EffectivePermission,
} from '../../../domain/rbac/effective-permissions.js';

export interface ResolvedAccess {
  active: boolean;
  email: string;
  permissions: string[];
}

const TTL_MS = 30_000;

/**
 * Resolves and caches a user's effective permissions. The cache is invalidated
 * explicitly on changes; the short TTL covers multi-process deployments.
 */
@injectable()
export class EffectivePermissionService {
  private readonly cache = new Map<string, { value: ResolvedAccess; expires: number }>();

  constructor(@inject(TYPES.IUserRepository) private readonly users: IUserRepository) {}

  async getAccess(userId: string): Promise<ResolvedAccess | null> {
    const hit = this.cache.get(userId);
    if (hit && hit.expires > Date.now()) return hit.value;

    const user = await this.users.findById(userId);
    if (!user) {
      this.cache.delete(userId);
      return null;
    }
    const detailed = await this.getDetailed(userId);
    const value: ResolvedAccess = { active: user.isActive, email: user.email.value, permissions: allowedKeys(detailed) };
    this.cache.set(userId, { value, expires: Date.now() + TTL_MS });
    return value;
  }

  async getDetailed(userId: string): Promise<EffectivePermission[]> {
    const [grants, overrides] = await Promise.all([
      this.users.getRoleGrants(userId),
      this.users.getOverrides(userId),
    ]);
    return computeEffectivePermissions(grants, overrides);
  }

  invalidate(userId: string): void {
    this.cache.delete(userId);
  }

  invalidateMany(userIds: string[]): void {
    userIds.forEach((id) => this.cache.delete(id));
  }

  invalidateAll(): void {
    this.cache.clear();
  }
}
