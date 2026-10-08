import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { IUserRepository } from '../../../domain/user/user.repository.interface.js';
import type { ICompanyRepository } from '../../../domain/company/company.repository.interface.js';
import { isPlatformOnlyPermission } from '../../../domain/rbac/permission-catalog.js';
import {
  allowedKeys,
  computeEffectivePermissions,
  type EffectivePermission,
} from '../../../domain/rbac/effective-permissions.js';

export interface ResolvedAccess {
  /** the user is active and so is their company */
  active: boolean;
  email: string;
  permissions: string[];
  companyId: string;
  /** the user's company is the platform owner */
  platform: boolean;
}

const TTL_MS = 30_000;

/**
 * Resolves and caches a user's effective permissions. The cache is invalidated
 * explicitly on changes; the short TTL covers multi-process deployments.
 */
@injectable()
export class EffectivePermissionService {
  private readonly cache = new Map<string, { value: ResolvedAccess; expires: number }>();

  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.ICompanyRepository) private readonly companies: ICompanyRepository,
  ) {}

  async getAccess(userId: string): Promise<ResolvedAccess | null> {
    const hit = this.cache.get(userId);
    if (hit && hit.expires > Date.now()) return hit.value;

    const user = await this.users.findById(userId);
    if (!user) {
      this.cache.delete(userId);
      return null;
    }
    const [detailed, company] = await Promise.all([this.getDetailed(userId), this.companies.findById(user.companyId)]);
    const platform = !!company?.isPlatform;
    const value: ResolvedAccess = {
      active: user.isActive && company?.status === 'active',
      email: user.email.value,
      // Platform management belongs to the main company only, whatever roles or overrides say.
      permissions: allowedKeys(detailed).filter((k) => platform || !isPlatformOnlyPermission(k)),
      companyId: user.companyId,
      platform,
    };
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
