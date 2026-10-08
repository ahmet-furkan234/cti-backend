import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { IUserRepository } from '../../../domain/user/user.repository.interface.js';
import type { ICompanyRepository } from '../../../domain/company/company.repository.interface.js';
import { NotFoundException } from '../../../domain/common/exceptions.js';
import { EffectivePermissionService } from '../../rbac/services/effective-permission.service.js';
import { Entity } from '../../../shared/strings.js';

@injectable()
export class GetMeUseCase {
  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
    @inject(TYPES.ICompanyRepository) private readonly companies: ICompanyRepository,
  ) {}

  /** `actingCompanyId`: the company the request works in (differs from the user's own for a platform user working in another one). */
  async execute(userId: string, actingCompanyId?: string) {
    const user = await this.users.findById(userId);
    if (!user) throw new NotFoundException(Entity.user);
    const [roles, access, home, acting] = await Promise.all([
      this.users.getRoles(userId),
      this.perms.getAccess(userId),
      this.companies.findById(user.companyId),
      this.companies.findById(actingCompanyId ?? user.companyId),
    ]);
    const brief = (c: typeof home) => (c ? { id: c.id, name: c.name, isPlatform: c.isPlatform } : null);
    return {
      id: user.id,
      email: user.email.value,
      name: user.name,
      roles,
      permissions: access?.permissions ?? [],
      lastLoginAt: user.lastLoginAt,
      company: brief(home),
      /** the company whose data is on screen */
      actingCompany: brief(acting),
    };
  }
}
