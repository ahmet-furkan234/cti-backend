import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { IUserRepository } from '../../../domain/user/user.repository.interface.js';
import { NotFoundException } from '../../../domain/common/exceptions.js';
import { EffectivePermissionService } from '../../rbac/services/effective-permission.service.js';
import { Entity } from '../../../shared/strings.js';

@injectable()
export class GetMeUseCase {
  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
  ) {}

  async execute(userId: string) {
    const user = await this.users.findById(userId);
    if (!user) throw new NotFoundException(Entity.user);
    const [roles, access] = await Promise.all([this.users.getRoles(userId), this.perms.getAccess(userId)]);
    return {
      id: user.id,
      email: user.email.value,
      name: user.name,
      roles,
      permissions: access?.permissions ?? [],
      lastLoginAt: user.lastLoginAt,
    };
  }
}
