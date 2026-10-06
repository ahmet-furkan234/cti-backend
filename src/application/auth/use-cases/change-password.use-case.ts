import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { IUserRepository } from '../../../domain/user/user.repository.interface.js';
import type { IRefreshTokenRepository } from '../../../domain/auth/auth.repositories.js';
import type { IPasswordHasher } from '../../ports/ports.js';
import { PlainPassword } from '../../../domain/common/value-objects/plain-password.value-object.js';
import { InvalidCredentialsException } from '../../../domain/auth/auth.exceptions.js';
import { NotFoundException } from '../../../domain/common/exceptions.js';
import { AuditService } from '../../audit/audit.service.js';
import { AuditAction, Entity } from '../../../shared/strings.js';

@injectable()
export class ChangePasswordUseCase {
  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.IRefreshTokenRepository) private readonly refreshRepo: IRefreshTokenRepository,
    @inject(TYPES.IPasswordHasher) private readonly hasher: IPasswordHasher,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(userId: string, currentPassword: string, newPassword: string, ip: string | null): Promise<void> {
    const user = await this.users.findById(userId);
    if (!user) throw new NotFoundException(Entity.user);
    if (!(await this.hasher.verify(user.passwordHash, currentPassword))) throw new InvalidCredentialsException();

    user.changePasswordHash(await this.hasher.hash(PlainPassword.from(newPassword).reveal()));
    await this.users.save(user);
    await this.refreshRepo.revokeAllForUser(userId);
    await this.audit.record({ id: userId, email: user.email.value, ip }, AuditAction.authPasswordChanged, { type: 'user', id: userId });
  }
}
