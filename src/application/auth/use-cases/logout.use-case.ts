import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { IRefreshTokenRepository } from '../../../domain/auth/auth.repositories.js';
import type { ITokenService } from '../../ports/ports.js';

@injectable()
export class LogoutUseCase {
  constructor(
    @inject(TYPES.ITokenService) private readonly tokens: ITokenService,
    @inject(TYPES.IRefreshTokenRepository) private readonly refreshRepo: IRefreshTokenRepository,
  ) {}

  async execute(refreshToken: string | undefined): Promise<void> {
    if (!refreshToken) return;
    const stored = await this.refreshRepo.findByHash(this.tokens.hashOpaqueToken(refreshToken));
    if (stored) await this.refreshRepo.revokeFamily(stored.familyId);
  }
}
