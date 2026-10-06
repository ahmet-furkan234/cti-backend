import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { IRefreshTokenRepository } from '../../../domain/auth/auth.repositories.js';
import type { IUserRepository } from '../../../domain/user/user.repository.interface.js';
import type { ITokenService } from '../../ports/ports.js';
import { RefreshTokenInvalidException, UserInactiveException } from '../../../domain/auth/auth.exceptions.js';
import { SessionService, type ClientInfo, type IssuedSession } from '../session.service.js';
import { AuditService } from '../../audit/audit.service.js';
import { AuditAction } from '../../../shared/strings.js';

const REUSE_GRACE_MS = 10_000;

@injectable()
export class RefreshSessionUseCase {
  constructor(
    @inject(TYPES.ITokenService) private readonly tokens: ITokenService,
    @inject(TYPES.IRefreshTokenRepository) private readonly refreshRepo: IRefreshTokenRepository,
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.SessionService) private readonly sessions: SessionService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(refreshToken: string, client: ClientInfo): Promise<IssuedSession> {
    const stored = await this.refreshRepo.findByHash(this.tokens.hashOpaqueToken(refreshToken));
    if (!stored) throw new RefreshTokenInvalidException();

    if (stored.revokedAt) {
      // Two tabs (or a StrictMode double effect) refreshing at once present the same
      // token; the loser must retry with the fresh cookie instead of killing the session.
      if (Date.now() - stored.revokedAt.getTime() < REUSE_GRACE_MS) throw new RefreshTokenInvalidException();
      // A rotated token was presented again: assume theft and kill the whole family.
      await this.refreshRepo.revokeFamily(stored.familyId);
      await this.audit.record(
        { id: stored.userId, email: null, ip: client.ip },
        AuditAction.authRefreshReuseDetected,
        { type: 'user', id: stored.userId },
      );
      throw new RefreshTokenInvalidException();
    }
    if (stored.expiresAt <= new Date()) throw new RefreshTokenInvalidException();

    const user = await this.users.findById(stored.userId);
    if (!user) throw new RefreshTokenInvalidException();
    if (!user.isActive) throw new UserInactiveException();

    await this.refreshRepo.revoke(stored.id);
    return this.sessions.issue(user.id, client, stored.familyId);
  }
}
