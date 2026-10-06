import { randomUUID } from 'crypto';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { IRefreshTokenRepository } from '../../domain/auth/auth.repositories.js';
import type { ITokenService } from '../ports/ports.js';
import type { EnvConfig } from '../../infrastructure/common/env.config.js';

export interface ClientInfo {
  ip: string | null;
  userAgent: string | null;
}

export interface IssuedSession {
  accessToken: string;
  expiresIn: number;
  refreshToken: string;
  refreshExpiresAt: Date;
  familyId: string;
}

@injectable()
export class SessionService {
  constructor(
    @inject(TYPES.ITokenService) private readonly tokens: ITokenService,
    @inject(TYPES.IRefreshTokenRepository) private readonly refreshRepo: IRefreshTokenRepository,
    @inject(TYPES.EnvConfig) private readonly config: EnvConfig,
  ) {}

  async issue(userId: string, client: ClientInfo, familyId: string = randomUUID()): Promise<IssuedSession> {
    const access = this.tokens.signAccessToken(userId);
    const refresh = this.tokens.generateOpaqueToken();
    const refreshExpiresAt = new Date(Date.now() + this.config.REFRESH_TOKEN_TTL_DAYS * 86_400_000);
    await this.refreshRepo.create({
      userId,
      familyId,
      tokenHash: refresh.hash,
      expiresAt: refreshExpiresAt,
      ip: client.ip,
      userAgent: client.userAgent,
    });
    return {
      accessToken: access.token,
      expiresIn: access.expiresInSeconds,
      refreshToken: refresh.token,
      refreshExpiresAt,
      familyId,
    };
  }
}
