import { and, eq, isNull, ne } from 'drizzle-orm';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type {
  AuthToken, AuthTokenPurpose, IAuthTokenRepository, IRefreshTokenRepository, RefreshToken,
} from '../../../domain/auth/auth.repositories.js';
import type { Database } from '../client.js';
import { authTokens, refreshTokens } from '../schema/index.js';

@injectable()
export class RefreshTokenRepository implements IRefreshTokenRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  async create(t: Omit<RefreshToken, 'id' | 'createdAt' | 'revokedAt'>) {
    await this.db.insert(refreshTokens).values(t);
  }

  async findByHash(hash: string): Promise<RefreshToken | null> {
    const [r] = await this.db.select().from(refreshTokens).where(eq(refreshTokens.tokenHash, hash)).limit(1);
    return r ?? null;
  }

  async revoke(id: string) {
    await this.db.update(refreshTokens).set({ revokedAt: new Date() }).where(eq(refreshTokens.id, id));
  }

  async revokeFamily(familyId: string) {
    await this.db
      .update(refreshTokens)
      .set({ revokedAt: new Date() })
      .where(and(eq(refreshTokens.familyId, familyId), isNull(refreshTokens.revokedAt)));
  }

  async revokeAllForUser(userId: string, exceptFamilyId?: string) {
    const conds = [eq(refreshTokens.userId, userId), isNull(refreshTokens.revokedAt)];
    if (exceptFamilyId) conds.push(ne(refreshTokens.familyId, exceptFamilyId));
    await this.db.update(refreshTokens).set({ revokedAt: new Date() }).where(and(...conds));
  }
}

@injectable()
export class AuthTokenRepository implements IAuthTokenRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  async create(t: Omit<AuthToken, 'id' | 'createdAt' | 'usedAt'>) {
    await this.db.insert(authTokens).values(t);
  }

  async findByHash(hash: string, purpose: AuthTokenPurpose): Promise<AuthToken | null> {
    const [r] = await this.db
      .select()
      .from(authTokens)
      .where(and(eq(authTokens.tokenHash, hash), eq(authTokens.purpose, purpose)))
      .limit(1);
    return r ?? null;
  }

  async markUsed(id: string) {
    await this.db.update(authTokens).set({ usedAt: new Date() }).where(eq(authTokens.id, id));
  }

  async invalidateOpen(purpose: AuthTokenPurpose, match: { email?: string; userId?: string }) {
    const conds = [eq(authTokens.purpose, purpose), isNull(authTokens.usedAt)];
    if (match.email) conds.push(eq(authTokens.email, match.email));
    if (match.userId) conds.push(eq(authTokens.userId, match.userId));
    await this.db.update(authTokens).set({ usedAt: new Date() }).where(and(...conds));
  }
}
