export interface RefreshToken {
  id: string;
  userId: string;
  familyId: string;
  tokenHash: string;
  expiresAt: Date;
  revokedAt: Date | null;
  ip: string | null;
  userAgent: string | null;
  createdAt: Date;
}

export interface IRefreshTokenRepository {
  create(token: Omit<RefreshToken, 'id' | 'createdAt' | 'revokedAt'>): Promise<void>;
  findByHash(hash: string): Promise<RefreshToken | null>;
  revoke(id: string): Promise<void>;
  revokeFamily(familyId: string): Promise<void>;
  revokeAllForUser(userId: string, exceptFamilyId?: string): Promise<void>;
}

export type AuthTokenPurpose = 'invite' | 'reset';

export interface AuthToken {
  id: string;
  purpose: AuthTokenPurpose;
  tokenHash: string;
  email: string | null;
  userId: string | null;
  /** invites: the company the new user joins */
  companyId: string | null;
  roleIds: string[];
  expiresAt: Date;
  usedAt: Date | null;
  createdBy: string | null;
  createdAt: Date;
}

export interface IAuthTokenRepository {
  create(token: Omit<AuthToken, 'id' | 'createdAt' | 'usedAt'>): Promise<void>;
  findByHash(hash: string, purpose: AuthTokenPurpose): Promise<AuthToken | null>;
  markUsed(id: string): Promise<void>;
  /** Invalidates open tokens (e.g. previous invites for the same email). */
  invalidateOpen(purpose: AuthTokenPurpose, match: { email?: string; userId?: string }): Promise<void>;
}
