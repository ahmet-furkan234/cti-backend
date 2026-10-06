import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { IAuthTokenRepository, AuthToken, AuthTokenPurpose } from '../../../domain/auth/auth.repositories.js';
import type { IRefreshTokenRepository } from '../../../domain/auth/auth.repositories.js';
import type { IUserRepository } from '../../../domain/user/user.repository.interface.js';
import type { IRoleRepository } from '../../../domain/rbac/role.repository.interface.js';
import type { IPasswordHasher, ITokenService } from '../../ports/ports.js';
import { Email } from '../../../domain/common/value-objects/email.value-object.js';
import { PlainPassword } from '../../../domain/common/value-objects/plain-password.value-object.js';
import { User } from '../../../domain/user/user.entity.js';
import { AlreadyExistsException, NotFoundException } from '../../../domain/common/exceptions.js';
import { AuthTokenInvalidException } from '../../../domain/auth/auth.exceptions.js';
import { SessionService, type ClientInfo, type IssuedSession } from '../session.service.js';
import { AuditService } from '../../audit/audit.service.js';
import { AuditAction, Entity } from '../../../shared/strings.js';

async function loadUsable(
  repo: IAuthTokenRepository,
  tokens: ITokenService,
  raw: string,
  purpose: AuthTokenPurpose,
): Promise<AuthToken> {
  const found = await repo.findByHash(tokens.hashOpaqueToken(raw), purpose);
  if (!found || found.usedAt || found.expiresAt <= new Date()) throw new AuthTokenInvalidException();
  return found;
}

/** Public: lets the register / reset page show which account the link is for. */
@injectable()
export class GetAuthTokenInfoUseCase {
  constructor(
    @inject(TYPES.IAuthTokenRepository) private readonly repo: IAuthTokenRepository,
    @inject(TYPES.ITokenService) private readonly tokens: ITokenService,
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
  ) {}

  async execute(raw: string, purpose: AuthTokenPurpose): Promise<{ email: string }> {
    const t = await loadUsable(this.repo, this.tokens, raw, purpose);
    if (t.email) return { email: t.email };
    const user = t.userId ? await this.users.findById(t.userId) : null;
    if (!user) throw new AuthTokenInvalidException();
    return { email: user.email.value };
  }
}

@injectable()
export class RegisterWithInviteUseCase {
  constructor(
    @inject(TYPES.IAuthTokenRepository) private readonly repo: IAuthTokenRepository,
    @inject(TYPES.ITokenService) private readonly tokens: ITokenService,
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.IRoleRepository) private readonly roles: IRoleRepository,
    @inject(TYPES.IPasswordHasher) private readonly hasher: IPasswordHasher,
    @inject(TYPES.SessionService) private readonly sessions: SessionService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(
    input: { token: string; name: string; password: string } & ClientInfo,
  ): Promise<{ userId: string; session: IssuedSession }> {
    const invite = await loadUsable(this.repo, this.tokens, input.token, 'invite');
    if (!invite.email) throw new AuthTokenInvalidException();
    const email = Email.from(invite.email);
    const password = PlainPassword.from(input.password);
    if (await this.users.findByEmail(email)) throw new AlreadyExistsException(Entity.user, 'email');

    const user = new User({
      email,
      name: input.name,
      passwordHash: await this.hasher.hash(password.reveal()),
    });
    await this.users.create(user);
    // Roles may have been deleted since the invite was issued.
    const validRoles = await this.roles.findByIds(invite.roleIds);
    await this.users.replaceRoles(user.id, validRoles.map((r) => r.id));
    await this.repo.markUsed(invite.id);

    user.registerSuccessfulLogin();
    await this.users.save(user);
    const session = await this.sessions.issue(user.id, input);
    await this.audit.record({ id: user.id, email: user.email.value, ip: input.ip }, AuditAction.authRegistered, { type: 'user', id: user.id }, {
      roles: validRoles.map((r) => r.name),
    });
    return { userId: user.id, session };
  }
}

@injectable()
export class ResetPasswordUseCase {
  constructor(
    @inject(TYPES.IAuthTokenRepository) private readonly repo: IAuthTokenRepository,
    @inject(TYPES.ITokenService) private readonly tokens: ITokenService,
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.IRefreshTokenRepository) private readonly refreshRepo: IRefreshTokenRepository,
    @inject(TYPES.IPasswordHasher) private readonly hasher: IPasswordHasher,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(input: { token: string; password: string; ip: string | null }): Promise<void> {
    const t = await loadUsable(this.repo, this.tokens, input.token, 'reset');
    const user = t.userId ? await this.users.findById(t.userId) : null;
    if (!user) throw new NotFoundException(Entity.user);

    user.changePasswordHash(await this.hasher.hash(PlainPassword.from(input.password).reveal()));
    await this.users.save(user);
    await this.repo.markUsed(t.id);
    await this.refreshRepo.revokeAllForUser(user.id);
    await this.audit.record({ id: user.id, email: user.email.value, ip: input.ip }, AuditAction.authPasswordReset, { type: 'user', id: user.id });
  }
}
