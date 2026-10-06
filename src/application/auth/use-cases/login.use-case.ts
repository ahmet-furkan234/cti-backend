import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { IUserRepository } from '../../../domain/user/user.repository.interface.js';
import type { IPasswordHasher } from '../../ports/ports.js';
import { Email } from '../../../domain/common/value-objects/email.value-object.js';
import { AccountLockedException } from '../../../domain/common/exceptions.js';
import { InvalidCredentialsException, UserInactiveException } from '../../../domain/auth/auth.exceptions.js';
import { SessionService, type ClientInfo, type IssuedSession } from '../session.service.js';
import { AuditService } from '../../audit/audit.service.js';
import { AuditAction } from '../../../shared/strings.js';

export interface LoginInput extends ClientInfo {
  email: string;
  password: string;
}

@injectable()
export class LoginUseCase {
  // A real hash (computed once) to verify against when the email is unknown, so the
  // response time does not reveal whether an account exists.
  private dummyHash: Promise<string> | null = null;

  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.IPasswordHasher) private readonly hasher: IPasswordHasher,
    @inject(TYPES.SessionService) private readonly sessions: SessionService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(input: LoginInput): Promise<{ userId: string; session: IssuedSession }> {
    const email = Email.tryFrom(input.email);
    const actor = { id: null, email: email?.value ?? input.email.trim().toLowerCase().slice(0, 254), ip: input.ip };
    const user = email ? await this.users.findByEmail(email) : null;

    if (!user) {
      this.dummyHash ??= this.hasher.hash('cti-dummy-password-for-timing');
      await this.hasher.verify(await this.dummyHash, input.password);
      await this.audit.record(actor, AuditAction.authLoginFailed, undefined, { reason: 'unknown_user' });
      throw new InvalidCredentialsException();
    }
    if (user.isLocked()) {
      await this.audit.record({ ...actor, id: user.id }, AuditAction.authLoginBlocked, undefined, { reason: 'locked' });
      throw new AccountLockedException(user.lockedUntil!);
    }

    const valid = await this.hasher.verify(user.passwordHash, input.password);
    if (!valid) {
      user.registerFailedLogin();
      await this.users.save(user);
      await this.audit.record({ ...actor, id: user.id }, AuditAction.authLoginFailed, undefined, { reason: 'bad_password' });
      throw new InvalidCredentialsException();
    }
    if (!user.isActive) throw new UserInactiveException();

    user.registerSuccessfulLogin();
    await this.users.save(user);
    const session = await this.sessions.issue(user.id, input);
    await this.audit.record({ ...actor, id: user.id }, AuditAction.authLogin, { type: 'user', id: user.id });
    return { userId: user.id, session };
  }
}
