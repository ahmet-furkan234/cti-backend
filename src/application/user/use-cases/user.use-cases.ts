import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { IUserRepository, ListUsersQuery } from '../../../domain/user/user.repository.interface.js';
import type { IRoleRepository } from '../../../domain/rbac/role.repository.interface.js';
import type { IPermissionRepository } from '../../../domain/rbac/role.repository.interface.js';
import type { IAuthTokenRepository, IRefreshTokenRepository } from '../../../domain/auth/auth.repositories.js';
import type { ITokenService } from '../../ports/ports.js';
import type { IPasswordHasher } from '../../ports/ports.js';
import type { UserStatus } from '../../../domain/user/user.entity.js';
import type { OverrideEffect } from '../../../domain/rbac/effective-permissions.js';
import { Email } from '../../../domain/common/value-objects/email.value-object.js';
import { PlainPassword } from '../../../domain/common/value-objects/plain-password.value-object.js';
import { User } from '../../../domain/user/user.entity.js';
import { SUPER_ADMIN_ROLE } from '../../../domain/rbac/permission-catalog.js';
import {
  AlreadyExistsException,
  ForbiddenException,
  InvalidStateException,
  InvalidValueException,
} from '../../../domain/common/exceptions.js';
import { EffectivePermissionService } from '../../rbac/services/effective-permission.service.js';
import { assertCanGrant, assertCanManageUser, assertKnownPermissions, assertPlatformKeysAllowed, assertRolesAssignable, loadCompanyUser } from '../../shared/access-guard.js';
import { tenant } from '../../../shared/tenant.js';
import { AuditService } from '../../audit/audit.service.js';
import { auditActor, type Actor } from '../../shared/actor.js';
import type { EnvConfig } from '../../../infrastructure/common/env.config.js';
import { AuditAction, Entity, Errors, WebPath } from '../../../shared/strings.js';
import { PERMISSIONS } from '../../../domain/rbac/permission-catalog.js';

const INVITE_TTL_MS = 7 * 86_400_000;
const RESET_TTL_MS = 24 * 3_600_000;

function userDto(
  user: { id: string; email: Email; name: string; status: string; lastLoginAt: Date | null; createdAt: Date },
  roles: { id: string; name: string }[],
) {
  return {
    id: user.id,
    email: user.email.value,
    name: user.name,
    status: user.status,
    lastLoginAt: user.lastLoginAt,
    createdAt: user.createdAt,
    roles,
  };
}

@injectable()
export class ListUsersUseCase {
  constructor(@inject(TYPES.IUserRepository) private readonly users: IUserRepository) {}

  async execute(query: ListUsersQuery) {
    const { items, total } = await this.users.list(query);
    return {
      items: items.map((i) => userDto(i.user, i.roles)),
      total,
      page: query.page,
      pageSize: query.pageSize,
    };
  }
}

@injectable()
export class GetUserUseCase {
  constructor(@inject(TYPES.IUserRepository) private readonly users: IUserRepository) {}

  async execute(id: string) {
    const user = await loadCompanyUser(this.users, id);
    const [roles, overrides] = await Promise.all([this.users.getRoles(id), this.users.getOverrides(id)]);
    return { ...userDto(user, roles), overrides };
  }
}

@injectable()
export class InviteUserUseCase {
  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.IRoleRepository) private readonly roles: IRoleRepository,
    @inject(TYPES.IAuthTokenRepository) private readonly authTokens: IAuthTokenRepository,
    @inject(TYPES.ITokenService) private readonly tokens: ITokenService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
    @inject(TYPES.EnvConfig) private readonly config: EnvConfig,
  ) {}

  async execute(actor: Actor, input: { email: string; roleIds: string[] }) {
    const email = Email.from(input.email);
    if (await this.users.findByEmail(email)) throw new AlreadyExistsException(Entity.user, 'email');

    const roles = await this.roles.findByIds(input.roleIds);
    if (roles.length !== new Set(input.roleIds).size) throw new InvalidValueException(Errors.rolesMissing);
    assertRolesAssignable(roles);
    assertCanGrant(actor.permissions, roles.flatMap((r) => r.permissionKeys));

    await this.authTokens.invalidateOpen('invite', { email: email.value });
    const { token, hash } = this.tokens.generateOpaqueToken();
    const expiresAt = new Date(Date.now() + INVITE_TTL_MS);
    await this.authTokens.create({
      purpose: 'invite',
      tokenHash: hash,
      email: email.value,
      userId: null,
      companyId: tenant.id(),
      roleIds: roles.map((r) => r.id),
      expiresAt,
      createdBy: actor.id,
    });
    await this.audit.record(auditActor(actor), AuditAction.userInvited, { type: 'user', id: email.value }, { roles: roles.map((r) => r.name) });
    // No mailer yet (alert channels arrive in a later phase): the admin shares the link.
    return { email: email.value, expiresAt, inviteUrl: `${this.config.WEB_BASE_URL}${WebPath.register(token)}` };
  }
}

@injectable()
export class CreateUserUseCase {
  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.IRoleRepository) private readonly roles: IRoleRepository,
    @inject(TYPES.IPermissionRepository) private readonly permissions: IPermissionRepository,
    @inject(TYPES.IPasswordHasher) private readonly hasher: IPasswordHasher,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, input: {
    name: string;
    email: string;
    password: string;
    roleIds: string[];
    overrides: { key: string; effect: OverrideEffect }[];
  }) {
    const email = Email.from(input.email);
    const password = PlainPassword.from(input.password);
    if (await this.users.findByEmail(email)) throw new AlreadyExistsException(Entity.user, 'email');

    const roles = await this.roles.findByIds(input.roleIds);
    if (roles.length !== new Set(input.roleIds).size) throw new InvalidValueException(Errors.rolesMissing);
    assertRolesAssignable(roles);
    assertCanGrant(actor.permissions, roles.flatMap((r) => r.permissionKeys));

    if (new Set(input.overrides.map((o) => o.key)).size !== input.overrides.length) {
      throw new InvalidValueException(Errors.duplicateOverrides);
    }
    if (input.overrides.length > 0 && !actor.permissions.includes(PERMISSIONS.PERMISSION_ASSIGN)) {
      throw new ForbiddenException(Errors.insufficientPrivilege);
    }
    await assertKnownPermissions(this.permissions, input.overrides.map((o) => o.key));
    assertPlatformKeysAllowed(input.overrides.filter((o) => o.effect === 'grant').map((o) => o.key));
    assertCanGrant(actor.permissions, input.overrides.filter((o) => o.effect === 'grant').map((o) => o.key));

    const user = new User({
      companyId: tenant.id(),
      email,
      name: input.name,
      passwordHash: await this.hasher.hash(password.reveal()),
    });
    await this.users.create(user);
    await this.users.replaceRoles(user.id, roles.map((r) => r.id));
    if (input.overrides.length > 0) await this.users.replaceOverrides(user.id, input.overrides);
    await this.audit.record(auditActor(actor), AuditAction.userCreated, { type: 'user', id: user.id }, {
      email: email.value,
      roles: roles.map((r) => r.name),
      overrides: input.overrides,
    });
    return { ...userDto(user, roles), overrides: input.overrides };
  }
}

@injectable()
export class UpdateUserUseCase {
  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.IRoleRepository) private readonly roles: IRoleRepository,
    @inject(TYPES.IRefreshTokenRepository) private readonly refreshRepo: IRefreshTokenRepository,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, id: string, input: { name?: string; status?: UserStatus; roleIds?: string[] }) {
    const user = await loadCompanyUser(this.users, id);
    const isSelf = actor.id === id;
    if (!isSelf) await assertCanManageUser(this.perms, actor.permissions, id);
    const changes: Record<string, unknown> = {};

    if (input.roleIds && isSelf) throw new ForbiddenException(Errors.selfRoleChange);
    if (input.status === 'disabled' && isSelf) throw new ForbiddenException(Errors.selfDisable);

    const currentRoles = await this.users.getRoles(id);
    const superRole = await this.roles.findByName(SUPER_ADMIN_ROLE);
    const isSuper = !!superRole && currentRoles.some((r) => r.id === superRole.id);

    if (input.roleIds) {
      const roles = await this.roles.findByIds(input.roleIds);
      if (roles.length !== new Set(input.roleIds).size) throw new InvalidValueException(Errors.rolesMissing);
      assertRolesAssignable(roles);
      assertCanGrant(actor.permissions, roles.flatMap((r) => r.permissionKeys));
      if (isSuper && superRole && !roles.some((r) => r.id === superRole.id) && user.isActive) {
        await this.assertNotLastSuperAdmin(superRole.id);
      }
      await this.users.replaceRoles(id, roles.map((r) => r.id));
      changes['roles'] = roles.map((r) => r.name);
    }

    if (input.status && input.status !== user.status) {
      if (input.status === 'disabled' && isSuper && superRole) await this.assertNotLastSuperAdmin(superRole.id);
      user.setStatus(input.status);
      changes['status'] = input.status;
      if (input.status === 'disabled') await this.refreshRepo.revokeAllForUser(id);
    }
    if (input.name !== undefined && input.name.trim() !== user.name) {
      user.rename(input.name);
      changes['name'] = user.name;
    }

    await this.users.save(user);
    this.perms.invalidate(id);
    await this.audit.record(auditActor(actor), AuditAction.userUpdated, { type: 'user', id }, changes);
    const roles = await this.users.getRoles(id);
    return userDto(user, roles);
  }

  private async assertNotLastSuperAdmin(superRoleId: string): Promise<void> {
    if ((await this.users.countActiveWithRole(superRoleId)) <= 1) {
      throw new InvalidStateException(Errors.lastSuperAdmin);
    }
  }
}

@injectable()
export class DeleteUserUseCase {
  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.IRoleRepository) private readonly roles: IRoleRepository,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, id: string): Promise<void> {
    if (actor.id === id) throw new ForbiddenException(Errors.selfDelete);
    const user = await loadCompanyUser(this.users, id);
    await assertCanManageUser(this.perms, actor.permissions, id);

    const superRole = await this.roles.findByName(SUPER_ADMIN_ROLE);
    if (superRole && user.isActive) {
      const roles = await this.users.getRoles(id);
      if (roles.some((r) => r.id === superRole.id) && (await this.users.countActiveWithRole(superRole.id)) <= 1) {
        throw new InvalidStateException(Errors.lastSuperAdmin);
      }
    }
    await this.users.delete(id);
    this.perms.invalidate(id);
    await this.audit.record(auditActor(actor), AuditAction.userDeleted, { type: 'user', id }, { email: user.email.value });
  }
}

@injectable()
export class SetUserPermissionOverridesUseCase {
  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.IPermissionRepository) private readonly permissions: IPermissionRepository,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, id: string, overrides: { key: string; effect: OverrideEffect }[]) {
    if (actor.id === id) throw new ForbiddenException(Errors.selfPermissionChange);
    await loadCompanyUser(this.users, id);
    await assertCanManageUser(this.perms, actor.permissions, id);

    await assertKnownPermissions(this.permissions, overrides.map((o) => o.key));
    if (new Set(overrides.map((o) => o.key)).size !== overrides.length) {
      throw new InvalidValueException(Errors.duplicateOverrides);
    }
    assertPlatformKeysAllowed(overrides.filter((o) => o.effect === 'grant').map((o) => o.key));
    assertCanGrant(actor.permissions, overrides.filter((o) => o.effect === 'grant').map((o) => o.key));

    await this.users.replaceOverrides(id, overrides);
    this.perms.invalidate(id);
    await this.audit.record(auditActor(actor), AuditAction.userPermissionsChanged, { type: 'user', id }, { overrides });
    return { overrides };
  }
}

@injectable()
export class GetUserEffectivePermissionsUseCase {
  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
  ) {}

  async execute(id: string) {
    await loadCompanyUser(this.users, id);
    return { permissions: await this.perms.getDetailed(id) };
  }
}

@injectable()
export class IssuePasswordResetUseCase {
  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.IAuthTokenRepository) private readonly authTokens: IAuthTokenRepository,
    @inject(TYPES.ITokenService) private readonly tokens: ITokenService,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
    @inject(TYPES.EnvConfig) private readonly config: EnvConfig,
  ) {}

  async execute(actor: Actor, id: string) {
    await loadCompanyUser(this.users, id);
    await assertCanManageUser(this.perms, actor.permissions, id);
    await this.authTokens.invalidateOpen('reset', { userId: id });
    const { token, hash } = this.tokens.generateOpaqueToken();
    const expiresAt = new Date(Date.now() + RESET_TTL_MS);
    await this.authTokens.create({
      purpose: 'reset',
      tokenHash: hash,
      email: null,
      userId: id,
      companyId: null,
      roleIds: [],
      expiresAt,
      createdBy: actor.id,
    });
    await this.audit.record(auditActor(actor), AuditAction.userPasswordResetIssued, { type: 'user', id });
    return { expiresAt, resetUrl: `${this.config.WEB_BASE_URL}${WebPath.resetPassword(token)}` };
  }
}

@injectable()
export class RevokeUserSessionsUseCase {
  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.IRefreshTokenRepository) private readonly refreshRepo: IRefreshTokenRepository,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, id: string): Promise<void> {
    await loadCompanyUser(this.users, id);
    if (actor.id !== id) await assertCanManageUser(this.perms, actor.permissions, id);
    await this.refreshRepo.revokeAllForUser(id);
    await this.audit.record(auditActor(actor), AuditAction.userSessionsRevoked, { type: 'user', id });
  }
}

@injectable()
export class ListUserSessionsUseCase {
  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.IRefreshTokenRepository) private readonly refreshRepo: IRefreshTokenRepository,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
  ) {}

  async execute(actor: Actor, id: string) {
    await loadCompanyUser(this.users, id);
    if (actor.id !== id) await assertCanManageUser(this.perms, actor.permissions, id);
    const sessions = await this.refreshRepo.listActiveForUser(id);
    return {
      items: sessions.map((session) => ({
        id: session.familyId,
        ip: session.ip,
        userAgent: session.userAgent,
        lastSeenAt: session.createdAt,
        expiresAt: session.expiresAt,
      })),
    };
  }
}

@injectable()
export class RevokeUserSessionUseCase {
  constructor(
    @inject(TYPES.IUserRepository) private readonly users: IUserRepository,
    @inject(TYPES.IRefreshTokenRepository) private readonly refreshRepo: IRefreshTokenRepository,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, id: string, sessionId: string): Promise<void> {
    await loadCompanyUser(this.users, id);
    if (actor.id !== id) await assertCanManageUser(this.perms, actor.permissions, id);
    await this.refreshRepo.revokeFamilyForUser(id, sessionId);
    await this.audit.record(auditActor(actor), AuditAction.userSessionsRevoked, { type: 'user', id }, { sessionId });
  }
}
