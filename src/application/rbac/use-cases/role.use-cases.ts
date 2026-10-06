import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { IPermissionRepository, IRoleRepository } from '../../../domain/rbac/role.repository.interface.js';
import { PermissionKey } from '../../../domain/common/value-objects/permission-key.value-object.js';
import { RoleName } from '../../../domain/common/value-objects/role-name.value-object.js';
import { SUPER_ADMIN_ROLE } from '../../../domain/rbac/permission-catalog.js';
import {
  AlreadyExistsException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '../../../domain/common/exceptions.js';
import { EffectivePermissionService } from '../services/effective-permission.service.js';
import { assertCanGrant, assertKnownPermissions } from '../../shared/access-guard.js';
import { AuditService } from '../../audit/audit.service.js';
import { auditActor, type Actor } from '../../shared/actor.js';
import { AuditAction, Entity, Errors } from '../../../shared/strings.js';

@injectable()
export class ListRolesUseCase {
  constructor(@inject(TYPES.IRoleRepository) private readonly roles: IRoleRepository) {}
  execute() {
    return this.roles.list();
  }
}

@injectable()
export class GetRoleUseCase {
  constructor(@inject(TYPES.IRoleRepository) private readonly roles: IRoleRepository) {}
  async execute(id: string) {
    const role = await this.roles.findById(id);
    if (!role) throw new NotFoundException(Entity.role);
    return role;
  }
}

@injectable()
export class ListPermissionsUseCase {
  constructor(@inject(TYPES.IPermissionRepository) private readonly permissions: IPermissionRepository) {}
  execute() {
    return this.permissions.list();
  }
}

@injectable()
export class CreateRoleUseCase {
  constructor(
    @inject(TYPES.IRoleRepository) private readonly roles: IRoleRepository,
    @inject(TYPES.IPermissionRepository) private readonly permissions: IPermissionRepository,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, input: { name: string; description: string; permissionKeys: string[] }) {
    const name = RoleName.from(input.name).value;
    if (await this.roles.findByName(name)) throw new AlreadyExistsException(Entity.role, 'name');
    const keys = PermissionKey.fromAll(input.permissionKeys).map((k) => k.value);
    await assertKnownPermissions(this.permissions, keys);
    assertCanGrant(actor.permissions, keys);

    const role = await this.roles.create({ name, description: input.description, permissionKeys: keys });
    await this.audit.record(auditActor(actor), AuditAction.roleCreated, { type: 'role', id: role.id }, { name, permissions: keys });
    return role;
  }
}

@injectable()
export class UpdateRoleUseCase {
  constructor(
    @inject(TYPES.IRoleRepository) private readonly roles: IRoleRepository,
    @inject(TYPES.IPermissionRepository) private readonly permissions: IPermissionRepository,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, id: string, input: { name?: string; description?: string; permissionKeys?: string[] }) {
    const role = await this.roles.findById(id);
    if (!role) throw new NotFoundException(Entity.role);

    if (role.isSystem && input.name !== undefined && RoleName.from(input.name).value !== role.name) {
      throw new ForbiddenException(Errors.systemRoleNameImmutable);
    }
    if (role.name === SUPER_ADMIN_ROLE && input.permissionKeys) {
      throw new ForbiddenException(Errors.superAdminPermissionsImmutable);
    }
    const patch: { name?: string; description?: string; permissionKeys?: string[] } = {};
    if (input.name !== undefined && !role.isSystem) {
      const name = RoleName.from(input.name).value;
      const clash = await this.roles.findByName(name);
      if (clash && clash.id !== id) throw new AlreadyExistsException(Entity.role, 'name');
      patch.name = name;
    }
    if (input.description !== undefined) patch.description = input.description;

    let diff: { added: string[]; removed: string[] } | undefined;
    if (input.permissionKeys) {
      const keys = PermissionKey.fromAll(input.permissionKeys).map((k) => k.value);
      await assertKnownPermissions(this.permissions, keys);
      const added = keys.filter((k) => !role.permissionKeys.includes(k));
      // An actor may only ADD permissions they hold themselves.
      assertCanGrant(actor.permissions, added);
      patch.permissionKeys = keys;
      diff = { added, removed: role.permissionKeys.filter((k) => !keys.includes(k)) };
    }

    const updated = await this.roles.update(id, patch);
    if (diff) this.perms.invalidateMany(await this.roles.memberIds(id));
    await this.audit.record(auditActor(actor), AuditAction.roleUpdated, { type: 'role', id }, { ...patch, diff });
    return updated;
  }
}

@injectable()
export class DeleteRoleUseCase {
  constructor(
    @inject(TYPES.IRoleRepository) private readonly roles: IRoleRepository,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async execute(actor: Actor, id: string): Promise<void> {
    const role = await this.roles.findById(id);
    if (!role) throw new NotFoundException(Entity.role);
    if (role.isSystem) throw new ForbiddenException(Errors.systemRoleUndeletable);
    if (role.memberCount > 0) {
      throw new ConflictException(Errors.roleInUse(role.memberCount));
    }
    await this.roles.delete(id);
    this.perms.invalidateAll();
    await this.audit.record(auditActor(actor), AuditAction.roleDeleted, { type: 'role', id }, { name: role.name });
  }
}
