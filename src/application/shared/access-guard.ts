import type { IPermissionRepository, Role } from '../../domain/rbac/role.repository.interface.js';
import type { IUserRepository } from '../../domain/user/user.repository.interface.js';
import type { User } from '../../domain/user/user.entity.js';
import { PLATFORM_ONLY_ROLES, isPlatformOnlyPermission } from '../../domain/rbac/permission-catalog.js';
import { tenant } from '../../shared/tenant.js';
import { PermissionKey } from '../../domain/common/value-objects/permission-key.value-object.js';
import { ForbiddenException, InvalidValueException, NotFoundException } from '../../domain/common/exceptions.js';
import { allowedKeys } from '../../domain/rbac/effective-permissions.js';
import type { EffectivePermissionService } from '../rbac/services/effective-permission.service.js';
import { Entity, Errors } from '../../shared/strings.js';

/** Prevents privilege escalation: an actor can only hand out what they hold. */
export function assertCanGrant(actorPermissions: string[], keys: string[]): void {
  const held = new Set(actorPermissions);
  const missing = keys.filter((k) => !held.has(k));
  if (missing.length > 0) {
    throw new ForbiddenException(Errors.privilegeEscalation(missing));
  }
}

/**
 * An actor may only manage users whose permissions are a subset of their own;
 * otherwise an `admin` could reset the password of (and take over) a `super_admin`.
 */
export async function assertCanManageUser(
  perms: EffectivePermissionService,
  actorPermissions: string[],
  targetUserId: string,
): Promise<void> {
  const target = allowedKeys(await perms.getDetailed(targetUserId));
  const held = new Set(actorPermissions);
  if (target.some((k) => !held.has(k))) {
    throw new ForbiddenException(Errors.insufficientPrivilege);
  }
}

/** Rejects permission keys that are not part of the catalog stored in the database. */
export async function assertKnownPermissions(repo: IPermissionRepository, keys: string[]): Promise<void> {
  PermissionKey.fromAll(keys); // rejects malformed keys before hitting the catalog
  const known = new Set(await repo.keys());
  const unknown = keys.filter((k) => !known.has(k));
  if (unknown.length) throw new InvalidValueException(Errors.unknownPermissions(unknown));
}

/** A user of another company does not exist as far as this company is concerned. */
export async function loadCompanyUser(users: IUserRepository, id: string): Promise<User> {
  const user = await users.findById(id);
  if (!user || user.companyId !== tenant.id()) throw new NotFoundException(Entity.user);
  return user;
}

/** Platform-level permissions (company management) can only exist inside the main company. */
export function assertPlatformKeysAllowed(keys: string[]): void {
  const platformKeys = keys.filter(isPlatformOnlyPermission);
  if (platformKeys.length > 0 && !tenant.require().platform) throw new ForbiddenException(Errors.platformPermissionsOnly(platformKeys));
}

/** Roles reserved for the platform company cannot be handed to another company's users. */
export function assertRolesAssignable(roles: Pick<Role, 'name' | 'permissionKeys'>[]): void {
  if (tenant.require().platform) return;
  const reserved = roles.find((r) => PLATFORM_ONLY_ROLES.includes(r.name) || r.permissionKeys.some(isPlatformOnlyPermission));
  if (reserved) throw new ForbiddenException(Errors.platformRoleOnly(reserved.name));
}
