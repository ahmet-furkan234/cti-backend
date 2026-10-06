import type { IPermissionRepository } from '../../domain/rbac/role.repository.interface.js';
import { PermissionKey } from '../../domain/common/value-objects/permission-key.value-object.js';
import { ForbiddenException, InvalidValueException } from '../../domain/common/exceptions.js';
import { allowedKeys } from '../../domain/rbac/effective-permissions.js';
import type { EffectivePermissionService } from '../rbac/services/effective-permission.service.js';
import { Errors } from '../../shared/strings.js';

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
