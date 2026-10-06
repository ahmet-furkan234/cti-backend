import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { IPermissionRepository, IRoleRepository } from '../../../domain/rbac/role.repository.interface.js';
import { PERMISSION_CATALOG, SYSTEM_ROLES } from '../../../domain/rbac/permission-catalog.js';

/** Idempotent: syncs the code-defined permission catalog and system roles. */
@injectable()
export class CatalogBootstrapService {
  constructor(
    @inject(TYPES.IPermissionRepository) private readonly permissions: IPermissionRepository,
    @inject(TYPES.IRoleRepository) private readonly roles: IRoleRepository,
  ) {}

  async run(): Promise<void> {
    const known = new Set(await this.permissions.keys());
    await this.permissions.syncCatalog(PERMISSION_CATALOG);
    // Permissions added to the catalog after a system role was created reach that role once, so existing installs
    // gain new modules without overriding what an admin later removed.
    const added = PERMISSION_CATALOG.map((p) => p.key).filter((k) => !known.has(k));

    for (const def of SYSTEM_ROLES) {
      const existing = await this.roles.findByName(def.name);
      if (!existing) {
        await this.roles.create({
          name: def.name,
          description: def.description,
          isSystem: true,
          permissionKeys: def.permissions,
        });
      } else if (def.allPermissions) {
        await this.roles.update(existing.id, { permissionKeys: def.permissions });
      } else if (known.size > 0) {
        const grant = def.permissions.filter((k) => added.includes(k) && !existing.permissionKeys.includes(k));
        if (grant.length) await this.roles.update(existing.id, { permissionKeys: [...existing.permissionKeys, ...grant] });
      }
    }
  }
}
