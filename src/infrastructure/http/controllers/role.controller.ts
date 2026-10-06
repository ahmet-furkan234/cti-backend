import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { Actor } from '../../../application/shared/actor.js';
import { CreateRoleUseCase, DeleteRoleUseCase, GetRoleUseCase, ListPermissionsUseCase, ListRolesUseCase, UpdateRoleUseCase } from '../../../application/rbac/use-cases/role.use-cases.js';

@injectable()
export class RoleController {
  constructor(
    @inject(TYPES.ListRolesUseCase) private readonly list_: ListRolesUseCase,
    @inject(TYPES.GetRoleUseCase) private readonly get_: GetRoleUseCase,
    @inject(TYPES.CreateRoleUseCase)
    private readonly create_: CreateRoleUseCase,
    @inject(TYPES.UpdateRoleUseCase)
    private readonly update_: UpdateRoleUseCase,
    @inject(TYPES.DeleteRoleUseCase)
    private readonly delete_: DeleteRoleUseCase,
    @inject(TYPES.ListPermissionsUseCase)
    private readonly permissions_: ListPermissionsUseCase,
  ) {}

  list() {
    return this.list_.execute();
  }
  get(id: string) {
    return this.get_.execute(id);
  }
  create(
    a: Actor,
    b: { name: string; description: string; permissionKeys: string[] },
  ) {
    return this.create_.execute(a, b);
  }
  update(
    a: Actor,
    id: string,
    b: {
      name?: string | undefined;
      description?: string | undefined;
      permissionKeys?: string[] | undefined;
    },
  ) {
    return this.update_.execute(a, id, {
      ...(b.name !== undefined ? { name: b.name } : {}),
      ...(b.description !== undefined ? { description: b.description } : {}),
      ...(b.permissionKeys !== undefined
        ? { permissionKeys: b.permissionKeys }
        : {}),
    });
  }
  delete(a: Actor, id: string) {
    return this.delete_.execute(a, id);
  }
  permissions() {
    return this.permissions_.execute();
  }
}
