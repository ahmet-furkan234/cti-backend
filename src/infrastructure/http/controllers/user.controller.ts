import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { Actor } from '../../../application/shared/actor.js';
import type { OverrideEffect } from '../../../domain/rbac/effective-permissions.js';
import type { UserStatus } from '../../../domain/user/user.entity.js';
import { DeleteUserUseCase, GetUserEffectivePermissionsUseCase, GetUserUseCase, InviteUserUseCase, IssuePasswordResetUseCase, ListUsersUseCase, RevokeUserSessionsUseCase, SetUserPermissionOverridesUseCase, UpdateUserUseCase } from '../../../application/user/use-cases/user.use-cases.js';

@injectable()
export class UserController {
  constructor(
    @inject(TYPES.ListUsersUseCase) private readonly list_: ListUsersUseCase,
    @inject(TYPES.GetUserUseCase) private readonly get_: GetUserUseCase,
    @inject(TYPES.InviteUserUseCase)
    private readonly invite_: InviteUserUseCase,
    @inject(TYPES.UpdateUserUseCase)
    private readonly update_: UpdateUserUseCase,
    @inject(TYPES.DeleteUserUseCase)
    private readonly delete_: DeleteUserUseCase,
    @inject(TYPES.SetUserPermissionOverridesUseCase)
    private readonly overrides_: SetUserPermissionOverridesUseCase,
    @inject(TYPES.GetUserEffectivePermissionsUseCase)
    private readonly effective_: GetUserEffectivePermissionsUseCase,
    @inject(TYPES.IssuePasswordResetUseCase)
    private readonly reset_: IssuePasswordResetUseCase,
    @inject(TYPES.RevokeUserSessionsUseCase)
    private readonly revoke_: RevokeUserSessionsUseCase,
  ) {}

  //TODO : Parametreleri bu şekilde alınmıcak daha temiz bir yapı olucak
  list(q: {
    q?: string | undefined;
    status?: UserStatus | undefined;
    roleId?: string | undefined;
    page: number;
    pageSize: number;
  }) {
    return this.list_.execute(q);
  }
  get(id: string) {
    return this.get_.execute(id);
  }
  invite(a: Actor, b: { email: string; roleIds: string[] }) {
    return this.invite_.execute(a, b);
  }
  update(
    a: Actor,
    id: string,
    b: {
      name?: string | undefined;
      status?: UserStatus | undefined;
      roleIds?: string[] | undefined;
    },
  ) {
    return this.update_.execute(a, id, {
      ...(b.name !== undefined ? { name: b.name } : {}),
      ...(b.status !== undefined ? { status: b.status } : {}),
      ...(b.roleIds !== undefined ? { roleIds: b.roleIds } : {}),
    }); //TODO burda validator yapsıı yazıcaz ancak daha önceden tarşalım bunu
  }
  delete(a: Actor, id: string) {
    return this.delete_.execute(a, id);
  }
  setOverrides(
    a: Actor,
    id: string,
    o: { key: string; effect: OverrideEffect }[],
  ) {
    return this.overrides_.execute(a, id, o);
  }
  effective(id: string) {
    return this.effective_.execute(id);
  }
  issueReset(a: Actor, id: string) {
    return this.reset_.execute(a, id);
  }
  revokeSessions(a: Actor, id: string) {
    return this.revoke_.execute(a, id);
  }
}
