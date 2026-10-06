import type { Email } from '../common/value-objects/email.value-object.js';
import type { User, UserStatus } from './user.entity.js';
import type { PermissionOverride, RoleGrant } from '../rbac/effective-permissions.js';

export interface UserRoleRef {
  id: string;
  name: string;
}

export interface UserListItem {
  user: User;
  roles: UserRoleRef[];
}

export interface ListUsersQuery {
  q?: string | undefined;
  status?: UserStatus | undefined;
  roleId?: string | undefined;
  page: number;
  pageSize: number;
}

export interface IUserRepository {
  findById(id: string): Promise<User | null>;
  findByEmail(email: Email): Promise<User | null>;
  create(user: User): Promise<void>;
  save(user: User): Promise<void>;
  delete(id: string): Promise<void>;
  list(query: ListUsersQuery): Promise<{ items: UserListItem[]; total: number }>;
  count(): Promise<number>;

  getRoles(userId: string): Promise<UserRoleRef[]>;
  replaceRoles(userId: string, roleIds: string[]): Promise<void>;
  /** Number of ACTIVE users holding the given role. */
  countActiveWithRole(roleId: string): Promise<number>;

  getRoleGrants(userId: string): Promise<RoleGrant[]>;
  getOverrides(userId: string): Promise<PermissionOverride[]>;
  replaceOverrides(userId: string, overrides: PermissionOverride[]): Promise<void>;
}
