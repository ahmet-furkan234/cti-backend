import { and, count, eq, ilike, inArray, or, sql, type SQL } from 'drizzle-orm';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { User } from '../../../domain/user/user.entity.js';
import type { Email } from '../../../domain/common/value-objects/email.value-object.js';
import type {
  IUserRepository, ListUsersQuery, UserListItem, UserRoleRef,
} from '../../../domain/user/user.repository.interface.js';
import type { PermissionOverride, RoleGrant } from '../../../domain/rbac/effective-permissions.js';
import { tenant } from '../../../shared/tenant.js';
import type { Database } from '../client.js';
import { rolePermissions, roles, userPermissions, userRoles, users } from '../schema/index.js';

type Row = typeof users.$inferSelect;

const toEntity = (r: Row): User =>
  new User({
    id: r.id, companyId: r.companyId, email: r.email, name: r.name, passwordHash: r.passwordHash, status: r.status,
    failedLoginAttempts: r.failedLoginAttempts, lockedUntil: r.lockedUntil, lastLoginAt: r.lastLoginAt,
    createdAt: r.createdAt, updatedAt: r.updatedAt,
  });

const toRow = (u: User) => ({
  email: u.email.value, name: u.name, passwordHash: u.passwordHash, status: u.status,
  failedLoginAttempts: u.failedLoginAttempts, lockedUntil: u.lockedUntil, lastLoginAt: u.lastLoginAt,
  updatedAt: u.updatedAt,
});

@injectable()
export class UserRepository implements IUserRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  async findById(id: string) {
    const [r] = await this.db.select().from(users).where(eq(users.id, id)).limit(1);
    return r ? toEntity(r) : null;
  }

  async findByEmail(email: Email) {
    const [r] = await this.db.select().from(users).where(eq(users.email, email.value)).limit(1);
    return r ? toEntity(r) : null;
  }

  async create(user: User) {
    await this.db.insert(users).values({ id: user.id, companyId: user.companyId, createdAt: user.createdAt, ...toRow(user) });
  }

  async save(user: User) {
    await this.db.update(users).set(toRow(user)).where(eq(users.id, user.id));
  }

  async delete(id: string) {
    await this.db.delete(users).where(eq(users.id, id));
  }

  async count() {
    const [r] = await this.db.select({ n: count() }).from(users);
    return r?.n ?? 0;
  }

  async list(q: ListUsersQuery): Promise<{ items: UserListItem[]; total: number }> {
    const conds: (SQL | undefined)[] = [eq(users.companyId, tenant.id())];
    if (q.q) {
      const like = `%${q.q.replace(/[%_\\]/g, '\\$&')}%`;
      conds.push(or(ilike(users.email, like), ilike(users.name, like)));
    }
    if (q.status) conds.push(eq(users.status, q.status));
    if (q.roleId) {
      conds.push(sql`exists (select 1 from ${userRoles} ur where ur.user_id = ${users.id} and ur.role_id = ${q.roleId})`);
    }
    const where = conds.length ? and(...conds) : undefined;

    const [rows, [totalRow]] = await Promise.all([
      this.db.select().from(users).where(where).orderBy(users.createdAt).limit(q.pageSize).offset((q.page - 1) * q.pageSize),
      this.db.select({ n: count() }).from(users).where(where),
    ]);
    if (rows.length === 0) return { items: [], total: totalRow?.n ?? 0 };

    const roleRows = await this.db
      .select({ userId: userRoles.userId, id: roles.id, name: roles.name })
      .from(userRoles)
      .innerJoin(roles, eq(roles.id, userRoles.roleId))
      .where(inArray(userRoles.userId, rows.map((r) => r.id)));
    const byUser = new Map<string, UserRoleRef[]>();
    for (const r of roleRows) byUser.set(r.userId, [...(byUser.get(r.userId) ?? []), { id: r.id, name: r.name }]);

    return {
      items: rows.map((r) => ({ user: toEntity(r), roles: byUser.get(r.id) ?? [] })),
      total: totalRow?.n ?? 0,
    };
  }

  async getRoles(userId: string): Promise<UserRoleRef[]> {
    return this.db
      .select({ id: roles.id, name: roles.name })
      .from(userRoles)
      .innerJoin(roles, eq(roles.id, userRoles.roleId))
      .where(eq(userRoles.userId, userId));
  }

  async replaceRoles(userId: string, roleIds: string[]) {
    await this.db.transaction(async (tx) => {
      await tx.delete(userRoles).where(eq(userRoles.userId, userId));
      if (roleIds.length) await tx.insert(userRoles).values(roleIds.map((roleId) => ({ userId, roleId })));
    });
  }

  async countActiveWithRole(roleId: string) {
    const [r] = await this.db
      .select({ n: count() })
      .from(userRoles)
      .innerJoin(users, eq(users.id, userRoles.userId))
      .where(and(eq(userRoles.roleId, roleId), eq(users.status, 'active')));
    return r?.n ?? 0;
  }

  async getRoleGrants(userId: string): Promise<RoleGrant[]> {
    return this.db
      .select({ key: rolePermissions.permissionKey, roleName: roles.name })
      .from(userRoles)
      .innerJoin(roles, eq(roles.id, userRoles.roleId))
      .innerJoin(rolePermissions, eq(rolePermissions.roleId, userRoles.roleId))
      .where(eq(userRoles.userId, userId));
  }

  async getOverrides(userId: string): Promise<PermissionOverride[]> {
    return this.db
      .select({ key: userPermissions.permissionKey, effect: userPermissions.effect })
      .from(userPermissions)
      .where(eq(userPermissions.userId, userId));
  }

  async replaceOverrides(userId: string, overrides: PermissionOverride[]) {
    await this.db.transaction(async (tx) => {
      await tx.delete(userPermissions).where(eq(userPermissions.userId, userId));
      if (overrides.length) {
        await tx.insert(userPermissions).values(
          overrides.map((o) => ({ userId, permissionKey: o.key, effect: o.effect })),
        );
      }
    });
  }
}
