import { and, count, eq, inArray, isNull, or, sql, type SQL } from 'drizzle-orm';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type {
  IPermissionRepository, IRoleRepository, Permission, Role,
} from '../../../domain/rbac/role.repository.interface.js';
import { tenant } from '../../../shared/tenant.js';
import type { Database } from '../client.js';
import { permissions, rolePermissions, roles, userRoles, users } from '../schema/index.js';

/** What the current company can see and use: the shared system roles plus its own custom roles (system roles only, outside a company). */
const visible = (): SQL => {
  const scope = tenant.current();
  return scope ? or(isNull(roles.companyId), eq(roles.companyId, scope.companyId))! : isNull(roles.companyId);
};

@injectable()
export class RoleRepository implements IRoleRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  private async hydrate(rows: (typeof roles.$inferSelect)[]): Promise<Role[]> {
    if (rows.length === 0) return [];
    const ids = rows.map((r) => r.id);
    const [perms, members] = await Promise.all([
      this.db.select().from(rolePermissions).where(inArray(rolePermissions.roleId, ids)),
      // Members are counted inside the current company: a shared system role is held by users of many companies.
      this.db
        .select({ roleId: userRoles.roleId, n: count() })
        .from(userRoles)
        .innerJoin(users, eq(users.id, userRoles.userId))
        .where(and(inArray(userRoles.roleId, ids), tenant.current() ? eq(users.companyId, tenant.id()) : undefined))
        .groupBy(userRoles.roleId),
    ]);
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      isSystem: r.isSystem,
      companyId: r.companyId,
      permissionKeys: perms.filter((p) => p.roleId === r.id).map((p) => p.permissionKey).sort(),
      memberCount: members.find((m) => m.roleId === r.id)?.n ?? 0,
      createdAt: r.createdAt,
      updatedAt: r.updatedAt,
    }));
  }

  async list() {
    return this.hydrate(await this.db.select().from(roles).where(visible()).orderBy(roles.name));
  }

  async findById(id: string) {
    return (await this.hydrate(await this.db.select().from(roles).where(and(eq(roles.id, id), visible())).limit(1)))[0] ?? null;
  }

  async findByIds(ids: string[]) {
    if (ids.length === 0) return [];
    return this.hydrate(await this.db.select().from(roles).where(and(inArray(roles.id, ids), visible())));
  }

  async findByName(name: string) {
    return (await this.hydrate(await this.db.select().from(roles).where(and(eq(roles.name, name), visible())).limit(1)))[0] ?? null;
  }

  async create(input: { name: string; description: string; isSystem?: boolean; permissionKeys: string[] }) {
    const id = await this.db.transaction(async (tx) => {
      const [row] = await tx
        .insert(roles)
        .values({
          name: input.name, description: input.description, isSystem: input.isSystem ?? false,
          // System roles are shared; custom roles belong to the company that creates them.
          companyId: input.isSystem ? null : tenant.id(),
        })
        .returning({ id: roles.id });
      if (input.permissionKeys.length) {
        await tx.insert(rolePermissions).values(input.permissionKeys.map((k) => ({ roleId: row!.id, permissionKey: k })));
      }
      return row!.id;
    });
    return (await this.findById(id))!;
  }

  async update(id: string, input: { name?: string; description?: string; permissionKeys?: string[] }) {
    await this.db.transaction(async (tx) => {
      const patch: Partial<typeof roles.$inferInsert> = { updatedAt: new Date() };
      if (input.name !== undefined) patch.name = input.name;
      if (input.description !== undefined) patch.description = input.description;
      await tx.update(roles).set(patch).where(eq(roles.id, id));
      if (input.permissionKeys) {
        await tx.delete(rolePermissions).where(eq(rolePermissions.roleId, id));
        if (input.permissionKeys.length) {
          await tx.insert(rolePermissions).values(input.permissionKeys.map((k) => ({ roleId: id, permissionKey: k })));
        }
      }
    });
    return (await this.findById(id))!;
  }

  async delete(id: string) {
    await this.db.delete(roles).where(eq(roles.id, id));
  }

  async memberIds(roleId: string) {
    const rows = await this.db.select({ id: userRoles.userId }).from(userRoles).where(eq(userRoles.roleId, roleId));
    return rows.map((r) => r.id);
  }
}

@injectable()
export class PermissionRepository implements IPermissionRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  async list(): Promise<Permission[]> {
    return this.db.select().from(permissions).orderBy(permissions.module, permissions.key);
  }

  async keys() {
    return (await this.db.select({ key: permissions.key }).from(permissions)).map((r) => r.key);
  }

  async syncCatalog(items: Permission[]) {
    if (items.length === 0) return;
    await this.db
      .insert(permissions)
      .values(items)
      .onConflictDoUpdate({
        target: permissions.key,
        set: { module: sql`excluded.module`, description: sql`excluded.description` },
      });
    // Permissions removed from the code catalog disappear (cascades off roles/overrides).
    await this.db.delete(permissions).where(
      sql`${permissions.key} not in (${sql.join(items.map((i) => sql`${i.key}`), sql`, `)})`,
    );
  }
}
