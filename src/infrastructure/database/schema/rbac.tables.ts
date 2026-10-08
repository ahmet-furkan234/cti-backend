import { sql } from 'drizzle-orm';
import { boolean, index, pgTable, primaryKey, text, timestamp, uniqueIndex, uuid } from 'drizzle-orm/pg-core';
import { companies } from './company.table.js';
import { users } from './users.table.js';

export const roles = pgTable(
  'roles',
  {
  id: uuid('id').primaryKey().defaultRandom(),
  /** null = system role shared by every company; otherwise a custom role of that company */
  companyId: uuid('company_id').references(() => companies.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  description: text('description').notNull().default(''),
  isSystem: boolean('is_system').notNull().default(false),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex('roles_scope_name_uq').on(sql`coalesce(${t.companyId}::text, '')`, t.name)],
);

export const permissions = pgTable('permissions', {
  key: text('key').primaryKey(),
  module: text('module').notNull(),
  description: text('description').notNull().default(''),
});

export const rolePermissions = pgTable(
  'role_permissions',
  {
    roleId: uuid('role_id').notNull().references(() => roles.id, { onDelete: 'cascade' }),
    permissionKey: text('permission_key').notNull().references(() => permissions.key, { onDelete: 'cascade' }),
  },
  (t) => [primaryKey({ columns: [t.roleId, t.permissionKey] })],
);

export const userRoles = pgTable(
  'user_roles',
  {
    userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    roleId: uuid('role_id').notNull().references(() => roles.id, { onDelete: 'restrict' }),
  },
  (t) => [primaryKey({ columns: [t.userId, t.roleId] }), index('user_roles_role_idx').on(t.roleId)],
);

export const userPermissions = pgTable(
  'user_permissions',
  {
    userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    permissionKey: text('permission_key').notNull().references(() => permissions.key, { onDelete: 'cascade' }),
    effect: text('effect', { enum: ['grant', 'deny'] }).notNull(),
  },
  (t) => [primaryKey({ columns: [t.userId, t.permissionKey] })],
);
