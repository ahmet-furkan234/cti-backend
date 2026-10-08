import { sql } from 'drizzle-orm';
import { companies } from './company.table.js';
import { boolean, index, integer, jsonb, pgTable, text, timestamp, uniqueIndex, uuid } from 'drizzle-orm/pg-core';

export const assets = pgTable(
  'assets',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    companyId: uuid('company_id').notNull().references(() => companies.id, { onDelete: 'cascade' }),
    type: text('type', { enum: ['fw', 'server', 'web', 'db', 'container', 'cloud', 'laptop'] }).notNull(),
    name: text('name').notNull(),
    /** IP address or URL, depending on the type */
    addr: text('addr'),
    os: text('os'),
    env: text('env').notNull().default('prod'),
    criticality: text('criticality', { enum: ['critical', 'high', 'medium', 'low'] }).notNull().default('medium'),
    exposed: boolean('exposed').notNull().default(false),
    source: text('source').notNull().default('manual'),
    owner: text('owner'),
    tags: text('tags').array().notNull().default(sql`'{}'::text[]`),
    /** type-specific answers of the "add asset" form */
    attrs: jsonb('attrs').$type<Record<string, string | boolean>>().notNull().default({}),
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).notNull().defaultNow(),
    archivedAt: timestamp('archived_at', { withTimezone: true }),
    createdBy: uuid('created_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('assets_name_uq').on(t.companyId, sql`lower(${t.name})`),
    index('assets_company_idx').on(t.companyId),
    index('assets_type_idx').on(t.type),
    index('assets_env_idx').on(t.env),
    index('assets_seen_idx').on(t.lastSeenAt.desc()),
  ],
);

export const assetSoftware = pgTable(
  'asset_software',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    assetId: uuid('asset_id').notNull().references(() => assets.id, { onDelete: 'cascade' }),
    vendor: text('vendor'),
    product: text('product').notNull(),
    version: text('version'),
  },
  (t) => [index('asset_software_asset_idx').on(t.assetId)],
);

export const assetImports = pgTable(
  'asset_imports',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    companyId: uuid('company_id').notNull().references(() => companies.id, { onDelete: 'cascade' }),
    source: text('source').notNull(),
    kind: text('kind').notNull(),
    rows: integer('rows').notNull().default(0),
    created: integer('created').notNull().default(0),
    updated: integer('updated').notNull().default(0),
    skipped: integer('skipped').notNull().default(0),
    status: text('status', { enum: ['healthy', 'degraded', 'failing'] }).notNull().default('healthy'),
    createdBy: uuid('created_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('asset_imports_at_idx').on(t.createdAt.desc())],
);
