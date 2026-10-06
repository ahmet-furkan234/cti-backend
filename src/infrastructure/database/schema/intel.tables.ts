import { sql } from 'drizzle-orm';
import { boolean, index, integer, pgTable, real, text, timestamp, uniqueIndex, uuid } from 'drizzle-orm/pg-core';

export const watchlists = pgTable('watchlists', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  vendors: text('vendors').array().notNull().default(sql`'{}'::text[]`),
  products: text('products').array().notNull().default(sql`'{}'::text[]`),
  tag: text('tag').notNull().default(''),
  minCvss: real('min_cvss').notNull().default(0),
  kevOnly: boolean('kev_only').notNull().default(false),
  /** percent, 0 = any */
  minEpss: integer('min_epss').notNull().default(0),
  channelId: uuid('channel_id'),
  enabled: boolean('enabled').notNull().default(true),
  /** watermark: findings first seen before this were already announced */
  evaluatedAt: timestamp('evaluated_at', { withTimezone: true }).notNull().defaultNow(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const iocs = pgTable(
  'iocs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    type: text('type', { enum: ['ipv4', 'ipv6', 'cidr', 'domain', 'url', 'email', 'sha256', 'sha1', 'md5'] }).notNull(),
    value: text('value').notNull(),
    source: text('source').notNull().default('Manual'),
    confidence: integer('confidence').notNull().default(50),
    expiresAt: timestamp('expires_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex('iocs_uq').on(t.type, t.value), index('iocs_type_idx').on(t.type)],
);
