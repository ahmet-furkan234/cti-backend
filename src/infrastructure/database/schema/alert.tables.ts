import { sql } from 'drizzle-orm';
import { companies } from './company.table.js';
import { boolean, index, integer, jsonb, pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core';

export const alertChannels = pgTable('alert_channels', {
  id: uuid('id').primaryKey().defaultRandom(),
  companyId: uuid('company_id').notNull().references(() => companies.id, { onDelete: 'cascade' }),
  kind: text('kind', { enum: ['slack', 'smtp', 'telegram', 'webhook'] }).notNull(),
  name: text('name').notNull(),
  /** field id → value; the fields per kind are defined by the web app */
  values: jsonb('values').$type<Record<string, string>>().notNull().default({}),
  status: text('status', { enum: ['healthy', 'degraded', 'failing'] }).notNull().default('healthy'),
  problem: text('problem'),
  lastTestAt: timestamp('last_test_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const alertRules = pgTable('alert_rules', {
  id: uuid('id').primaryKey().defaultRandom(),
  companyId: uuid('company_id').notNull().references(() => companies.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  trigger: text('trigger', { enum: ['kev', 'critical', 'sla', 'epss', 'sync', 'digest'] }).notNull(),
  envs: text('envs').array().notNull().default(sql`'{}'::text[]`),
  minRisk: integer('min_risk').notNull().default(0),
  exposedOnly: boolean('exposed_only').notNull().default(false),
  tag: text('tag').notNull().default(''),
  channelIds: uuid('channel_ids').array().notNull().default(sql`'{}'::uuid[]`),
  throttle: text('throttle', { enum: ['every', 'asset6h', 'daily'] }).notNull().default('every'),
  enabled: boolean('enabled').notNull().default(true),
  lastFiredAt: timestamp('last_fired_at', { withTimezone: true }),
  /** watermark: matches first seen before this have already been looked at */
  evaluatedAt: timestamp('evaluated_at', { withTimezone: true }).notNull().defaultNow(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const alertLog = pgTable(
  'alert_log',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    companyId: uuid('company_id').notNull().references(() => companies.id, { onDelete: 'cascade' }),
    ruleId: uuid('rule_id'),
    assetId: uuid('asset_id'),
    channelIds: uuid('channel_ids').array().notNull().default(sql`'{}'::uuid[]`),
    result: text('result', { enum: ['sent', 'throttled', 'failed'] }).notNull(),
    detail: text('detail').notNull().default(''),
    at: timestamp('at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('alert_log_at_idx').on(t.at.desc())],
);

