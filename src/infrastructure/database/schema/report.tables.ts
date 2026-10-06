import { sql } from 'drizzle-orm';
import { boolean, index, integer, pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core';

export const reportSchedules = pgTable('report_schedules', {
  id: uuid('id').primaryKey().defaultRandom(),
  template: text('template', { enum: ['exec', 'kev', 'sla', 'owner'] }).notNull(),
  /** limits the report to one team / owner */
  scope: text('scope'),
  freq: text('freq', { enum: ['daily', 'weekly-mon', 'weekly-fri', 'monthly'] }).notNull(),
  recipients: text('recipients').array().notNull().default(sql`'{}'::text[]`),
  formats: text('formats').array().notNull().default(sql`'{csv}'::text[]`),
  enabled: boolean('enabled').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

export const reportRuns = pgTable(
  'report_runs',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    scheduleId: uuid('schedule_id'),
    template: text('template', { enum: ['exec', 'kev', 'sla', 'owner'] }).notNull(),
    scope: text('scope'),
    formats: text('formats').array().notNull().default(sql`'{csv}'::text[]`),
    status: text('status', { enum: ['ready', 'failed', 'generating'] }).notNull().default('generating'),
    manual: boolean('manual').notNull().default(false),
    sizeBytes: integer('size_bytes'),
    /** the generated CSV body */
    content: text('content'),
    error: text('error'),
    createdBy: uuid('created_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('report_runs_at_idx').on(t.createdAt.desc())],
);
