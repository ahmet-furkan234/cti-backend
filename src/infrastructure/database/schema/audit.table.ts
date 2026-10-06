import { index, jsonb, pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core';

// No FK on actor: history must survive user deletion.
export const auditLog = pgTable(
  'audit_log',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    actorId: uuid('actor_id'),
    actorEmail: text('actor_email'),
    action: text('action').notNull(),
    targetType: text('target_type'),
    targetId: text('target_id'),
    meta: jsonb('meta').$type<Record<string, unknown>>().notNull().default({}),
    ip: text('ip'),
    at: timestamp('at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index('audit_at_idx').on(t.at.desc(), t.id.desc()),
    index('audit_actor_idx').on(t.actorId, t.at.desc()),
    index('audit_action_idx').on(t.action, t.at.desc()),
  ],
);
