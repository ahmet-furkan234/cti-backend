import { boolean, pgTable, text, timestamp, uniqueIndex, uuid } from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';

/** A tenant. Exactly one company is the platform owner ("main company"); it manages all the others. */
export const companies = pgTable(
  'companies',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull(),
    isPlatform: boolean('is_platform').notNull().default(false),
    status: text('status', { enum: ['active', 'suspended'] }).notNull().default('active'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex('companies_name_uq').on(sql`lower(${t.name})`),
    uniqueIndex('companies_one_platform_uq').on(t.isPlatform).where(sql`${t.isPlatform}`),
  ],
);
