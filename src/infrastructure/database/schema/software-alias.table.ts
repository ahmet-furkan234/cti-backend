import { sql } from 'drizzle-orm';
import { companies } from './company.table.js';
import { pgTable, text, timestamp, uniqueIndex, uuid } from 'drizzle-orm/pg-core';

/** Names the team uses for software ("Our ERP") mapped to the product the CVE data knows ("vendor:product"). */
export const softwareAliases = pgTable(
  'software_aliases',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    companyId: uuid('company_id').notNull().references(() => companies.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    pair: text('pair').notNull(),
    createdBy: uuid('created_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [uniqueIndex('software_aliases_name_uq').on(t.companyId, sql`lower(${t.name})`)],
);
