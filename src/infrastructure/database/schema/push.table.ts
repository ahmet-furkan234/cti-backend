import { index, pgTable, text, timestamp, uuid } from 'drizzle-orm/pg-core';
import { companies } from './company.table.js';
import { users } from './users.table.js';

/** FCM registration tokens of the mobile app installs that signed in as a user. One token = one install. */
export const pushDevices = pgTable(
  'push_devices',
  {
    token: text('token').primaryKey(),
    userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    companyId: uuid('company_id').notNull().references(() => companies.id, { onDelete: 'cascade' }),
    platform: text('platform', { enum: ['ios', 'android'] }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index('push_devices_company_idx').on(t.companyId), index('push_devices_user_idx').on(t.userId)],
);
