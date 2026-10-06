import { index, pgTable, text, timestamp, uniqueIndex, uuid } from 'drizzle-orm/pg-core';
import { assets } from './inventory.tables.js';

/** CVE × asset matches produced from the inventory against the CVE database. */
export const assetVulns = pgTable(
  'asset_vulns',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    assetId: uuid('asset_id').notNull().references(() => assets.id, { onDelete: 'cascade' }),
    cveId: text('cve_id').notNull(),
    /** the matched component, "vendor:product" */
    component: text('component').notNull(),
    installedVersion: text('installed_version'),
    fixedVersion: text('fixed_version'),
    status: text('status', { enum: ['open', 'in_progress', 'accepted', 'mitigated'] }).notNull().default('open'),
    firstSeenAt: timestamp('first_seen_at', { withTimezone: true }).notNull().defaultNow(),
    statusChangedAt: timestamp('status_changed_at', { withTimezone: true }),
    statusChangedBy: uuid('status_changed_by'),
  },
  (t) => [
    uniqueIndex('asset_vulns_uq').on(t.assetId, t.cveId, t.component),
    index('asset_vulns_cve_idx').on(t.cveId),
    index('asset_vulns_status_idx').on(t.status),
  ],
);
