import { sql } from 'drizzle-orm';
import {
  boolean, customType, index, jsonb, pgTable, real, smallint, text, timestamp,
} from 'drizzle-orm/pg-core';

const tsvector = customType<{ data: string }>({ dataType: () => 'tsvector' });

export const cve = pgTable(
  'cve',
  {
    id: text('id').primaryKey(),
    published: timestamp('published', { withTimezone: true }).notNull(),
    lastModified: timestamp('last_modified', { withTimezone: true }).notNull(),
    vulnStatus: text('vuln_status'),
    description: text('description').notNull().default(''),
    // Unscored CVEs store 0 so keyset sorting never has to deal with NULLs.
    cvssScore: real('cvss_score').notNull().default(0),
    cvssSeverity: smallint('cvss_severity').notNull().default(0),
    cvssVector: text('cvss_vector'),
    cvssVersion: text('cvss_version'),
    cwe: text('cwe').array().notNull().default(sql`'{}'::text[]`),
    isKev: boolean('is_kev').notNull().default(false),
    kevAdded: timestamp('kev_added', { withTimezone: true }),
    kevDueDate: timestamp('kev_due_date', { withTimezone: true }),
    kevRansomware: boolean('kev_ransomware').notNull().default(false),
    epss: real('epss').notNull().default(0),
    epssPercentile: real('epss_percentile').notNull().default(0),
    references: jsonb('references').notNull().default(sql`'[]'::jsonb`),
    /** lowercase "vendor:product" pairs from CPE matches */
    affected: text('affected').array().notNull().default(sql`'{}'::text[]`),
    vendors: text('vendors').array().notNull().default(sql`'{}'::text[]`),
    /** Compact vulnerable CPE matches with version ranges (input for asset matching, phase 2). */
    cpeMatches: jsonb('cpe_matches').notNull().default(sql`'[]'::jsonb`),
    searchVec: tsvector('search_vec').generatedAlwaysAs(
      sql`to_tsvector('english', id || ' ' || coalesce(description, ''))`,
    ),
  },
  (t) => [
    index('cve_id_pattern_idx').using('btree', t.id.op('text_pattern_ops')),
    index('cve_search_vec_idx').using('gin', t.searchVec),
    index('cve_description_trgm_idx').using('gin', t.description.op('gin_trgm_ops')),
    index('cve_published_idx').on(t.published.desc(), t.id.desc()),
    index('cve_modified_idx').on(t.lastModified.desc(), t.id.desc()),
    index('cve_cvss_idx').on(t.cvssScore.desc(), t.id.desc()),
    index('cve_epss_idx').on(t.epss.desc(), t.id.desc()),
    index('cve_kev_idx').on(t.kevAdded.desc(), t.id.desc()).where(sql`${t.isKev}`),
    // "KEV only" is the most common filter; one tiny partial index per sort option keeps those lists off the heap sort.
    index('cve_kev_published_idx').on(t.published.desc(), t.id.desc()).where(sql`${t.isKev}`),
    index('cve_kev_modified_idx').on(t.lastModified.desc(), t.id.desc()).where(sql`${t.isKev}`),
    index('cve_kev_cvss_idx').on(t.cvssScore.desc(), t.id.desc()).where(sql`${t.isKev}`),
    index('cve_kev_epss_idx').on(t.epss.desc(), t.id.desc()).where(sql`${t.isKev}`),
    // Narrow index so the dashboard's severity counts are index-only scans instead of a pass over the 1.2 GB heap.
    index('cve_severity_idx').on(t.cvssSeverity),
    index('cve_affected_idx').using('gin', t.affected),
    index('cve_vendors_idx').using('gin', t.vendors),
    index('cve_cwe_idx').using('gin', t.cwe),
  ],
);
