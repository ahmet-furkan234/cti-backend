import { sql } from 'drizzle-orm';
import { slaWindowHours } from '../../domain/vuln/risk.js';

/** Raw SQL that can't be expressed through the drizzle schema, kept in one place. */
export const SQL = {
  /** Trigram index support (`gin_trgm_ops`) for partial-word CVE search; ensured before migrating. */
  ensureTrigramExtension: 'CREATE EXTENSION IF NOT EXISTS pg_trgm',
} as const;

/** Fix window (hours) of a match, from the joined `c` (cve) alias; mirrors domain/vuln/risk.ts. */
export const SLA_WINDOW_SQL = sql`case when c.is_kev then ${slaWindowHours({ cvss: 0, kev: true })}::int
  when c.cvss_score >= 9 then ${slaWindowHours({ cvss: 9, kev: false })}::int when c.cvss_score >= 7 then ${slaWindowHours({ cvss: 7, kev: false })}::int
  when c.cvss_score >= 4 then ${slaWindowHours({ cvss: 4, kev: false })}::int else ${slaWindowHours({ cvss: 0, kev: false })}::int end`;

/** Hours left until a match's fix window ends (negative = overdue); uses the `av` (asset_vulns) and `c` aliases. */
export const SLA_LEFT_SQL = sql`extract(epoch from (av.first_seen_at + (${SLA_WINDOW_SQL}) * interval '1 hour' - now())) / 3600`;
