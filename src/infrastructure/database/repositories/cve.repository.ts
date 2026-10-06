import { and, count, eq, gte, inArray, lte, sql, type SQL } from 'drizzle-orm';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type {
  Cve, CpeMatch, CveListItem, CveReference, CveStats, ICveRepository,
  SearchCvesQuery, SearchCvesResult, SeverityLevel,
} from '../../../domain/cve/cve.repository.interface.js';
import { InvalidValueException } from '../../../domain/common/exceptions.js';
import type { Database } from '../client.js';
import { cve } from '../schema/index.js';
import { Errors } from '../../../shared/strings.js';


const SORT_COLUMNS = {
  published: { col: cve.published, kind: 'time' },
  modified: { col: cve.lastModified, kind: 'time' },
  cvss: { col: cve.cvssScore, kind: 'num' },
  epss: { col: cve.epss, kind: 'num' },
} as const;

const escapeLike = (s: string) => s.replace(/[\\%_]/g, '\\$&');

function decodeCursor(cursor: string): { v: string | number; id: string } {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as { v: string | number; id: string };
    if ((typeof parsed.v !== 'string' && typeof parsed.v !== 'number') || typeof parsed.id !== 'string') throw new Error();
    return parsed;
  } catch {
    throw new InvalidValueException(Errors.invalidCursor);
  }
}

@injectable()
export class CveRepository implements ICveRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  private buildWhere(q: SearchCvesQuery): SQL | undefined {
    const c: SQL[] = [];
    const term = q.q?.trim();
    if (term) {
      if (/^cve-\d{4}(-\d*)?$/i.test(term)) {
        c.push(sql`${cve.id} like ${term.toUpperCase() + '%'}`); // served by the text_pattern_ops index
      } else {
        const fts = sql`${cve.searchVec} @@ websearch_to_tsquery('english', ${term})`;
        // Trigram ILIKE catches partial words ("log4" → log4j); useless below 3 chars.
        c.push(term.length >= 3 ? sql`(${fts} or ${cve.description} ilike ${'%' + escapeLike(term) + '%'})` : fts);
      }
    }
    if (q.severities?.length) c.push(inArray(cve.cvssSeverity, q.severities));
    if (q.cvssMin !== undefined) c.push(gte(cve.cvssScore, q.cvssMin));
    if (q.cvssMax !== undefined) c.push(lte(cve.cvssScore, q.cvssMax));
    if (q.kev) c.push(eq(cve.isKev, true));
    if (q.epssMin !== undefined) c.push(gte(cve.epss, q.epssMin));
    if (q.publishedFrom) c.push(gte(cve.published, q.publishedFrom));
    if (q.publishedTo) c.push(lte(cve.published, q.publishedTo));
    if (q.vendor && q.product) c.push(sql`${cve.affected} @> ARRAY[${`${q.vendor.toLowerCase()}:${q.product.toLowerCase()}`}]::text[]`);
    else if (q.vendor) c.push(sql`${cve.vendors} @> ARRAY[${q.vendor.toLowerCase()}]::text[]`);
    if (q.cwe) c.push(sql`${cve.cwe} @> ARRAY[${q.cwe.toUpperCase()}]::text[]`);
    return c.length ? and(...c) : undefined;
  }

  async search(q: SearchCvesQuery): Promise<SearchCvesResult> {
    const where = this.buildWhere(q);
    const sort = SORT_COLUMNS[q.sort];
    const desc = q.order === 'desc';

    const conds: (SQL | undefined)[] = [where];
    if (q.cursor) {
      const cur = decodeCursor(q.cursor);
      const val = sort.kind === 'time' ? sql`${String(cur.v)}::timestamptz` : sql`${Number(cur.v)}::real`;
      conds.push(desc ? sql`(${sort.col}, ${cve.id}) < (${val}, ${cur.id})` : sql`(${sort.col}, ${cve.id}) > (${val}, ${cur.id})`);
    }
    // Explicit NULLS ordering matches the index definitions so the planner can use them.
    const order = desc
      ? sql`${sort.col} desc nulls last, ${cve.id} desc nulls last`
      : sql`${sort.col} asc nulls first, ${cve.id} asc nulls first`;

    const rows = await this.db
      .select({
        id: cve.id, published: cve.published, lastModified: cve.lastModified, description: cve.description,
        cvssScore: cve.cvssScore, cvssSeverity: cve.cvssSeverity, isKev: cve.isKev, epss: cve.epss, affected: cve.affected,
      })
      .from(cve)
      .where(and(...conds))
      .orderBy(order)
      .limit(q.limit + 1);

    const hasMore = rows.length > q.limit;
    const page = hasMore ? rows.slice(0, q.limit) : rows;
    const last = page[page.length - 1];
    const items: CveListItem[] = page.map((r) => ({
      ...r,
      description: r.description.length > 400 ? r.description.slice(0, 400) + '…' : r.description,
      cvssSeverity: r.cvssSeverity as SeverityLevel,
      affected: r.affected.slice(0, 8),
    }));

    let nextCursor: string | null = null;
    if (hasMore && last) {
      const v = sort.kind === 'time' ? (sort.col === cve.published ? last.published : last.lastModified).toISOString()
        : sort.col === cve.cvssScore ? last.cvssScore : last.epss;
      nextCursor = Buffer.from(JSON.stringify({ v, id: last.id })).toString('base64url');
    }

    const result: SearchCvesResult = { items, nextCursor };
    if (q.includeTotal) {
      const [t] = await this.db.select({ n: count() }).from(cve).where(where);
      result.total = t?.n ?? 0;
    }
    return result;
  }

  async findById(id: string): Promise<Cve | null> {
    const [r] = await this.db.select().from(cve).where(eq(cve.id, id)).limit(1);
    if (!r) return null;
    return {
      id: r.id, published: r.published, lastModified: r.lastModified, vulnStatus: r.vulnStatus,
      description: r.description, cvssScore: r.cvssScore, cvssSeverity: r.cvssSeverity as SeverityLevel,
      cvssVector: r.cvssVector, cvssVersion: r.cvssVersion, cwe: r.cwe, isKev: r.isKev, kevAdded: r.kevAdded,
      kevDueDate: r.kevDueDate, kevRansomware: r.kevRansomware, epss: r.epss, epssPercentile: r.epssPercentile,
      references: r.references as CveReference[], affected: r.affected, vendors: r.vendors,
      cpeMatches: r.cpeMatches as CpeMatch[],
    };
  }

  async stats(): Promise<CveStats> {
    const db = this.db;
    const [totals, sev, perDay, topCwe, topVendors, newestKev] = await Promise.all([
      db.execute<{ total: string; kev: string; critical: string; last24h: string }>(sql`
        select count(*) as total,
               count(*) filter (where is_kev) as kev,
               count(*) filter (where cvss_severity = 4) as critical,
               count(*) filter (where published > now() - interval '24 hours') as last24h
        from cve`),
      db.execute<{ severity: number; n: string }>(sql`select cvss_severity as severity, count(*) as n from cve group by 1 order by 1`),
      db.execute<{ day: string; n: string }>(sql`
        select to_char(date_trunc('day', published), 'YYYY-MM-DD') as day, count(*) as n
        from cve where published >= now() - interval '30 days' group by 1 order by 1`),
      db.execute<{ cwe: string; n: string }>(sql`
        select w as cwe, count(*) as n from cve, unnest(cwe) as w
        where published >= now() - interval '365 days' and w like 'CWE-%'
        group by 1 order by 2 desc limit 10`),
      db.execute<{ vendor: string; n: string }>(sql`
        select v as vendor, count(*) as n from cve, unnest(vendors) as v
        where published >= now() - interval '365 days' group by 1 order by 2 desc limit 10`),
      db.select({ id: cve.id, kevAdded: cve.kevAdded, description: cve.description, cvssScore: cve.cvssScore })
        .from(cve).where(eq(cve.isKev, true))
        .orderBy(sql`${cve.kevAdded} desc nulls last, ${cve.id} desc nulls last`).limit(10),
    ]);
    const t = totals.rows[0]!;
    return {
      total: Number(t.total), kevCount: Number(t.kev), criticalCount: Number(t.critical), addedLast24h: Number(t.last24h),
      severityDistribution: sev.rows.map((r) => ({ severity: r.severity as SeverityLevel, count: Number(r.n) })),
      perDay: perDay.rows.map((r) => ({ day: r.day, count: Number(r.n) })),
      topCwe: topCwe.rows.map((r) => ({ cwe: r.cwe, count: Number(r.n) })),
      topVendors: topVendors.rows.map((r) => ({ vendor: r.vendor, count: Number(r.n) })),
      newestKev: newestKev.map((r) => ({ ...r, description: r.description.slice(0, 200) })),
    };
  }
}
