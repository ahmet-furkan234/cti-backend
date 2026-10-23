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
import { tenant } from '../../../shared/tenant.js';


const SORT_COLUMNS = {
  published: { col: cve.published, kind: 'time' },
  modified: { col: cve.lastModified, kind: 'time' },
  cvss: { col: cve.cvssScore, kind: 'num' },
  epss: { col: cve.epss, kind: 'num' },
} as const;

const STATS_TTL_MS = 60_000;

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
    if (q.assetScope) {
      const narrow: SQL[] = [];
      if (q.assetScope.exposed) narrow.push(sql`a.exposed`);
      if (q.assetScope.env) narrow.push(sql`a.env = ${q.assetScope.env}`);
      c.push(sql`exists (select 1 from asset_vulns av join assets a on a.id = av.asset_id
        where av.cve_id = ${cve.id} and a.company_id = ${tenant.id()} and av.status in ('open', 'in_progress')${narrow.length ? sql` and ${sql.join(narrow, sql` and `)}` : sql``})`);
    }
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

    // The total is independent of the page, so it runs alongside the page query instead of after it.
    // Drizzle builders are lazy, hence execute(); the no-op catch keeps a failing page query from leaving this one unhandled.
    const totalQuery = q.includeTotal ? this.db.select({ n: count() }).from(cve).where(where).execute() : null;
    totalQuery?.catch(() => undefined);

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
    const counts = q.assetCounts && page.length ? await this.assetCounts(page.map((r) => r.id)) : null;
    const items: CveListItem[] = page.map((r) => ({
      ...r,
      ...(counts ? { affectedAssets: counts.get(r.id) ?? 0 } : {}),
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
    if (totalQuery) {
      const [t] = await totalQuery;
      result.total = t?.n ?? 0;
    }
    return result;
  }

  /** unresolved matches per CVE on the current company's assets */
  private async assetCounts(ids: string[]): Promise<Map<string, number>> {
    const res = await this.db.execute(sql`select av.cve_id, count(distinct av.asset_id)::int as n
      from asset_vulns av join assets a on a.id = av.asset_id
      where a.company_id = ${tenant.id()} and av.status in ('open', 'in_progress') and av.cve_id = any(${sql`ARRAY[${sql.join(ids.map((i) => sql`${i}`), sql`, `)}]::text[]`})
      group by av.cve_id`);
    return new Map(((res as unknown as { rows: { cve_id: string; n: number }[] }).rows).map((r) => [r.cve_id, Number(r.n)]));
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

  /**
   * Dashboard numbers are global (not per company) and the underlying data changes hourly at most, so one
   * computation is shared by every request for a minute. Concurrent callers join the in-flight computation.
   */
  private statsCache: { at: number; value: Promise<CveStats> } | null = null;

  stats(): Promise<CveStats> {
    const cached = this.statsCache;
    if (cached && Date.now() - cached.at < STATS_TTL_MS) return cached.value;
    const value = this.computeStats();
    this.statsCache = { at: Date.now(), value };
    // A failed computation must not be served for a minute.
    value.catch(() => { if (this.statsCache?.value === value) this.statsCache = null; });
    return value;
  }

  private async computeStats(): Promise<CveStats> {
    const db = this.db;
    // total / critical come from the severity breakdown: each is an index-only scan, none touches the heap.
    const [kevCount, last24h, sev, perDay, topCwe, topVendors, newestKev] = await Promise.all([
      db.execute<{ n: string }>(sql`select count(*) as n from cve where is_kev`),
      db.execute<{ n: string }>(sql`select count(*) as n from cve where published > now() - interval '24 hours'`),
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
    const bySeverity = sev.rows.map((r) => ({ severity: r.severity as SeverityLevel, count: Number(r.n) }));
    return {
      total: bySeverity.reduce((s, r) => s + r.count, 0),
      kevCount: Number(kevCount.rows[0]?.n ?? 0),
      criticalCount: bySeverity.find((r) => r.severity === 4)?.count ?? 0,
      addedLast24h: Number(last24h.rows[0]?.n ?? 0),
      severityDistribution: bySeverity,
      perDay: perDay.rows.map((r) => ({ day: r.day, count: Number(r.n) })),
      topCwe: topCwe.rows.map((r) => ({ cwe: r.cwe, count: Number(r.n) })),
      topVendors: topVendors.rows.map((r) => ({ vendor: r.vendor, count: Number(r.n) })),
      newestKev: newestKev.map((r) => ({ ...r, description: r.description.slice(0, 200) })),
    };
  }
}
