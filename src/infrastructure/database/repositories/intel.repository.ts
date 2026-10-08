import { and, eq, sql, type SQL } from 'drizzle-orm';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { FindingList, FindingsQuery, IIntelRepository, IocAsset, IocList, ListIocsQuery, NewIoc, NewKev, NewWatchlist, Watchlist, WatchlistHit } from '../../../domain/intel/intel.repository.interface.js';
import { tenant } from '../../../shared/tenant.js';
import type { Database } from '../client.js';
import { iocs, watchlists } from '../schema/index.js';

const rowsOf = <T>(res: unknown): T[] => ((res as { rows?: T[] }).rows ?? []) as T[];
const escapeLike = (s: string) => s.replace(/[\\%_]/g, '\\$&');

const IPV4 = String.raw`'^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$'`;
/** Inventory assets an indicator points at (address, host name or a range containing the address). */
const IOC_ON_ASSET = sql`(case i.type
  when 'ipv4' then a.addr = i.value
  when 'ipv6' then lower(a.addr) = lower(i.value)
  when 'domain' then lower(a.name) = lower(i.value) or lower(coalesce(a.addr, '')) like '%' || lower(i.value) || '%'
  when 'cidr' then (case when a.addr ~ ${sql.raw(IPV4)} then a.addr::inet <<= i.value::cidr else false end)
  else false end)`;
const IOC_MATCHES = sql`(select count(*)::int from assets a where a.company_id = i.company_id and ${IOC_ON_ASSET})`;

/** Assets covered by a watchlist w: by component (vendor / product) or, when none is set, by tag. */
const COVERS = sql`(a.company_id = w.company_id
  and ((cardinality(w.vendors) = 0 and cardinality(w.products) = 0 and w.tag <> '')
    or exists (select 1 from asset_vulns v where v.asset_id = a.id and (split_part(v.component, ':', 1) = any(w.vendors) or split_part(v.component, ':', 2) = any(w.products)))
    or exists (select 1 from asset_software s where s.asset_id = a.id and (lower(s.vendor) = any(w.vendors) or lower(s.product) = any(w.products))))
  and (w.tag = '' or w.tag = any(a.tags)))`;

const toWatchlist = (r: Record<string, unknown>): Watchlist => ({
  id: r['id'] as string, name: r['name'] as string, vendors: r['vendors'] as string[], products: r['products'] as string[],
  tag: r['tag'] as string, minCvss: Number(r['min_cvss']), kevOnly: r['kev_only'] as boolean, minEpss: Number(r['min_epss']),
  channelId: r['channel_id'] as string | null, enabled: r['enabled'] as boolean, count: Number(r['count']), hits: Number(r['hits']),
});

@injectable()
export class IntelRepository implements IIntelRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  private async watchlistRows(where?: SQL): Promise<Watchlist[]> {
    const res = await this.db.execute(sql`select w.*,
      (select count(*)::int from assets a where ${COVERS}) as count,
      (select count(*)::int from asset_vulns av join assets a on a.id = av.asset_id join cve c on c.id = av.cve_id
        where ${COVERS} and av.status in ('open', 'in_progress') and av.first_seen_at > now() - interval '7 days'
        and c.cvss_score >= w.min_cvss and (not w.kev_only or c.is_kev) and c.epss * 100 >= w.min_epss
        and (cardinality(w.vendors) + cardinality(w.products) = 0
          or split_part(av.component, ':', 1) = any(w.vendors) or split_part(av.component, ':', 2) = any(w.products))) as hits
      from watchlists w where w.company_id = ${tenant.id()}${where ? sql` and ${where}` : sql``} order by w.created_at desc`);
    return rowsOf<Record<string, unknown>>(res).map(toWatchlist);
  }

  watchlists(): Promise<Watchlist[]> {
    return this.watchlistRows();
  }
  async createWatchlist(input: NewWatchlist): Promise<Watchlist> {
    const [r] = await this.db.insert(watchlists).values({ ...input, companyId: tenant.id() }).returning({ id: watchlists.id });
    return (await this.watchlistRows(sql`w.id = ${r!.id}`))[0]!;
  }
  async updateWatchlist(id: string, patch: Partial<NewWatchlist>): Promise<Watchlist | null> {
    const res = await this.db.update(watchlists).set(patch).where(and(eq(watchlists.id, id), eq(watchlists.companyId, tenant.id()))).returning({ id: watchlists.id });
    return res.length ? (await this.watchlistRows(sql`w.id = ${id}`))[0] ?? null : null;
  }
  async deleteWatchlist(id: string): Promise<boolean> {
    return (await this.db.delete(watchlists).where(and(eq(watchlists.id, id), eq(watchlists.companyId, tenant.id()))).returning({ id: watchlists.id })).length > 0;
  }

  async notifying() {
    const rows = await this.db.select().from(watchlists).where(and(eq(watchlists.companyId, tenant.id()), sql`${watchlists.enabled} and ${watchlists.channelId} is not null`));
    return rows.map((w) => ({ id: w.id, name: w.name, channelId: w.channelId!, evaluatedAt: w.evaluatedAt }));
  }

  async findings(q: FindingsQuery): Promise<FindingList> {
    const since = new Date(Date.now() - q.days * 86_400_000);
    const res = await this.db.execute(sql`select av.id, w.id as watchlist_id, w.name as watchlist, av.cve_id, c.cvss_score, c.is_kev, c.epss,
        a.id as asset_id, a.name as asset, a.env, av.component, av.first_seen_at, count(*) over()::int as total
      from watchlists w, asset_vulns av join assets a on a.id = av.asset_id join cve c on c.id = av.cve_id
      where w.company_id = ${tenant.id()} and w.enabled${q.watchlistId ? sql` and w.id = ${q.watchlistId}` : sql``} and ${COVERS}
        and av.status in ('open', 'in_progress') and av.first_seen_at > ${since}
        and c.cvss_score >= w.min_cvss and (not w.kev_only or c.is_kev) and c.epss * 100 >= w.min_epss
        and (cardinality(w.vendors) + cardinality(w.products) = 0
          or split_part(av.component, ':', 1) = any(w.vendors) or split_part(av.component, ':', 2) = any(w.products))
      order by c.is_kev desc, c.cvss_score desc, av.first_seen_at desc limit ${q.limit}`);
    const rows = rowsOf<Record<string, unknown>>(res);
    return {
      total: Number(rows[0]?.['total'] ?? 0),
      items: rows.map((r) => ({
        id: `${r['id'] as string}:${r['watchlist_id'] as string}`, watchlistId: r['watchlist_id'] as string, watchlist: r['watchlist'] as string,
        cve: r['cve_id'] as string, cvss: Number(r['cvss_score']), kev: r['is_kev'] as boolean, epss: Number(r['epss']),
        assetId: r['asset_id'] as string, asset: r['asset'] as string, env: r['env'] as string, component: r['component'] as string,
        firstSeenAt: new Date(r['first_seen_at'] as string),
      })),
    };
  }

  async iocAssets(id: string): Promise<IocAsset[]> {
    const res = await this.db.execute(sql`select a.id, a.name, a.addr, a.env, a.exposed,
        (select count(*)::int from asset_vulns av where av.asset_id = a.id and av.status in ('open', 'in_progress')) as open_vulns
      from iocs i join assets a on a.company_id = i.company_id
      where i.id = ${id} and i.company_id = ${tenant.id()} and ${IOC_ON_ASSET}
      order by open_vulns desc, a.name limit 50`);
    return rowsOf<Record<string, unknown>>(res).map((r) => ({
      id: r['id'] as string, name: r['name'] as string, addr: (r['addr'] as string | null) ?? null, env: r['env'] as string,
      exposed: r['exposed'] as boolean, openVulns: Number(r['open_vulns']),
    }));
  }

  async newKev(days: number, limit: number): Promise<NewKev[]> {
    const since = new Date(Date.now() - days * 86_400_000);
    const res = await this.db.execute(sql`select c.id, c.cvss_score, c.epss, c.kev_ransomware, c.kev_added,
        (select count(distinct av.asset_id)::int from asset_vulns av join assets a on a.id = av.asset_id
          where av.cve_id = c.id and a.company_id = ${tenant.id()} and av.status in ('open', 'in_progress')) as assets
      from cve c where c.is_kev and c.kev_added >= ${since}
      order by assets desc, c.kev_added desc limit ${limit}`);
    return rowsOf<Record<string, unknown>>(res).map((r) => ({
      cve: r['id'] as string, cvss: Number(r['cvss_score']), epss: Number(r['epss']), ransomware: r['kev_ransomware'] as boolean,
      addedAt: new Date(r['kev_added'] as string), assets: Number(r['assets']),
    }));
  }

  async hitsSince(id: string, since: Date): Promise<WatchlistHit[]> {
    const res = await this.db.execute(sql`select av.cve_id, a.name, c.cvss_score
      from watchlists w, asset_vulns av join assets a on a.id = av.asset_id join cve c on c.id = av.cve_id
      where w.id = ${id} and w.company_id = ${tenant.id()} and ${COVERS} and av.status in ('open', 'in_progress') and av.first_seen_at > ${since}
        and c.cvss_score >= w.min_cvss and (not w.kev_only or c.is_kev) and c.epss * 100 >= w.min_epss
        and (cardinality(w.vendors) + cardinality(w.products) = 0
          or split_part(av.component, ':', 1) = any(w.vendors) or split_part(av.component, ':', 2) = any(w.products))
      order by c.cvss_score desc limit 200`);
    return rowsOf<{ cve_id: string; name: string; cvss_score: number }>(res).map((r) => ({ line: `${r.cve_id} × ${r.name} (CVSS ${Number(r.cvss_score).toFixed(1)})` }));
  }

  async markEvaluated(id: string, at: Date): Promise<void> {
    await this.db.update(watchlists).set({ evaluatedAt: at }).where(and(eq(watchlists.id, id), eq(watchlists.companyId, tenant.id())));
  }

  async iocs(q: ListIocsQuery): Promise<IocList> {
    const c: SQL[] = [sql`i.company_id = ${tenant.id()}`, sql`(i.expires_at is null or i.expires_at > now())`];
    if (q.types?.length) c.push(sql`i.type in (${sql.join(q.types.map((t) => sql`${t}`), sql`, `)})`);
    const term = q.q?.trim();
    if (term) {
      const like = `%${escapeLike(term)}%`;
      c.push(sql`(i.value ilike ${like} or i.source ilike ${like})`);
    }
    const where = sql.join(c, sql` and `);
    const matched = q.onlyMatches ? sql`where matches > 0` : sql``;
    const [items, totals] = await Promise.all([
      this.db.execute(sql`select * from (select i.*, ${IOC_MATCHES} as matches from iocs i where ${where}) x ${matched}
        order by matches desc, created_at desc limit ${q.limit} offset ${q.offset}`),
      this.db.execute(sql`select count(*) filter (where ${where})::int as total,
        count(*) filter (where i.expires_at is null or i.expires_at > now())::int as active,
        count(*) filter (where i.expires_at > now() and i.expires_at < now() + interval '7 days')::int as expiring from iocs i where i.company_id = ${tenant.id()}`),
    ]);
    const t = rowsOf<Record<string, number>>(totals)[0] ?? {};
    return {
      items: rowsOf<Record<string, unknown>>(items).map((r) => ({
        id: r['id'] as string, type: r['type'] as IocList['items'][number]['type'], value: r['value'] as string, source: r['source'] as string,
        confidence: Number(r['confidence']), expiresAt: r['expires_at'] ? new Date(r['expires_at'] as string) : null, matches: Number(r['matches']),
      })),
      total: Number(t['total'] ?? 0), active: Number(t['active'] ?? 0), expiring: Number(t['expiring'] ?? 0),
    };
  }

  async addIocs(items: NewIoc[]): Promise<number> {
    if (items.length === 0) return 0;
    const res = await this.db.insert(iocs).values(items.map((i) => ({ ...i, companyId: tenant.id() }))).onConflictDoNothing().returning({ id: iocs.id });
    return res.length;
  }
  async deleteIoc(id: string): Promise<boolean> {
    return (await this.db.delete(iocs).where(and(eq(iocs.id, id), eq(iocs.companyId, tenant.id()))).returning({ id: iocs.id })).length > 0;
  }
}
