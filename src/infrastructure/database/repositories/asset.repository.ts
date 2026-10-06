import { eq, inArray, sql, type SQL } from 'drizzle-orm';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type {
  Asset, AssetListItem, AssetPatch, AssetSort, AssetStats, AssetStatus, AssetTab, IAssetRepository, ImportRecord, ListAssetsQuery,
  ListAssetsResult, NewAsset, NewImportRecord, SoftwareItem,
} from '../../../domain/inventory/inventory.repository.interface.js';
import type { Database } from '../client.js';
import { assetImports, assets, assetSoftware } from '../schema/index.js';

const TAB_TYPES: Record<AssetTab, string[] | null> = {
  all: null, srv: ['server', 'web', 'db'], ep: ['laptop'], net: ['fw'], ctr: ['container'], cld: ['cloud'],
};
const STALE_DAYS = 30;

/** Same additive model as domain/vuln/risk.ts, expressed in SQL so lists can aggregate per asset. */
const RISK_SQL = sql`least(100, round(c.cvss_score * 3)::int + case when c.is_kev then 25 else 0 end + round(c.epss * 20)::int
  + case when a.exposed then 15 else 0 end + case a.env when 'prod' then 10 when 'staging' then 6 when 'dev' then 3 else 5 end)`;

const escapeLike = (s: string) => s.replace(/[\\%_]/g, '\\$&');

type AssetRowT = typeof assets.$inferSelect;

function statusOf(row: Pick<AssetRowT, 'archivedAt' | 'lastSeenAt'>): AssetStatus {
  if (row.archivedAt) return 'archived';
  return Date.now() - row.lastSeenAt.getTime() > STALE_DAYS * 86_400_000 ? 'stale' : 'active';
}

function toAsset(row: AssetRowT, software: SoftwareItem[]): Asset {
  return {
    id: row.id, type: row.type, name: row.name, addr: row.addr, os: row.os, env: row.env, criticality: row.criticality,
    exposed: row.exposed, source: row.source, owner: row.owner, tags: row.tags, attrs: row.attrs, status: statusOf(row),
    lastSeenAt: row.lastSeenAt, createdAt: row.createdAt, updatedAt: row.updatedAt, software,
  };
}

const rowsOf = <T>(res: unknown): T[] => ((res as { rows?: T[] }).rows ?? []) as T[];

@injectable()
export class AssetRepository implements IAssetRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  private where(q: ListAssetsQuery): SQL {
    const c: SQL[] = [sql`true`];
    const types = TAB_TYPES[q.tab];
    if (types) c.push(sql`a.type in (${sql.join(types.map((t) => sql`${t}`), sql`, `)})`);
    const term = q.q?.trim();
    if (term) {
      const like = `%${escapeLike(term)}%`;
      c.push(sql`(a.name ilike ${like} or a.addr ilike ${like} or a.os ilike ${like})`);
    }
    if (q.exposed) c.push(sql`a.exposed`);
    if (q.env) c.push(sql`a.env = ${q.env}`);
    if (q.criticality) c.push(sql`a.criticality = ${q.criticality}`);
    if (q.stale) c.push(sql`a.archived_at is null and a.last_seen_at < now() - ${`${STALE_DAYS} days`}::interval`);
    if (q.criticalVulns) c.push(sql`coalesce(v.c4, 0) > 0`);
    return sql.join(c, sql` and `);
  }

  private static readonly LATERAL = sql`left join lateral (
    select max(${RISK_SQL}) as risk,
      count(*) filter (where c.cvss_severity = 4) as c4, count(*) filter (where c.cvss_severity = 3) as c3,
      count(*) filter (where c.cvss_severity = 2) as c2, count(*) filter (where c.cvss_severity <= 1) as c1
    from asset_vulns av join cve c on c.id = av.cve_id
    where av.asset_id = a.id and av.status in ('open', 'in_progress')
  ) v on true`;

  async list(q: ListAssetsQuery): Promise<ListAssetsResult> {
    const order: Record<AssetSort, SQL> = {
      risk: sql`coalesce(v.risk, 0) desc, a.name asc`,
      seen: sql`a.last_seen_at desc, a.name asc`,
      name: sql`lower(a.name) asc`,
    };
    const where = this.where(q);
    const [items, count, stats] = await Promise.all([
      this.db.execute(sql`select a.*, coalesce(v.risk, 0) as risk, coalesce(v.c4, 0) as c4, coalesce(v.c3, 0) as c3,
          coalesce(v.c2, 0) as c2, coalesce(v.c1, 0) as c1
        from assets a ${AssetRepository.LATERAL} where ${where} order by ${order[q.sort]}
        limit ${q.pageSize} offset ${(q.page - 1) * q.pageSize}`),
      this.db.execute(sql`select count(*)::int as n from assets a ${AssetRepository.LATERAL} where ${where}`),
      this.stats(),
    ]);
    return {
      items: rowsOf<Record<string, unknown>>(items).map((r) => this.toListItem(r)),
      total: rowsOf<{ n: number }>(count)[0]?.n ?? 0,
      stats,
    };
  }

  private toListItem(r: Record<string, unknown>): AssetListItem {
    const lastSeenAt = new Date(r['last_seen_at'] as string);
    const archivedAt = r['archived_at'] ? new Date(r['archived_at'] as string) : null;
    return {
      id: r['id'] as string, type: r['type'] as AssetListItem['type'], name: r['name'] as string, addr: r['addr'] as string | null,
      os: r['os'] as string | null, env: r['env'] as string, criticality: r['criticality'] as AssetListItem['criticality'],
      exposed: r['exposed'] as boolean, source: r['source'] as string, owner: r['owner'] as string | null, tags: r['tags'] as string[],
      status: statusOf({ archivedAt, lastSeenAt }), lastSeenAt, createdAt: new Date(r['created_at'] as string),
      updatedAt: new Date(r['updated_at'] as string), risk: Number(r['risk']),
      counts: [Number(r['c4']), Number(r['c3']), Number(r['c2']), Number(r['c1'])],
    };
  }

  private async stats(): Promise<AssetStats> {
    const res = await this.db.execute(sql`select
      count(*)::int as total,
      count(*) filter (where archived_at is not null)::int as archived,
      count(*) filter (where archived_at is null and last_seen_at < now() - ${`${STALE_DAYS} days`}::interval)::int as stale,
      count(*) filter (where exposed)::int as exposed,
      count(*) filter (where type in ('server', 'web', 'db'))::int as srv,
      count(*) filter (where type = 'laptop')::int as ep,
      count(*) filter (where type = 'fw')::int as net,
      count(*) filter (where type = 'container')::int as ctr,
      count(*) filter (where type = 'cloud')::int as cld,
      (select count(distinct av.asset_id)::int from asset_vulns av join cve c on c.id = av.cve_id
        where av.status in ('open', 'in_progress') and c.cvss_severity = 4) as with_critical
      from assets`);
    const r = rowsOf<Record<string, number>>(res)[0] ?? {};
    const n = (k: string) => Number(r[k] ?? 0);
    return {
      total: n('total'), archived: n('archived'), stale: n('stale'), active: n('total') - n('archived') - n('stale'),
      exposed: n('exposed'), withCritical: n('with_critical'),
      tabs: { all: n('total'), srv: n('srv'), ep: n('ep'), net: n('net'), ctr: n('ctr'), cld: n('cld') },
    };
  }

  private async softwareOf(ids: string[]): Promise<Map<string, SoftwareItem[]>> {
    const map = new Map<string, SoftwareItem[]>();
    if (ids.length === 0) return map;
    const rows = await this.db.select().from(assetSoftware).where(inArray(assetSoftware.assetId, ids));
    for (const r of rows) map.set(r.assetId, [...(map.get(r.assetId) ?? []), { vendor: r.vendor, product: r.product, version: r.version }]);
    return map;
  }

  async findById(id: string): Promise<Asset | null> {
    const [row] = await this.db.select().from(assets).where(eq(assets.id, id)).limit(1);
    return row ? toAsset(row, (await this.softwareOf([id])).get(id) ?? []) : null;
  }

  async findByIdentity(name: string | null, addr: string | null): Promise<Asset | null> {
    if (!name && !addr) return null;
    const cond = [name ? sql`lower(name) = ${name.toLowerCase()}` : undefined, addr ? sql`addr = ${addr}` : undefined].filter(Boolean) as SQL[];
    const [row] = await this.db.select().from(assets).where(sql.join(cond, sql` or `)).limit(1);
    return row ? toAsset(row, (await this.softwareOf([row.id])).get(row.id) ?? []) : null;
  }

  private async writeSoftware(assetId: string, items: SoftwareItem[]): Promise<void> {
    await this.db.delete(assetSoftware).where(eq(assetSoftware.assetId, assetId));
    if (items.length) await this.db.insert(assetSoftware).values(items.map((s) => ({ assetId, ...s })));
  }

  async create(input: NewAsset): Promise<Asset> {
    const { software, ...fields } = input;
    const [row] = await this.db.insert(assets).values(fields).returning();
    await this.writeSoftware(row!.id, software);
    return toAsset(row!, software);
  }

  async update(id: string, patch: AssetPatch): Promise<Asset | null> {
    const { software, archived, seen, ...fields } = patch;
    const set: Partial<typeof assets.$inferInsert> = { ...fields, updatedAt: new Date() };
    if (seen) set.lastSeenAt = new Date();
    if (archived !== undefined) set.archivedAt = archived ? new Date() : null;
    const [row] = await this.db.update(assets).set(set).where(eq(assets.id, id)).returning();
    if (!row) return null;
    if (software) await this.writeSoftware(id, software);
    return toAsset(row, software ?? (await this.softwareOf([id])).get(id) ?? []);
  }

  async delete(id: string): Promise<boolean> {
    return (await this.db.delete(assets).where(eq(assets.id, id)).returning({ id: assets.id })).length > 0;
  }

  async forMatching(id?: string): Promise<Asset[]> {
    const rows = id ? await this.db.select().from(assets).where(eq(assets.id, id)) : await this.db.select().from(assets);
    const sw = await this.softwareOf(rows.map((r) => r.id));
    return rows.map((r) => toAsset(r, sw.get(r.id) ?? []));
  }

  async imports(limit: number): Promise<ImportRecord[]> {
    return (await this.db.select().from(assetImports).orderBy(sql`${assetImports.createdAt} desc`).limit(limit)).map((r) => ({
      id: r.id, source: r.source, kind: r.kind, rows: r.rows, created: r.created, updated: r.updated, skipped: r.skipped,
      status: r.status, createdAt: r.createdAt,
    }));
  }

  async recordImport(input: NewImportRecord): Promise<ImportRecord> {
    const [r] = await this.db.insert(assetImports).values(input).returning();
    return {
      id: r!.id, source: r!.source, kind: r!.kind, rows: r!.rows, created: r!.created, updated: r!.updated, skipped: r!.skipped,
      status: r!.status, createdAt: r!.createdAt,
    };
  }
}
