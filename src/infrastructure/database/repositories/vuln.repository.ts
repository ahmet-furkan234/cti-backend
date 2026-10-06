import { eq, inArray, sql } from 'drizzle-orm';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { CpeMatch, SeverityLevel } from '../../../domain/cve/cve.repository.interface.js';
import type {
  CveAssetRow, FoundMatch, IVulnRepository, ListVulnsQuery, MatchCandidate, VulnRow,
} from '../../../domain/vuln/vuln.repository.interface.js';
import type { VulnStatus } from '../../../domain/vuln/risk.js';
import type { Database } from '../client.js';
import { assetVulns, softwareAliases } from '../schema/index.js';

const rowsOf = <T>(res: unknown): T[] => ((res as { rows?: T[] }).rows ?? []) as T[];
const escapeLike = (s: string) => s.replace(/[\\%_]/g, '\\$&');
const pgArray = (items: string[]) => sql`ARRAY[${sql.join(items.map((i) => sql`${i}`), sql`, `)}]::text[]`;

const SELECT = sql`select av.id, av.cve_id, av.asset_id, a.name as host, a.env, a.exposed, a.addr, a.os, a.owner, a.source, a.last_seen_at,
    c.is_kev, c.cvss_score, c.cvss_severity, c.epss, av.status, av.first_seen_at, av.component, av.installed_version, av.fixed_version
  from asset_vulns av join assets a on a.id = av.asset_id join cve c on c.id = av.cve_id`;

function toRow(r: Record<string, unknown>): CveAssetRow {
  return {
    id: r['id'] as string, cve: r['cve_id'] as string, assetId: r['asset_id'] as string, host: r['host'] as string, env: r['env'] as string,
    exposed: r['exposed'] as boolean, kev: r['is_kev'] as boolean, cvss: Number(r['cvss_score']), severity: Number(r['cvss_severity']) as SeverityLevel,
    epss: Number(r['epss']), status: r['status'] as VulnStatus, firstSeenAt: new Date(r['first_seen_at'] as string),
    component: r['component'] as string, installedVersion: r['installed_version'] as string | null, fixedVersion: r['fixed_version'] as string | null,
    ip: r['addr'] as string | null, os: r['os'] as string | null, owner: r['owner'] as string | null, source: r['source'] as string,
    lastSeenAt: new Date(r['last_seen_at'] as string),
  };
}

@injectable()
export class VulnRepository implements IVulnRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  async candidates(pairs: string[]): Promise<MatchCandidate[]> {
    if (pairs.length === 0) return [];
    const res = await this.db.execute(
      sql`select id, cvss_score, cpe_matches from cve where affected && ${pgArray(pairs)}`,
    );
    return rowsOf<{ id: string; cvss_score: number; cpe_matches: CpeMatch[] }>(res).map((r) => ({
      id: r.id, cvssScore: Number(r.cvss_score), cpeMatches: r.cpe_matches,
    }));
  }

  async aliases() {
    const rows = await this.db.select().from(softwareAliases).orderBy(softwareAliases.name);
    return rows.map((r) => ({ id: r.id, name: r.name, pair: r.pair, createdAt: r.createdAt }));
  }

  async createAlias(input: { name: string; pair: string; createdBy: string | null }) {
    const [r] = await this.db.insert(softwareAliases).values(input).onConflictDoNothing().returning();
    return r ? { id: r.id, name: r.name, pair: r.pair, createdAt: r.createdAt } : null;
  }

  async deleteAlias(id: string) {
    return (await this.db.delete(softwareAliases).where(eq(softwareAliases.id, id)).returning({ id: softwareAliases.id })).length > 0;
  }

  async productPairs(): Promise<{ pair: string; cves: number }[]> {
    const res = await this.db.execute(sql`select a as pair, count(*)::int as cves from cve, unnest(affected) a group by a`);
    return rowsOf<{ pair: string; cves: number }>(res);
  }

  async replaceMatches(assetId: string, found: FoundMatch[]): Promise<void> {
    await this.db.transaction(async (tx) => {
      const keep = found.map((f) => `${f.cveId}|${f.component}`);
      if (keep.length === 0) {
        await tx.delete(assetVulns).where(sql`${assetVulns.assetId} = ${assetId}`);
      } else {
        await tx.delete(assetVulns).where(sql`${assetVulns.assetId} = ${assetId} and (${assetVulns.cveId} || '|' || ${assetVulns.component}) <> all(${pgArray(keep)})`);
        await tx
          .insert(assetVulns)
          .values(found.map((f) => ({ assetId, cveId: f.cveId, component: f.component, installedVersion: f.installedVersion, fixedVersion: f.fixedVersion })))
          .onConflictDoUpdate({
            target: [assetVulns.assetId, assetVulns.cveId, assetVulns.component],
            set: { installedVersion: sql`excluded.installed_version`, fixedVersion: sql`excluded.fixed_version` },
          });
      }
    });
  }

  async list(q: ListVulnsQuery): Promise<VulnRow[]> {
    const c = [sql`true`];
    if (q.status) c.push(sql`av.status = ${q.status}`);
    if (q.kev) c.push(sql`c.is_kev`);
    if (q.exposed) c.push(sql`a.exposed`);
    if (q.assetId) c.push(sql`av.asset_id = ${q.assetId}`);
    if (q.cveId) c.push(sql`av.cve_id = ${q.cveId}`);
    const term = q.q?.trim();
    if (term) {
      const like = `%${escapeLike(term)}%`;
      c.push(sql`(av.cve_id ilike ${like} or a.name ilike ${like} or av.fixed_version ilike ${like})`);
    }
    const res = await this.db.execute(sql`${SELECT} where ${sql.join(c, sql` and `)} order by c.cvss_score desc, av.cve_id limit ${q.limit}`);
    return rowsOf<Record<string, unknown>>(res).map(toRow);
  }

  async forCve(cveId: string): Promise<CveAssetRow[]> {
    const res = await this.db.execute(sql`${SELECT} where av.cve_id = ${cveId} order by a.name`);
    return rowsOf<Record<string, unknown>>(res).map(toRow);
  }

  async setStatus(ids: string[], status: VulnStatus, actorId: string): Promise<number> {
    const res = await this.db
      .update(assetVulns)
      .set({ status, statusChangedAt: new Date(), statusChangedBy: actorId })
      .where(inArray(assetVulns.id, ids))
      .returning({ id: assetVulns.id });
    return res.length;
  }
}
