import { and, desc, eq, sql, type SQL } from 'drizzle-orm';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type {
  Cell, Format, IReportRepository, NewRun, NewSchedule, Run, Schedule, Table, TemplateId,
} from '../../../domain/report/report.repository.interface.js';
import { tenant } from '../../../shared/tenant.js';
import type { Database } from '../client.js';
import { reportRuns, reportSchedules } from '../schema/index.js';
import { SLA_LEFT_SQL } from '../sql.js';

const rowsOf = <T>(res: unknown): T[] => ((res as { rows?: T[] }).rows ?? []) as T[];

const toSchedule = (r: typeof reportSchedules.$inferSelect): Schedule => ({
  id: r.id, template: r.template, scope: r.scope, freq: r.freq, recipients: r.recipients, formats: r.formats as Format[],
  enabled: r.enabled, createdAt: r.createdAt,
});
const runCols = {
  id: reportRuns.id, scheduleId: reportRuns.scheduleId, template: reportRuns.template, scope: reportRuns.scope, formats: reportRuns.formats,
  status: reportRuns.status, manual: reportRuns.manual, sizeBytes: reportRuns.sizeBytes, error: reportRuns.error, createdAt: reportRuns.createdAt,
};

const FROM = sql`from asset_vulns av join assets a on a.id = av.asset_id join cve c on c.id = av.cve_id`;
/** open matches on the current company's assets */
const open = () => sql`a.company_id = ${tenant.id()} and av.status in ('open', 'in_progress')`;
const MATCH_COLS = sql`av.cve_id, a.name as asset, a.env, a.exposed, a.owner, c.cvss_score, c.epss, c.is_kev, av.status, av.component,
  av.installed_version, av.fixed_version, round(${SLA_LEFT_SQL})::int as sla_hours_left`;
const MATCH_HEADER = ['cve', 'asset', 'environment', 'internet_facing', 'owner', 'cvss', 'epss', 'kev', 'status', 'component', 'installed_version', 'fixed_version', 'sla_hours_left'];
const matchRow = (r: Record<string, unknown>): Cell[] => [
  r['cve_id'] as string, r['asset'] as string, r['env'] as string, r['exposed'] as boolean, (r['owner'] as string | null) ?? '',
  Number(r['cvss_score']), Number(r['epss']), r['is_kev'] as boolean, r['status'] as string, r['component'] as string,
  (r['installed_version'] as string | null) ?? '', (r['fixed_version'] as string | null) ?? '',
  ['mitigated', 'accepted'].includes(r['status'] as string) ? '' : Number(r['sla_hours_left']),
];

@injectable()
export class ReportRepository implements IReportRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  async schedules(): Promise<Schedule[]> {
    return (await this.db.select().from(reportSchedules).where(eq(reportSchedules.companyId, tenant.id())).orderBy(desc(reportSchedules.createdAt))).map(toSchedule);
  }
  async createSchedule(input: NewSchedule): Promise<Schedule> {
    const [r] = await this.db.insert(reportSchedules).values({ ...input, companyId: tenant.id() }).returning();
    return toSchedule(r!);
  }
  async updateSchedule(id: string, patch: Partial<NewSchedule>): Promise<Schedule | null> {
    const [r] = await this.db.update(reportSchedules).set(patch).where(and(eq(reportSchedules.id, id), eq(reportSchedules.companyId, tenant.id()))).returning();
    return r ? toSchedule(r) : null;
  }
  async deleteSchedule(id: string): Promise<boolean> {
    return (await this.db.delete(reportSchedules).where(and(eq(reportSchedules.id, id), eq(reportSchedules.companyId, tenant.id()))).returning({ id: reportSchedules.id })).length > 0;
  }

  async runs(limit: number): Promise<Run[]> {
    const rows = await this.db.select(runCols).from(reportRuns).where(eq(reportRuns.companyId, tenant.id())).orderBy(desc(reportRuns.createdAt)).limit(limit);
    return rows.map((r) => ({ ...r, formats: r.formats as Format[] }));
  }
  async findRun(id: string): Promise<Run | null> {
    const [r] = await this.db.select(runCols).from(reportRuns).where(and(eq(reportRuns.id, id), eq(reportRuns.companyId, tenant.id()))).limit(1);
    return r ? { ...r, formats: r.formats as Format[] } : null;
  }
  async createRun(input: NewRun): Promise<Run> {
    const [r] = await this.db.insert(reportRuns).values({ ...input, companyId: tenant.id() }).returning({ id: reportRuns.id });
    return (await this.findRun(r!.id))!;
  }
  async finishRun(id: string, result: Parameters<IReportRepository['finishRun']>[1]): Promise<void> {
    await this.db
      .update(reportRuns)
      .set(result.status === 'ready' ? { status: 'ready', content: result.content, sizeBytes: Buffer.byteLength(result.content) } : { status: 'failed', error: result.error })
      .where(and(eq(reportRuns.id, id), eq(reportRuns.companyId, tenant.id())));
  }
  async content(id: string): Promise<string | null> {
    const [r] = await this.db.select({ content: reportRuns.content }).from(reportRuns).where(and(eq(reportRuns.id, id), eq(reportRuns.companyId, tenant.id()))).limit(1);
    return r?.content ?? null;
  }

  async data(template: TemplateId, scope: string | null, periodDays: number): Promise<Table> {
    switch (template) {
      case 'kev': {
        const res = await this.db.execute(sql`select ${MATCH_COLS} ${FROM} where ${open()} and c.is_kev order by sla_hours_left, c.cvss_score desc`);
        return { header: MATCH_HEADER, rows: rowsOf<Record<string, unknown>>(res).map(matchRow) };
      }
      case 'sla': {
        const res = await this.db.execute(sql`select * from (select ${MATCH_COLS} ${FROM} where ${open()}) x where sla_hours_left <= 72 order by sla_hours_left`);
        return { header: MATCH_HEADER, rows: rowsOf<Record<string, unknown>>(res).map(matchRow) };
      }
      case 'owner': {
        const where: SQL[] = [open()];
        if (scope) where.push(sql`lower(a.owner) = lower(${scope})`);
        const res = await this.db.execute(sql`select ${MATCH_COLS} ${FROM} where ${sql.join(where, sql` and `)} order by a.owner nulls last, c.cvss_score desc`);
        return { header: MATCH_HEADER, rows: rowsOf<Record<string, unknown>>(res).map(matchRow) };
      }
      case 'exec': {
        const res = await this.db.execute(sql`select
          (select count(*)::int from assets where company_id = ${tenant.id()} and archived_at is null) as assets,
          count(*) filter (where ${open()})::int as open,
          count(*) filter (where ${open()} and c.is_kev)::int as kev,
          count(*) filter (where ${open()} and c.cvss_severity = 4)::int as critical,
          count(*) filter (where ${open()} and ${SLA_LEFT_SQL} < 0)::int as overdue,
          count(*) filter (where av.first_seen_at > now() - ${`${periodDays} days`}::interval)::int as found,
          count(*) filter (where av.status = 'mitigated' and av.status_changed_at > now() - ${`${periodDays} days`}::interval)::int as mitigated
          ${FROM} where a.company_id = ${tenant.id()}`);
        const r = rowsOf<Record<string, number>>(res)[0] ?? {};
        const top = rowsOf<{ name: string; risk: number }>(
          await this.db.execute(sql`select a.name, max(least(100, round(c.cvss_score * 3)::int + case when c.is_kev then 25 else 0 end + round(c.epss * 20)::int
            + case when a.exposed then 15 else 0 end + case a.env when 'prod' then 10 when 'staging' then 6 when 'dev' then 3 else 5 end)) as risk
            ${FROM} where ${open()} group by a.name order by risk desc limit 10`),
        );
        const n = (k: string) => Number(r[k] ?? 0);
        return {
          header: ['metric', 'value'],
          rows: [
            ['period_days', periodDays], ['assets', n('assets')], ['open_vulnerabilities', n('open')], ['known_exploited_open', n('kev')],
            ['critical_open', n('critical')], ['sla_overdue', n('overdue')], ['found_in_period', n('found')], ['mitigated_in_period', n('mitigated')],
            ...top.map((t, i): Cell[] => [`top_risk_${i + 1}`, `${t.name} (${t.risk})`]),
          ],
        };
      }
    }
  }
}
