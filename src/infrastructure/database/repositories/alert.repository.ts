import { and, desc, eq, sql, type SQL } from 'drizzle-orm';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type {
  AlertEvent, Channel, IAlertRepository, LogEntry, NewChannel, NewLogEntry, NewRule, Rule,
} from '../../../domain/alerts/alert.repository.interface.js';
import { SLA_LEFT_SQL } from '../sql.js';
import { tenant } from '../../../shared/tenant.js';
import type { Database } from '../client.js';
import { alertChannels, alertLog, alertRules } from '../schema/index.js';

const rowsOf = <T>(res: unknown): T[] => ((res as { rows?: T[] }).rows ?? []) as T[];
const pgUuids = (ids: string[]) => sql`ARRAY[${sql.join(ids.map((i) => sql`${i}`), sql`, `)}]::uuid[]`;

const toChannel = (r: typeof alertChannels.$inferSelect): Channel => ({
  id: r.id, kind: r.kind, name: r.name, values: r.values, status: r.status, problem: r.problem, lastTestAt: r.lastTestAt,
});
const toLog = (r: typeof alertLog.$inferSelect): LogEntry => ({
  id: r.id, ruleId: r.ruleId, assetId: r.assetId, channelIds: r.channelIds, result: r.result, detail: r.detail, at: r.at,
});

/** Same additive model as domain/vuln/risk.ts, in SQL. */
const RISK = sql`least(100, round(c.cvss_score * 3)::int + case when c.is_kev then 25 else 0 end + round(c.epss * 20)::int
  + case when a.exposed then 15 else 0 end + case a.env when 'prod' then 10 when 'staging' then 6 when 'dev' then 3 else 5 end)`;

@injectable()
export class AlertRepository implements IAlertRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  async channels(): Promise<Channel[]> {
    return (await this.db.select().from(alertChannels).where(eq(alertChannels.companyId, tenant.id())).orderBy(alertChannels.createdAt)).map(toChannel);
  }
  async findChannel(id: string): Promise<Channel | null> {
    const [r] = await this.db.select().from(alertChannels).where(and(eq(alertChannels.id, id), eq(alertChannels.companyId, tenant.id()))).limit(1);
    return r ? toChannel(r) : null;
  }
  async createChannel(input: NewChannel): Promise<Channel> {
    const [r] = await this.db.insert(alertChannels).values({ ...input, companyId: tenant.id() }).returning();
    return toChannel(r!);
  }
  async updateChannel(id: string, patch: Parameters<IAlertRepository['updateChannel']>[1]): Promise<Channel | null> {
    const [r] = await this.db.update(alertChannels).set(patch).where(and(eq(alertChannels.id, id), eq(alertChannels.companyId, tenant.id()))).returning();
    return r ? toChannel(r) : null;
  }
  async deleteChannel(id: string): Promise<boolean> {
    const gone = await this.db.delete(alertChannels).where(and(eq(alertChannels.id, id), eq(alertChannels.companyId, tenant.id()))).returning({ id: alertChannels.id });
    // Rules keep working without the channel instead of pointing at nothing.
    await this.db.execute(sql`update alert_rules set channel_ids = array_remove(channel_ids, ${id}::uuid) where company_id = ${tenant.id()} and ${id}::uuid = any(channel_ids)`);
    return gone.length > 0;
  }

  private async withCounts(where?: SQL): Promise<Rule[]> {
    const res = await this.db.execute(sql`select r.*, (select count(*)::int from alert_log l where l.rule_id = r.id and l.result = 'sent'
        and l.at > now() - interval '30 days') as fired30 from alert_rules r where r.company_id = ${tenant.id()}${where ? sql` and ${where}` : sql``} order by r.created_at desc`);
    return rowsOf<Record<string, unknown>>(res).map((r) => ({
      id: r['id'] as string, name: r['name'] as string, trigger: r['trigger'] as Rule['trigger'], envs: r['envs'] as string[],
      minRisk: Number(r['min_risk']), exposedOnly: r['exposed_only'] as boolean, tag: r['tag'] as string,
      channelIds: r['channel_ids'] as string[], throttle: r['throttle'] as Rule['throttle'], enabled: r['enabled'] as boolean,
      lastFiredAt: r['last_fired_at'] ? new Date(r['last_fired_at'] as string) : null, evaluatedAt: new Date(r['evaluated_at'] as string),
      fired30: Number(r['fired30']),
    }));
  }
  rules(): Promise<Rule[]> {
    return this.withCounts();
  }
  async findRule(id: string): Promise<Rule | null> {
    return (await this.withCounts(sql`r.id = ${id}`))[0] ?? null;
  }
  async createRule(input: NewRule): Promise<Rule> {
    const [r] = await this.db.insert(alertRules).values({ ...input, companyId: tenant.id() }).returning({ id: alertRules.id });
    return (await this.findRule(r!.id))!;
  }
  async updateRule(id: string, patch: Partial<NewRule>): Promise<Rule | null> {
    const res = await this.db.update(alertRules).set(patch).where(and(eq(alertRules.id, id), eq(alertRules.companyId, tenant.id()))).returning({ id: alertRules.id });
    return res.length ? this.findRule(id) : null;
  }
  async deleteRule(id: string): Promise<boolean> {
    return (await this.db.delete(alertRules).where(and(eq(alertRules.id, id), eq(alertRules.companyId, tenant.id()))).returning({ id: alertRules.id })).length > 0;
  }
  async markEvaluated(id: string, at: Date, fired: boolean): Promise<void> {
    await this.db.update(alertRules).set(fired ? { evaluatedAt: at, lastFiredAt: at } : { evaluatedAt: at }).where(eq(alertRules.id, id));
  }

  async log(limit: number): Promise<LogEntry[]> {
    return (await this.db.select().from(alertLog).where(eq(alertLog.companyId, tenant.id())).orderBy(desc(alertLog.at)).limit(limit)).map(toLog);
  }
  async addLog(entry: NewLogEntry): Promise<LogEntry> {
    const [r] = await this.db.insert(alertLog).values({ ...entry, companyId: tenant.id() }).returning();
    return toLog(r!);
  }
  async recentlyNotifiedAssets(ruleId: string, since: Date): Promise<Set<string>> {
    const rows = await this.db
      .select({ assetId: alertLog.assetId })
      .from(alertLog)
      .where(and(eq(alertLog.ruleId, ruleId), eq(alertLog.result, 'sent'), sql`${alertLog.at} > ${since}`));
    return new Set(rows.map((r) => r.assetId).filter((x): x is string => !!x));
  }

  private ruleFilters(rule: Rule): SQL[] {
    const c: SQL[] = [sql`a.company_id = ${tenant.id()}`];
    if (rule.envs.length) c.push(sql`a.env in (${sql.join(rule.envs.map((e) => sql`${e}`), sql`, `)})`);
    if (rule.exposedOnly) c.push(sql`a.exposed`);
    if (rule.tag.trim()) c.push(sql`${rule.tag.trim()} = any(a.tags)`);
    return c;
  }

  async newMatches(rule: Rule, since: Date, kind: 'kev' | 'critical' | 'epss'): Promise<AlertEvent[]> {
    const c = [sql`av.first_seen_at > ${since}`, sql`av.status in ('open', 'in_progress')`, ...this.ruleFilters(rule)];
    c.push(kind === 'kev' ? sql`c.is_kev` : kind === 'critical' ? sql`c.cvss_severity = 4` : sql`c.epss >= 0.5`);
    const res = await this.db.execute(sql`select * from (select a.id as asset_id, a.name as host, av.cve_id, ${RISK} as risk, c.cvss_score
      from asset_vulns av join assets a on a.id = av.asset_id join cve c on c.id = av.cve_id where ${sql.join(c, sql` and `)}) x
      where risk >= ${rule.minRisk} order by risk desc limit 500`);
    return rowsOf<Record<string, unknown>>(res).map((r) => ({
      assetId: r['asset_id'] as string, host: r['host'] as string, cveId: r['cve_id'] as string, risk: Number(r['risk']),
      line: `${r['cve_id']} × ${r['host']} (CVSS ${Number(r['cvss_score']).toFixed(1)}, risk ${r['risk']})`,
    }));
  }

  async slaMatches(rule: Rule, hours: number): Promise<AlertEvent[]> {
    const c = [sql`av.status in ('open', 'in_progress')`, ...this.ruleFilters(rule)];
    const res = await this.db.execute(sql`select * from (select a.id as asset_id, a.name as host, av.cve_id, ${RISK} as risk,
        ${SLA_LEFT_SQL} as left_h
      from asset_vulns av join assets a on a.id = av.asset_id join cve c on c.id = av.cve_id where ${sql.join(c, sql` and `)}) x
      where risk >= ${rule.minRisk} and left_h <= ${hours} order by left_h limit 500`);
    return rowsOf<Record<string, unknown>>(res).map((r) => {
      const left = Math.round(Number(r['left_h']));
      return {
        assetId: r['asset_id'] as string, host: r['host'] as string, cveId: r['cve_id'] as string, risk: Number(r['risk']),
        line: `${r['cve_id']} × ${r['host']} (${left < 0 ? `${-left} h overdue` : `${left} h left`})`,
      };
    });
  }

  async failedSyncs(since: Date): Promise<{ source: string; error: string }[]> {
    const res = await this.db.execute(sql`select source, last_error from sync_state where status = 'error' and last_finished_at > ${since}`);
    return rowsOf<{ source: string; last_error: string | null }>(res).map((r) => ({ source: r.source, error: r.last_error ?? 'unknown error' }));
  }

  async digestCounts() {
    const res = await this.db.execute(sql`select
      count(*) filter (where av.status in ('open', 'in_progress'))::int as open,
      count(*) filter (where av.status in ('open', 'in_progress') and c.is_kev)::int as kev,
      count(*) filter (where av.status in ('open', 'in_progress') and c.cvss_severity = 4)::int as critical
      from asset_vulns av join assets a on a.id = av.asset_id join cve c on c.id = av.cve_id where a.company_id = ${tenant.id()}`);
    const r = rowsOf<Record<string, number>>(res)[0] ?? {};
    return { open: Number(r['open'] ?? 0), kev: Number(r['kev'] ?? 0), critical: Number(r['critical'] ?? 0) };
  }
}
