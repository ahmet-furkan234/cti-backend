import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { AlertEvent, Channel, IAlertRepository, Rule } from '../../domain/alerts/alert.repository.interface.js';
import type { IIntelRepository } from '../../domain/intel/intel.repository.interface.js';
import type { ICompanyRepository } from '../../domain/company/company.repository.interface.js';
import type { IChannelDispatcher, ILogger } from '../ports/ports.js';
import { tenant } from '../../shared/tenant.js';

const HOUR = 3_600_000;
const SLA_SOON_HOURS = 24;
const MAX_LINES = 10;

/** Looks for what changed since each rule last looked, and announces it through the rule's channels. */
@injectable()
export class AlertEvaluatorService {
  constructor(
    @inject(TYPES.IAlertRepository) private readonly repo: IAlertRepository,
    @inject(TYPES.IIntelRepository) private readonly intel: IIntelRepository,
    @inject(TYPES.ICompanyRepository) private readonly companies: ICompanyRepository,
    @inject(TYPES.IChannelDispatcher) private readonly dispatcher: IChannelDispatcher,
    @inject(TYPES.ILogger) private readonly logger: ILogger,
  ) {}

  /** Delivers one message to the given channels and records the outcome on each channel. Returns the failures. */
  async deliver(channelIds: string[], subject: string, text: string): Promise<{ sent: Channel[]; failed: { channel: Channel; why: string }[] }> {
    const sent: Channel[] = [];
    const failed: { channel: Channel; why: string }[] = [];
    for (const id of channelIds) {
      const channel = await this.repo.findChannel(id);
      if (!channel) continue;
      try {
        await this.dispatcher.send(channel, { subject, text });
        sent.push(channel);
        await this.repo.updateChannel(id, { status: 'healthy', problem: null, lastTestAt: new Date() });
      } catch (err) {
        const why = err instanceof Error ? err.message : 'unknown error';
        failed.push({ channel, why });
        await this.repo.updateChannel(id, { status: 'failing', problem: why, lastTestAt: new Date() });
      }
    }
    return { sent, failed };
  }

  private async notify(rule: Rule, subject: string, events: AlertEvent[], intro = ''): Promise<boolean> {
    const lines = events.slice(0, MAX_LINES).map((e) => `• ${e.line}`);
    if (events.length > MAX_LINES) lines.push(`…and ${events.length - MAX_LINES} more`);
    const text = [intro, ...lines].filter(Boolean).join('\n');
    const { sent, failed } = await this.deliver(rule.channelIds, subject, text);
    const assetId = events.length === 1 ? events[0]!.assetId : null;
    if (sent.length) {
      await this.repo.addLog({ ruleId: rule.id, assetId, channelIds: sent.map((c) => c.id), result: 'sent', detail: events.length === 1 ? events[0]!.line : `${events.length}: ${subject}`.slice(0, 300) });
    }
    if (failed.length) {
      await this.repo.addLog({ ruleId: rule.id, assetId, channelIds: failed.map((f) => f.channel.id), result: 'failed', detail: failed.map((f) => `${f.channel.name}: ${f.why}`).join('; ').slice(0, 300) });
    }
    return sent.length > 0;
  }

  async evaluate(rule: Rule, now = new Date()): Promise<void> {
    if (!rule.enabled || rule.channelIds.length === 0) {
      await this.repo.markEvaluated(rule.id, now, false);
      return;
    }
    let fired = false;
    switch (rule.trigger) {
      case 'kev':
      case 'critical':
      case 'epss': {
        let events = await this.repo.newMatches(rule, rule.evaluatedAt, rule.trigger);
        if (rule.throttle === 'asset6h') {
          const recent = await this.repo.recentlyNotifiedAssets(rule.id, new Date(now.getTime() - 6 * HOUR));
          const skipped = events.filter((e) => recent.has(e.assetId));
          events = events.filter((e) => !recent.has(e.assetId));
          if (skipped.length) {
            await this.repo.addLog({ ruleId: rule.id, assetId: null, channelIds: rule.channelIds, result: 'throttled', detail: `${skipped.length}: already reported for these assets in the last 6 hours` });
          }
        }
        if (events.length) fired = await this.notify(rule, `[CTI] ${rule.name}`, events);
        break;
      }
      case 'sla': {
        // At most one reminder a day: the list is "what is still running out", not "what just changed".
        if (rule.lastFiredAt && now.getTime() - rule.lastFiredAt.getTime() < 24 * HOUR) break;
        const events = await this.repo.slaMatches(rule, SLA_SOON_HOURS);
        if (events.length) fired = await this.notify(rule, `[CTI] ${rule.name}`, events);
        break;
      }
      case 'sync': {
        const failures = await this.repo.failedSyncs(rule.evaluatedAt);
        if (failures.length) {
          const events = failures.map((f) => ({ assetId: '', host: f.source, cveId: '', risk: 0, line: `${f.source}: ${f.error}` }));
          fired = await this.notify(rule, `[CTI] ${rule.name}`, events);
        }
        break;
      }
      case 'digest': {
        if (rule.lastFiredAt && now.getTime() - rule.lastFiredAt.getTime() < 24 * HOUR) break;
        const d = await this.repo.digestCounts();
        const events = [{ assetId: '', host: '', cveId: '', risk: 0, line: `${d.open} open · ${d.kev} known-exploited · ${d.critical} critical` }];
        fired = await this.notify(rule, `[CTI] ${rule.name}`, events);
        break;
      }
    }
    await this.repo.markEvaluated(rule.id, now, fired);
  }

  /** Each company's rules and watchlists are evaluated on their own, against that company's data and channels. */
  async tick(): Promise<void> {
    for (const company of await this.companies.active()) {
      await tenant.run({ companyId: company.id, platform: company.isPlatform }, async () => {
        for (const rule of await this.repo.rules()) {
          try {
            await this.evaluate(rule);
          } catch (err) {
            this.logger.error({ err, rule: rule.id, company: company.id }, 'alert rule evaluation failed');
          }
        }
        await this.tickWatchlists();
      });
    }
  }

  /** Watchlists announce new findings on their own channel. */
  async tickWatchlists(now = new Date()): Promise<void> {
    for (const w of await this.intel.notifying()) {
      try {
        const hits = await this.intel.hitsSince(w.id, w.evaluatedAt);
        if (hits.length) {
          const lines = hits.slice(0, MAX_LINES).map((h) => `• ${h.line}`);
          if (hits.length > MAX_LINES) lines.push(`…and ${hits.length - MAX_LINES} more`);
          const { sent, failed } = await this.deliver([w.channelId], `[CTI] Watchlist: ${w.name}`, lines.join('\n'));
          if (sent.length) await this.repo.addLog({ ruleId: null, assetId: null, channelIds: [w.channelId], result: 'sent', detail: `${w.name}: ${hits.length} new finding(s)` });
          if (failed.length) await this.repo.addLog({ ruleId: null, assetId: null, channelIds: [w.channelId], result: 'failed', detail: `${w.name}: ${failed[0]!.why}` });
        }
        await this.intel.markEvaluated(w.id, now);
      } catch (err) {
        this.logger.error({ err, watchlist: w.id }, 'watchlist evaluation failed');
      }
    }
  }
}
