import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { IAlertRepository } from '../../domain/alerts/alert.repository.interface.js';
import type { IReportRepository, Run, Schedule, TemplateId } from '../../domain/report/report.repository.interface.js';
import { latestSlot, toCsv } from '../../domain/report/schedule.js';
import type { ICompanyRepository } from '../../domain/company/company.repository.interface.js';
import type { IChannelDispatcher, ILogger } from '../ports/ports.js';
import { tenant } from '../../shared/tenant.js';

@injectable()
export class ReportService {
  constructor(
    @inject(TYPES.IReportRepository) private readonly repo: IReportRepository,
    @inject(TYPES.IAlertRepository) private readonly alerts: IAlertRepository,
    @inject(TYPES.ICompanyRepository) private readonly companies: ICompanyRepository,
    @inject(TYPES.IChannelDispatcher) private readonly dispatcher: IChannelDispatcher,
    @inject(TYPES.ILogger) private readonly logger: ILogger,
  ) {}

  /** Builds the CSV of an already-created run; failures are stored on the run instead of thrown. */
  async build(run: Run, periodDays = 30): Promise<string | null> {
    try {
      const table = await this.repo.data(run.template, run.scope, periodDays);
      const content = toCsv(table.header, table.rows);
      await this.repo.finishRun(run.id, { status: 'ready', content });
      return content;
    } catch (err) {
      this.logger.error({ err, run: run.id }, 'report generation failed');
      await this.repo.finishRun(run.id, { status: 'failed', error: err instanceof Error ? err.message : 'unknown error' });
      return null;
    }
  }

  /** Mails the file through the first configured e-mail channel; returns false when there is nothing to send through. */
  async mail(schedule: Pick<Schedule, 'template' | 'scope' | 'recipients'>, csv: string): Promise<boolean> {
    if (schedule.recipients.length === 0) return false;
    const channel = (await this.alerts.channels()).find((c) => c.kind === 'smtp');
    if (!channel) return false;
    const name = `${schedule.template}${schedule.scope ? `-${schedule.scope}` : ''}-${new Date().toISOString().slice(0, 10)}.csv`;
    try {
      await this.dispatcher.send(channel, {
        subject: `[CTI] ${schedule.template} report`, text: 'The report is attached.', to: schedule.recipients.join(', '),
        attachments: [{ filename: name, content: csv }],
      });
      return true;
    } catch (err) {
      this.logger.warn({ err }, 'report e-mail failed');
      return false;
    }
  }

  /** Runs every enabled schedule whose latest slot has not produced a report yet. */
  async tick(now = new Date()): Promise<void> {
    for (const company of await this.companies.active()) {
      await tenant.run({ companyId: company.id, platform: company.isPlatform }, () => this.tickCompany(now));
    }
  }

  private async tickCompany(now: Date): Promise<void> {
    const runs = await this.repo.runs(500);
    for (const s of await this.repo.schedules()) {
      if (!s.enabled) continue;
      const slot = latestSlot(s.freq, now);
      if (slot <= s.createdAt) continue; // never backfill before the schedule existed
      if (runs.some((r) => r.scheduleId === s.id && r.createdAt >= slot)) continue;
      const run = await this.repo.createRun({ scheduleId: s.id, template: s.template as TemplateId, scope: s.scope, formats: s.formats, manual: false, createdBy: null });
      const csv = await this.build(run);
      if (csv) await this.mail(s, csv);
    }
  }
}
