import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { Format, IReportRepository, NewSchedule, TemplateId } from '../../domain/report/report.repository.interface.js';
import { NotFoundException, InvalidStateException } from '../../domain/common/exceptions.js';
import { AuditService } from '../audit/audit.service.js';
import { ReportService } from './report.service.js';
import { auditActor, type Actor } from '../shared/actor.js';
import { AuditAction, Entity, Errors } from '../../shared/strings.js';

@injectable()
export class ReportUseCases {
  constructor(
    @inject(TYPES.IReportRepository) private readonly repo: IReportRepository,
    @inject(TYPES.ReportService) private readonly service: ReportService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  schedules() { return this.repo.schedules(); }
  runs() { return this.repo.runs(100); }

  async createSchedule(actor: Actor, input: NewSchedule) {
    const s = await this.repo.createSchedule(input);
    await this.audit.record(auditActor(actor), AuditAction.reportScheduleChanged, { type: 'schedule', id: s.id }, { change: 'created', template: s.template });
    return s;
  }
  async updateSchedule(actor: Actor, id: string, patch: Partial<NewSchedule>) {
    const s = await this.repo.updateSchedule(id, patch);
    if (!s) throw new NotFoundException(Entity.schedule);
    await this.audit.record(auditActor(actor), AuditAction.reportScheduleChanged, { type: 'schedule', id }, { change: 'updated' });
    return s;
  }
  async deleteSchedule(actor: Actor, id: string) {
    if (!(await this.repo.deleteSchedule(id))) throw new NotFoundException(Entity.schedule);
    await this.audit.record(auditActor(actor), AuditAction.reportScheduleChanged, { type: 'schedule', id }, { change: 'deleted' });
  }

  /** Generates a report now; with recipients it is also e-mailed. */
  async generate(actor: Actor, input: { template: TemplateId; scope: string | null; formats: Format[]; periodDays: number; recipients: string[] }) {
    const run = await this.repo.createRun({ scheduleId: null, template: input.template, scope: input.scope, formats: input.formats, manual: true, createdBy: actor.id });
    const csv = await this.service.build(run, input.periodDays);
    if (csv && input.recipients.length) await this.service.mail({ template: input.template, scope: input.scope, recipients: input.recipients }, csv);
    await this.audit.record(auditActor(actor), AuditAction.reportGenerated, { type: 'report', id: run.id }, { template: input.template });
    return (await this.repo.findRun(run.id))!;
  }

  async retry(actor: Actor, id: string) {
    const run = await this.repo.findRun(id);
    if (!run) throw new NotFoundException(Entity.report);
    return this.generate(actor, { template: run.template, scope: run.scope, formats: run.formats, periodDays: 30, recipients: [] });
  }

  async download(id: string) {
    const run = await this.repo.findRun(id);
    if (!run) throw new NotFoundException(Entity.report);
    const content = await this.repo.content(id);
    if (run.status !== 'ready' || !content) throw new InvalidStateException(Errors.reportNotReady);
    return { filename: `${run.template}${run.scope ? `-${run.scope}` : ''}-${run.createdAt.toISOString().slice(0, 10)}.csv`, content };
  }
}
