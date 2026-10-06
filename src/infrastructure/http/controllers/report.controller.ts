import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { Format, NewSchedule, TemplateId } from '../../../domain/report/report.repository.interface.js';
import type { Actor } from '../../../application/shared/actor.js';
import { ReportUseCases } from '../../../application/report/report.use-cases.js';

@injectable()
export class ReportController {
  constructor(@inject(TYPES.ReportUseCases) private readonly uc: ReportUseCases) {}

  async schedules() { return { items: await this.uc.schedules() }; }
  createSchedule(actor: Actor, b: NewSchedule) { return this.uc.createSchedule(actor, b); }
  updateSchedule(actor: Actor, id: string, b: Partial<NewSchedule>) { return this.uc.updateSchedule(actor, id, b); }
  deleteSchedule(actor: Actor, id: string) { return this.uc.deleteSchedule(actor, id); }
  async runs() { return { items: await this.uc.runs() }; }
  generate(actor: Actor, b: { template: TemplateId; scope: string | null; formats: Format[]; periodDays: number; recipients: string[] }) { return this.uc.generate(actor, b); }
  retry(actor: Actor, id: string) { return this.uc.retry(actor, id); }
  download(id: string) { return this.uc.download(id); }
}
