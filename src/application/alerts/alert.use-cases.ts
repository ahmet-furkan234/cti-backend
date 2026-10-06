import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { IAlertRepository, NewChannel, NewRule } from '../../domain/alerts/alert.repository.interface.js';
import { NotFoundException } from '../../domain/common/exceptions.js';
import { AuditService } from '../audit/audit.service.js';
import { AlertEvaluatorService } from './alert-evaluator.service.js';
import { auditActor, type Actor } from '../shared/actor.js';
import { AuditAction, Entity } from '../../shared/strings.js';

@injectable()
export class AlertUseCases {
  constructor(
    @inject(TYPES.IAlertRepository) private readonly repo: IAlertRepository,
    @inject(TYPES.AlertEvaluatorService) private readonly evaluator: AlertEvaluatorService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  /** Secrets never leave the server in clear text except to people allowed to manage channels. */
  channels() { return this.repo.channels(); }
  rules() { return this.repo.rules(); }
  async log() { return this.repo.log(200); }

  async createChannel(actor: Actor, input: NewChannel) {
    const c = await this.repo.createChannel(input);
    await this.audit.record(auditActor(actor), AuditAction.channelCreated, { type: 'channel', id: c.id }, { kind: c.kind });
    return c;
  }

  async updateChannel(actor: Actor, id: string, patch: Partial<NewChannel>) {
    const c = await this.repo.updateChannel(id, patch);
    if (!c) throw new NotFoundException(Entity.channel);
    await this.audit.record(auditActor(actor), AuditAction.channelUpdated, { type: 'channel', id });
    return c;
  }

  async deleteChannel(actor: Actor, id: string) {
    if (!(await this.repo.deleteChannel(id))) throw new NotFoundException(Entity.channel);
    await this.audit.record(auditActor(actor), AuditAction.channelDeleted, { type: 'channel', id });
  }

  async testChannel(id: string) {
    const channel = await this.repo.findChannel(id);
    if (!channel) throw new NotFoundException(Entity.channel);
    const { failed } = await this.evaluator.deliver([id], '[CTI] Test message', 'This is a test of the alert channel.');
    const updated = (await this.repo.findChannel(id))!;
    return { ok: failed.length === 0, why: failed[0]?.why ?? null, channel: updated };
  }

  async createRule(actor: Actor, input: NewRule) {
    const r = await this.repo.createRule(input);
    await this.audit.record(auditActor(actor), AuditAction.ruleCreated, { type: 'rule', id: r.id }, { trigger: r.trigger });
    return r;
  }

  async updateRule(actor: Actor, id: string, patch: Partial<NewRule>) {
    const r = await this.repo.updateRule(id, patch);
    if (!r) throw new NotFoundException(Entity.rule);
    await this.audit.record(auditActor(actor), AuditAction.ruleUpdated, { type: 'rule', id }, { fields: Object.keys(patch) });
    return r;
  }

  async deleteRule(actor: Actor, id: string) {
    if (!(await this.repo.deleteRule(id))) throw new NotFoundException(Entity.rule);
    await this.audit.record(auditActor(actor), AuditAction.ruleDeleted, { type: 'rule', id });
  }
}
