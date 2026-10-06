import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { NewChannel, NewRule } from '../../../domain/alerts/alert.repository.interface.js';
import type { Actor } from '../../../application/shared/actor.js';
import { AlertUseCases } from '../../../application/alerts/alert.use-cases.js';

@injectable()
export class AlertController {
  constructor(@inject(TYPES.AlertUseCases) private readonly uc: AlertUseCases) {}

  async channels(canSeeSecrets: boolean) {
    const items = await this.uc.channels();
    return { items: canSeeSecrets ? items : items.map((c) => ({ ...c, values: {} })) };
  }
  createChannel(actor: Actor, body: NewChannel) { return this.uc.createChannel(actor, body); }
  updateChannel(actor: Actor, id: string, body: Partial<NewChannel>) { return this.uc.updateChannel(actor, id, body); }
  deleteChannel(actor: Actor, id: string) { return this.uc.deleteChannel(actor, id); }
  testChannel(id: string) { return this.uc.testChannel(id); }
  async rules() { return { items: await this.uc.rules() }; }
  createRule(actor: Actor, body: NewRule) { return this.uc.createRule(actor, body); }
  updateRule(actor: Actor, id: string, body: Partial<NewRule>) { return this.uc.updateRule(actor, id, body); }
  deleteRule(actor: Actor, id: string) { return this.uc.deleteRule(actor, id); }
  async log() { return { items: await this.uc.log() }; }
}
