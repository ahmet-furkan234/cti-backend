import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { FindingsQuery, ListIocsQuery, NewIoc, NewWatchlist } from '../../../domain/intel/intel.repository.interface.js';
import type { Actor } from '../../../application/shared/actor.js';
import { IntelUseCases } from '../../../application/intel/intel.use-cases.js';

@injectable()
export class IntelController {
  constructor(@inject(TYPES.IntelUseCases) private readonly uc: IntelUseCases) {}

  async watchlists() { return { items: await this.uc.watchlists() }; }
  createWatchlist(actor: Actor, b: NewWatchlist) { return this.uc.createWatchlist(actor, b); }
  updateWatchlist(actor: Actor, id: string, b: Partial<NewWatchlist>) { return this.uc.updateWatchlist(actor, id, b); }
  deleteWatchlist(actor: Actor, id: string) { return this.uc.deleteWatchlist(actor, id); }
  iocs(q: ListIocsQuery) { return this.uc.iocs(q); }
  async findings(q: FindingsQuery) { return this.uc.findings(q); }
  async iocAssets(id: string) { return { items: await this.uc.iocAssets(id) }; }
  async newKev(days: number) { return { items: await this.uc.newKev(days) }; }
  addIocs(actor: Actor, items: NewIoc[]) { return this.uc.addIocs(actor, items); }
  deleteIoc(actor: Actor, id: string) { return this.uc.deleteIoc(actor, id); }
}
