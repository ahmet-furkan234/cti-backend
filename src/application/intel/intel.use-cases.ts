import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { FindingsQuery, IIntelRepository, ListIocsQuery, NewIoc, NewWatchlist } from '../../domain/intel/intel.repository.interface.js';
import { NotFoundException } from '../../domain/common/exceptions.js';
import { AuditService } from '../audit/audit.service.js';
import { auditActor, type Actor } from '../shared/actor.js';
import { AuditAction, Entity } from '../../shared/strings.js';

@injectable()
export class IntelUseCases {
  constructor(
    @inject(TYPES.IIntelRepository) private readonly repo: IIntelRepository,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  watchlists() { return this.repo.watchlists(); }
  iocs(q: ListIocsQuery) { return this.repo.iocs(q); }
  findings(q: FindingsQuery) { return this.repo.findings(q); }
  iocAssets(id: string) { return this.repo.iocAssets(id); }
  newKev(days: number) { return this.repo.newKev(days, 20); }

  async createWatchlist(actor: Actor, input: NewWatchlist) {
    const w = await this.repo.createWatchlist(input);
    await this.audit.record(auditActor(actor), AuditAction.watchlistChanged, { type: 'watchlist', id: w.id }, { change: 'created' });
    return w;
  }
  async updateWatchlist(actor: Actor, id: string, patch: Partial<NewWatchlist>) {
    const w = await this.repo.updateWatchlist(id, patch);
    if (!w) throw new NotFoundException(Entity.watchlist);
    await this.audit.record(auditActor(actor), AuditAction.watchlistChanged, { type: 'watchlist', id }, { change: 'updated' });
    return w;
  }
  async deleteWatchlist(actor: Actor, id: string) {
    if (!(await this.repo.deleteWatchlist(id))) throw new NotFoundException(Entity.watchlist);
    await this.audit.record(auditActor(actor), AuditAction.watchlistChanged, { type: 'watchlist', id }, { change: 'deleted' });
  }
  async addIocs(actor: Actor, items: NewIoc[]) {
    const added = await this.repo.addIocs(items);
    await this.audit.record(auditActor(actor), AuditAction.indicatorChanged, undefined, { change: 'added', added, received: items.length });
    return { added, duplicates: items.length - added };
  }
  async deleteIoc(actor: Actor, id: string) {
    if (!(await this.repo.deleteIoc(id))) throw new NotFoundException(Entity.indicator);
    await this.audit.record(auditActor(actor), AuditAction.indicatorChanged, { type: 'indicator', id }, { change: 'deleted' });
  }
}
