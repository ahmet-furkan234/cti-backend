import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { ListVulnsQuery } from '../../../domain/vuln/vuln.repository.interface.js';
import type { VulnStatus } from '../../../domain/vuln/risk.js';
import type { Actor } from '../../../application/shared/actor.js';
import {
  ListCveAssetsUseCase, ListVulnsUseCase, RematchVulnsUseCase, SetVulnStatusUseCase,
} from '../../../application/vuln/vuln.use-cases.js';

@injectable()
export class VulnController {
  constructor(
    @inject(TYPES.ListVulnsUseCase) private readonly list_: ListVulnsUseCase,
    @inject(TYPES.ListCveAssetsUseCase) private readonly cveAssets_: ListCveAssetsUseCase,
    @inject(TYPES.SetVulnStatusUseCase) private readonly status_: SetVulnStatusUseCase,
    @inject(TYPES.RematchVulnsUseCase) private readonly rematch_: RematchVulnsUseCase,
  ) {}

  list(q: ListVulnsQuery) { return this.list_.execute(q); }
  forCve(id: string) { return this.cveAssets_.execute(id.toUpperCase()); }
  setStatus(actor: Actor, ids: string[], status: VulnStatus) { return this.status_.execute(actor, ids, status); }
  rematch(actor: Actor) { return this.rematch_.execute(actor); }
}
