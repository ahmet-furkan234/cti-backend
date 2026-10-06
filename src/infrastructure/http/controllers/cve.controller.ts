import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { SearchCvesQuery } from '../../../domain/cve/cve.repository.interface.js';
import { GetCveStatsUseCase, GetCveUseCase, SearchCvesUseCase } from '../../../application/cve/use-cases/cve.use-cases.js';

@injectable()
export class CveController {
  constructor(
    @inject(TYPES.SearchCvesUseCase)
    private readonly search_: SearchCvesUseCase,
    @inject(TYPES.GetCveUseCase) private readonly get_: GetCveUseCase,
    @inject(TYPES.GetCveStatsUseCase)
    private readonly stats_: GetCveStatsUseCase,
  ) {}

  search(q: SearchCvesQuery) {
    return this.search_.execute(q);
  }
  get(id: string) {
    return this.get_.execute(id);
  }
  stats() {
    return this.stats_.execute();
  }
}
