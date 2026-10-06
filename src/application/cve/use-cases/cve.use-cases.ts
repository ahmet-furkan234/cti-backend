import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { ICveRepository, SearchCvesQuery } from '../../../domain/cve/cve.repository.interface.js';
import { CveId } from '../../../domain/common/value-objects/cve-id.value-object.js';
import { NotFoundException } from '../../../domain/common/exceptions.js';
import { Entity } from '../../../shared/strings.js';

@injectable()
export class SearchCvesUseCase {
  constructor(@inject(TYPES.ICveRepository) private readonly cves: ICveRepository) {}

  async execute(query: SearchCvesQuery) {
    const started = performance.now();
    const result = await this.cves.search(query);
    return { ...result, tookMs: Math.round(performance.now() - started) };
  }
}

@injectable()
export class GetCveUseCase {
  constructor(@inject(TYPES.ICveRepository) private readonly cves: ICveRepository) {}

  async execute(id: string) {
    const cve = await this.cves.findById(CveId.from(id).value);
    if (!cve) throw new NotFoundException(Entity.cve);
    return cve;
  }
}

const STATS_TTL_MS = 5 * 60_000;

@injectable()
export class GetCveStatsUseCase {
  private cached: { at: number; value: Awaited<ReturnType<ICveRepository['stats']>> } | null = null;

  constructor(@inject(TYPES.ICveRepository) private readonly cves: ICveRepository) {}

  async execute() {
    if (this.cached && Date.now() - this.cached.at < STATS_TTL_MS) return this.cached.value;
    const value = await this.cves.stats();
    this.cached = { at: Date.now(), value };
    return value;
  }
}
