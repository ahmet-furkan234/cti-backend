import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { IAssetRepository } from '../../domain/inventory/inventory.repository.interface.js';
import type { FoundMatch, IVulnRepository } from '../../domain/vuln/vuln.repository.interface.js';
import { componentsOf } from '../../domain/vuln/components.js';
import { matchVersion } from '../../domain/vuln/matching.js';
import type { ILogger } from '../ports/ports.js';
import { ProductCatalogService } from './product-catalog.service.js';

/** Matches what the inventory says is installed against the vulnerable CPE ranges in the CVE database. */
@injectable()
export class MatchAssetsService {
  constructor(
    @inject(TYPES.IAssetRepository) private readonly assets: IAssetRepository,
    @inject(TYPES.IVulnRepository) private readonly vulns: IVulnRepository,
    @inject(TYPES.ProductCatalogService) private readonly catalog: ProductCatalogService,
    @inject(TYPES.ILogger) private readonly logger: ILogger,
  ) {}

  /** One asset, or the whole inventory when no id is given. Returns how many matches were stored. */
  async run(assetId?: string): Promise<{ assets: number; matches: number }> {
    const list = await this.assets.forMatching(assetId);
    const products = await this.catalog.get();
    let total = 0;
    for (const asset of list) {
      const found = new Map<string, FoundMatch>();
      for (const comp of componentsOf(asset)) {
        // Without a version there is nothing to compare: skipping beats reporting every CVE of the product.
        if (!comp.version) continue;
        const pairs = comp.vendor ? [`${comp.vendor}:${comp.product}`] : products.pairsOf(comp.product);
        if (pairs.length === 0) continue;
        for (const cand of await this.vulns.candidates(pairs)) {
          for (const pair of pairs) {
            const verdict = matchVersion(cand.cpeMatches, pair, comp.version);
            if (!verdict.vulnerable) continue;
            found.set(`${cand.id}|${pair}`, {
              cveId: cand.id, component: pair, installedVersion: comp.version, fixedVersion: verdict.fixedIn,
            });
          }
        }
      }
      await this.vulns.replaceMatches(asset.id, [...found.values()]);
      total += found.size;
    }
    this.logger.info({ assets: list.length, matches: total }, 'asset matching finished');
    return { assets: list.length, matches: total };
  }
}
