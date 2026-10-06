import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { IVulnRepository } from '../../domain/vuln/vuln.repository.interface.js';
import { ProductIndex } from '../../domain/vuln/product-index.js';

const TTL_MS = 3_600_000;

/** The products the CVE data names, kept in memory (about a hundred thousand names) and refreshed hourly. */
@injectable()
export class ProductCatalogService {
  private index: ProductIndex | null = null;
  private loadedAt = 0;
  private loading: Promise<ProductIndex> | null = null;

  constructor(@inject(TYPES.IVulnRepository) private readonly vulns: IVulnRepository) {}

  /** Forget what was loaded (the team's names changed); the next `get` reloads. */
  invalidate(): void {
    this.index = null; // callers wait for the reload instead of seeing the old names
  }

  async get(): Promise<ProductIndex> {
    if (this.index && Date.now() - this.loadedAt < TTL_MS) return this.index;
    this.loading ??= Promise.all([this.vulns.productPairs(), this.vulns.aliases()])
      .then(([pairs, aliases]) => {
        this.index = new ProductIndex(pairs, aliases.map((a) => ({ name: a.name, pair: a.pair })));
        this.loadedAt = Date.now();
        return this.index;
      })
      .finally(() => (this.loading = null));
    return this.index ?? this.loading;
  }
}
