import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { IVulnRepository } from '../../domain/vuln/vuln.repository.interface.js';
import { RELEASE_SOURCES, newestFirst, tagVersions, versionsFromMatches } from '../../domain/vuln/known-versions.js';
import type { ProductCatalogService } from './product-catalog.service.js';

const TTL_MS = 6 * 3_600_000;
const FETCH_TIMEOUT_MS = 8_000;

/** Versions to offer for a product: what the CVE data mentions plus the latest releases from the project's own git tags. */
@injectable()
export class ProductVersionsService {
  private readonly cache = new Map<string, { at: number; versions: string[] }>();
  private readonly releases = new Map<string, { at: number; versions: string[] }>();

  constructor(
    @inject(TYPES.ProductCatalogService) private readonly catalog: ProductCatalogService,
    @inject(TYPES.IVulnRepository) private readonly vulns: IVulnRepository,
  ) {}

  async versions(product: string): Promise<string[]> {
    const index = await this.catalog.get();
    const pairs = index.pairsOf(product);
    if (pairs.length === 0) return [];
    const key = pairs.join(',');
    const hit = this.cache.get(key);
    if (hit && Date.now() - hit.at < TTL_MS) return hit.versions;
    const name = pairs[0]!.slice(pairs[0]!.indexOf(':') + 1);
    const [candidates, latest] = await Promise.all([this.vulns.candidates(pairs), this.latestReleases(name)]);
    const versions = newestFirst([...versionsFromMatches(candidates.flatMap((c) => c.cpeMatches), pairs), ...latest]);
    this.cache.set(key, { at: Date.now(), versions });
    return versions;
  }

  /** Never throws: with no network (or a rate limit) the CVE-derived list is simply used alone. */
  private async latestReleases(product: string): Promise<string[]> {
    const source = RELEASE_SOURCES[product];
    if (!source) return [];
    const hit = this.releases.get(product);
    if (hit && Date.now() - hit.at < TTL_MS) return hit.versions;
    let versions: string[] = [];
    try {
      // The git "info/refs" advertisement lists every tag in one response and, unlike the REST API, has no
      // 60-requests-an-hour limit and no 100-tag page.
      const res = await fetch(`https://github.com/${source.repo}.git/info/refs?service=git-upload-pack`, {
        headers: { 'user-agent': 'git/2.43' },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (res.ok) versions = tagVersions(await res.text(), source.tag);
    } catch {
      /* offline or rate limited */
    }
    this.releases.set(product, { at: Date.now() - (versions.length ? 0 : TTL_MS - 300_000), versions }); // retry a failure after 5 min
    return versions;
  }
}
