import { COMMON_SOFTWARE, MIN_CVES } from './common-software.js';

export interface ProductSuggestion {
  product: string;
  /** vendors that ship a product of this name */
  vendors: string[];
  /** how many CVEs name it, used to rank */
  cves: number;
  /** true when the name is one the team defined (it stands for another product) */
  alias?: boolean;
  /** browse-list section (see common-software.ts); only set while nothing has been typed */
  group?: string;
}

export interface SoftwareAlias {
  /** the name people write, e.g. "Our ERP" */
  name: string;
  /** the product it stands for, "vendor:product" */
  pair: string;
}

/** Letters and digits only, lowercase: "Open-SSH", "open_ssh" and "openssh" all become "openssh". */
export const compact = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]/g, '');

/** Edit distance (a swap of two neighbours counts as one edit), giving up once it must exceed `max`. */
export function editDistance(a: string, b: string, max: number): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev2: number[] = [];
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, prev2[j - 2]! + 1);
      cur.push(v);
      if (v < best) best = v;
    }
    if (best > max) return max + 1;
    prev2 = prev;
    prev = cur;
  }
  return prev[b.length]!;
}

interface Entry {
  product: string;
  compact: string;
  vendors: string[];
  cves: number;
  alias?: boolean;
  vendorCves?: Map<string, number>;
}

/** The products the CVE data knows ("vendor:product" pairs), searchable by exact name, sloppy spelling or prefix. */
export class ProductIndex {
  private readonly byProduct = new Map<string, Entry>();
  private readonly byCompact = new Map<string, Entry[]>();
  private readonly aliasByCompact = new Map<string, { entry: Entry; pair: string }>();

  constructor(pairs: { pair: string; cves: number }[], aliases: SoftwareAlias[] = []) {
    for (const { pair, cves } of pairs) {
      const at = pair.indexOf(':');
      if (at < 1) continue;
      const vendor = pair.slice(0, at);
      const product = pair.slice(at + 1);
      let e = this.byProduct.get(product);
      if (!e) {
        e = { product, compact: compact(product), vendors: [], cves: 0, vendorCves: new Map() };
        this.byProduct.set(product, e);
        const list = this.byCompact.get(e.compact) ?? [];
        list.push(e);
        this.byCompact.set(e.compact, list);
      }
      e.vendors.push(vendor);
      e.cves += cves;
      e.vendorCves!.set(vendor, cves);
    }
    // The vendor that most CVEs name comes first: that is the one people mean.
    for (const e of this.byProduct.values()) e.vendors.sort((a, b) => (e.vendorCves!.get(b) ?? 0) - (e.vendorCves!.get(a) ?? 0));
    const cvesOf = new Map(pairs.map((p) => [p.pair, p.cves]));
    for (const a of aliases) {
      const entry: Entry = { product: a.name, compact: compact(a.name), vendors: [a.pair.split(':')[0] ?? ''], cves: cvesOf.get(a.pair) ?? 0, alias: true };
      if (entry.compact) this.aliasByCompact.set(entry.compact, { entry, pair: a.pair });
    }
  }

  /** Every "vendor:product" for a product name; falls back to spelling variants ("Open SSH" → openssh). */
  pairsOf(name: string): string[] {
    // A name the team defined always wins over a same-named product.
    const alias = this.aliasByCompact.get(compact(name));
    if (alias) return [alias.pair];
    const exact = this.byProduct.get(name.toLowerCase().replace(/\s+/g, '_'));
    const entries = exact ? [exact] : (this.byCompact.get(compact(name)) ?? []);
    return entries.flatMap((e) => e.vendors.map((v) => `${v}:${e.product}`));
  }

  /** Whether the CVE data names this exact "vendor:product". */
  hasPair(pair: string): boolean {
    const at = pair.indexOf(':');
    return at > 0 && (this.byProduct.get(pair.slice(at + 1))?.vendors.includes(pair.slice(0, at)) ?? false);
  }

  has(name: string): boolean {
    return this.pairsOf(name).length > 0;
  }

  /** Best guesses for a (partial or misspelt) name: prefix first, then contains, then close spellings. */
  suggest(name: string, limit = 5): ProductSuggestion[] {
    return this.rank(name, limit, false);
  }

  /** What a name picker offers while typing: like `suggest`, but an exact match is listed (first). */
  search(name: string, limit = 8): ProductSuggestion[] {
    return this.rank(name, limit, true);
  }

  private rank(name: string, limit: number, includeExact: boolean): ProductSuggestion[] {
    const q = compact(name);
    // An empty picker offers the team's own names first, then the products with the most CVEs (chip firmware is
    // left out of this browse list: it is not what an inventory lists, and it is still found by typing).
    if (includeExact && q.length === 0) {
      const own = [...this.aliasByCompact.values()].map(({ entry: e }) => ({ product: e.product, vendors: e.vendors, cves: e.cves, alias: true }));
      const common = COMMON_SOFTWARE.flatMap(({ group, products }) =>
        products.flatMap((p) => {
          const e = this.byProduct.get(p);
          return e && e.cves >= MIN_CVES ? [{ product: e.product, vendors: e.vendors, cves: e.cves, group }] : [];
        }),
      );
      return [...own, ...common].slice(0, limit);
    }
    if (q.length < (includeExact ? 1 : 2)) return [];
    const maxEdit = Math.max(1, Math.floor(q.length / 4));
    const scored: { e: Entry; score: number }[] = [];
    const entries = [...[...this.aliasByCompact.values()].map((a) => a.entry), ...this.byProduct.values()];
    for (const e of entries) {
      if (e.compact === q && !includeExact) continue;
      let score: number;
      if (e.compact === q) score = -1;
      else if (e.compact.startsWith(q)) score = 0;
      else if (q.length >= 3 && e.compact.includes(q)) score = 1;
      else {
        const d = editDistance(q, e.compact, maxEdit);
        if (d > maxEdit) continue;
        score = 1 + d;
      }
      scored.push({ e, score });
    }
    return scored
      .sort((a, b) => a.score - b.score || b.e.cves - a.e.cves)
      .slice(0, limit)
      .map(({ e }) => ({ product: e.product, vendors: e.vendors, cves: e.cves, ...(e.alias ? { alias: true } : {}) }));
  }
}
