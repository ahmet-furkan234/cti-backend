/** 0 = unscored, 1 = low, 2 = medium, 3 = high, 4 = critical */
export type SeverityLevel = 0 | 1 | 2 | 3 | 4;

export interface CveReference {
  url: string;
  source?: string;
  tags?: string[];
}

export interface Cve {
  id: string;
  published: Date;
  lastModified: Date;
  vulnStatus: string | null;
  description: string;
  cvssScore: number;
  cvssSeverity: SeverityLevel;
  cvssVector: string | null;
  cvssVersion: string | null;
  cwe: string[];
  isKev: boolean;
  kevAdded: Date | null;
  kevDueDate: Date | null;
  kevRansomware: boolean;
  epss: number;
  epssPercentile: number;
  references: CveReference[];
  /** lowercase "vendor:product" pairs derived from CPE matches */
  affected: string[];
  vendors: string[];
  /** Vulnerable CPE matches with version ranges */
  cpeMatches: CpeMatch[];
}

export interface CpeMatch {
  /** CPE 2.3 criteria string */
  c: string;
  /** version ranges: start including/excluding, end including/excluding */
  vsi?: string;
  vse?: string;
  vei?: string;
  vee?: string;
}

export type CveSort = 'published' | 'modified' | 'cvss' | 'epss';

export interface SearchCvesQuery {
  q?: string | undefined;
  severities?: SeverityLevel[] | undefined;
  cvssMin?: number | undefined;
  cvssMax?: number | undefined;
  kev?: boolean | undefined;
  epssMin?: number | undefined;
  publishedFrom?: Date | undefined;
  publishedTo?: Date | undefined;
  vendor?: string | undefined;
  product?: string | undefined;
  cwe?: string | undefined;
  /** only CVEs with an unresolved match on the current company's assets, optionally narrowed to some of them */
  assetScope?: { exposed?: boolean | undefined; env?: string | undefined } | undefined;
  /** add how many of the company's assets each CVE affects */
  assetCounts?: boolean | undefined;
  sort: CveSort;
  order: 'asc' | 'desc';
  limit: number;
  cursor?: string | undefined;
  includeTotal?: boolean | undefined;
}

export interface CveListItem {
  id: string;
  published: Date;
  lastModified: Date;
  description: string;
  cvssScore: number;
  cvssSeverity: SeverityLevel;
  isKev: boolean;
  epss: number;
  affected: string[];
  /** unresolved matches on the current company's assets; only present when asked for */
  affectedAssets?: number;
}

export interface SearchCvesResult {
  items: CveListItem[];
  nextCursor: string | null;
  total?: number;
}

export interface CveStats {
  total: number;
  kevCount: number;
  criticalCount: number;
  addedLast24h: number;
  severityDistribution: { severity: SeverityLevel; count: number }[];
  perDay: { day: string; count: number }[];
  topCwe: { cwe: string; count: number }[];
  topVendors: { vendor: string; count: number }[];
  newestKev: { id: string; kevAdded: Date | null; description: string; cvssScore: number }[];
}

/** Read side only — ingestion lives in the cti-sync-worker service. */
export interface ICveRepository {
  search(query: SearchCvesQuery): Promise<SearchCvesResult>;
  findById(id: string): Promise<Cve | null>;
  stats(): Promise<CveStats>;
}
