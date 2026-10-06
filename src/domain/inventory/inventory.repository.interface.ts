export type AssetType = 'fw' | 'server' | 'web' | 'db' | 'container' | 'cloud' | 'laptop';
export type Criticality = 'critical' | 'high' | 'medium' | 'low';
export type AssetStatus = 'active' | 'stale' | 'archived';
export type AssetAttrs = Record<string, string | boolean>;

export interface SoftwareItem {
  vendor: string | null;
  product: string;
  version: string | null;
}

export interface NewAsset {
  type: AssetType;
  name: string;
  addr: string | null;
  os: string | null;
  env: string;
  criticality: Criticality;
  exposed: boolean;
  source: string;
  owner: string | null;
  tags: string[];
  attrs: AssetAttrs;
  software: SoftwareItem[];
  createdBy: string | null;
}

export type AssetPatch = Partial<Omit<NewAsset, 'createdBy'>> & { archived?: boolean; /** bump "last seen" (an import saw the asset again) */ seen?: boolean };

export interface Asset {
  id: string;
  type: AssetType;
  name: string;
  addr: string | null;
  os: string | null;
  env: string;
  criticality: Criticality;
  exposed: boolean;
  source: string;
  owner: string | null;
  tags: string[];
  attrs: AssetAttrs;
  status: AssetStatus;
  lastSeenAt: Date;
  createdAt: Date;
  updatedAt: Date;
  software: SoftwareItem[];
}

export interface AssetListItem extends Omit<Asset, 'software' | 'attrs'> {
  risk: number;
  /** open vulnerabilities by severity: critical, high, medium, low */
  counts: [number, number, number, number];
}

export type AssetTab = 'all' | 'srv' | 'ep' | 'net' | 'ctr' | 'cld';
export type AssetSort = 'risk' | 'seen' | 'name';

export interface ListAssetsQuery {
  q?: string | undefined;
  tab: AssetTab;
  exposed?: boolean | undefined;
  criticalVulns?: boolean | undefined;
  stale?: boolean | undefined;
  env?: string | undefined;
  criticality?: Criticality | undefined;
  sort: AssetSort;
  page: number;
  pageSize: number;
}

export interface AssetStats {
  total: number;
  active: number;
  stale: number;
  archived: number;
  exposed: number;
  withCritical: number;
  tabs: Record<AssetTab, number>;
}

export interface ListAssetsResult {
  items: AssetListItem[];
  /** matches of the current filter */
  total: number;
  stats: AssetStats;
}

export interface ImportRecord {
  id: string;
  source: string;
  kind: string;
  rows: number;
  created: number;
  updated: number;
  skipped: number;
  status: 'healthy' | 'degraded' | 'failing';
  createdAt: Date;
}

export type NewImportRecord = Omit<ImportRecord, 'id' | 'createdAt'> & { createdBy: string | null };

export interface IAssetRepository {
  list(query: ListAssetsQuery): Promise<ListAssetsResult>;
  findById(id: string): Promise<Asset | null>;
  /** by name (case-insensitive) or, failing that, by address */
  findByIdentity(name: string | null, addr: string | null): Promise<Asset | null>;
  create(input: NewAsset): Promise<Asset>;
  update(id: string, patch: AssetPatch): Promise<Asset | null>;
  delete(id: string): Promise<boolean>;
  /** all assets (with software) or a single one, for CVE matching */
  forMatching(id?: string): Promise<Asset[]>;
  imports(limit: number): Promise<ImportRecord[]>;
  recordImport(input: NewImportRecord): Promise<ImportRecord>;
}
