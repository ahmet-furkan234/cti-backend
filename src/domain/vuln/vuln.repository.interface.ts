import type { CpeMatch, SeverityLevel } from '../cve/cve.repository.interface.js';
import type { VulnStatus } from './risk.js';

export interface MatchCandidate {
  id: string;
  cvssScore: number;
  cpeMatches: CpeMatch[];
}

export interface FoundMatch {
  cveId: string;
  component: string;
  installedVersion: string | null;
  fixedVersion: string | null;
}

export interface VulnRow {
  id: string;
  cve: string;
  assetId: string;
  host: string;
  env: string;
  exposed: boolean;
  kev: boolean;
  cvss: number;
  severity: SeverityLevel;
  epss: number;
  status: VulnStatus;
  firstSeenAt: Date;
  component: string;
  installedVersion: string | null;
  fixedVersion: string | null;
}

export interface ListVulnsQuery {
  q?: string | undefined;
  status?: VulnStatus | undefined;
  kev?: boolean | undefined;
  exposed?: boolean | undefined;
  assetId?: string | undefined;
  cveId?: string | undefined;
  limit: number;
}

/** A CVE × asset match as shown on the CVE detail page. */
export interface CveAssetRow extends VulnRow {
  ip: string | null;
  os: string | null;
  owner: string | null;
  source: string;
  lastSeenAt: Date;
}

export interface SoftwareAliasRow {
  id: string;
  name: string;
  pair: string;
  createdAt: Date;
}

export interface IVulnRepository {
  aliases(): Promise<SoftwareAliasRow[]>;
  /** null when the name is already taken */
  createAlias(input: { name: string; pair: string; createdBy: string | null }): Promise<SoftwareAliasRow | null>;
  deleteAlias(id: string): Promise<boolean>;
  /** CVEs naming any of the given "vendor:product" pairs */
  candidates(pairs: string[]): Promise<MatchCandidate[]>;
  /** every "vendor:product" named by the CVE data, with how many CVEs name it */
  productPairs(): Promise<{ pair: string; cves: number }[]>;
  /** makes the stored matches of an asset equal to `found` (keeps status of surviving rows) */
  replaceMatches(assetId: string, found: FoundMatch[]): Promise<void>;
  list(query: ListVulnsQuery): Promise<VulnRow[]>;
  forCve(cveId: string): Promise<CveAssetRow[]>;
  setStatus(ids: string[], status: VulnStatus, actorId: string): Promise<number>;
}
