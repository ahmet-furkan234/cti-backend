export type IocType = 'ipv4' | 'ipv6' | 'cidr' | 'domain' | 'url' | 'email' | 'sha256' | 'sha1' | 'md5';

export interface Watchlist {
  id: string;
  name: string;
  vendors: string[];
  products: string[];
  tag: string;
  minCvss: number;
  kevOnly: boolean;
  minEpss: number;
  channelId: string | null;
  enabled: boolean;
  /** assets the list covers */
  count: number;
  /** open findings for those assets first seen in the last 7 days */
  hits: number;
}
export type NewWatchlist = Omit<Watchlist, 'id' | 'count' | 'hits'>;

export interface Ioc {
  id: string;
  type: IocType;
  value: string;
  source: string;
  confidence: number;
  expiresAt: Date | null;
  /** inventory assets the indicator points at */
  matches: number;
}
export type NewIoc = Pick<Ioc, 'type' | 'value'> & { source: string; confidence: number; expiresAt: Date | null };

export interface ListIocsQuery {
  q?: string | undefined;
  types?: IocType[] | undefined;
  onlyMatches?: boolean | undefined;
  limit: number;
  offset: number;
}

export interface IocList {
  items: Ioc[];
  total: number;
  /** all stored, not yet expired */
  active: number;
  /** expire within the next 7 days */
  expiring: number;
}

export interface WatchlistHit {
  line: string;
}

export interface FindingsQuery {
  /** only findings first seen within this many days */
  days: number;
  watchlistId?: string | undefined;
  limit: number;
}

/** An open finding on an asset that a watchlist follows. */
export interface WatchlistFinding {
  id: string;
  watchlistId: string;
  watchlist: string;
  cve: string;
  cvss: number;
  kev: boolean;
  epss: number;
  assetId: string;
  asset: string;
  env: string;
  component: string;
  firstSeenAt: Date;
}
export interface FindingList {
  items: WatchlistFinding[];
  total: number;
}

export interface IocAsset {
  id: string;
  name: string;
  addr: string | null;
  env: string;
  exposed: boolean;
  openVulns: number;
}

/** A CVE added to the known-exploited catalog recently, with how many of the company's assets it touches. */
export interface NewKev {
  cve: string;
  cvss: number;
  epss: number;
  ransomware: boolean;
  addedAt: Date;
  assets: number;
}

export interface IIntelRepository {
  findings(query: FindingsQuery): Promise<FindingList>;
  /** inventory assets the indicator points at */
  iocAssets(id: string): Promise<IocAsset[]>;
  newKev(days: number, limit: number): Promise<NewKev[]>;
  /** enabled lists that notify a channel, with the time they were last looked at */
  notifying(): Promise<{ id: string; name: string; channelId: string; evaluatedAt: Date }[]>;
  /** findings first seen after `since` that the list follows */
  hitsSince(id: string, since: Date): Promise<WatchlistHit[]>;
  markEvaluated(id: string, at: Date): Promise<void>;
  watchlists(): Promise<Watchlist[]>;
  createWatchlist(input: NewWatchlist): Promise<Watchlist>;
  updateWatchlist(id: string, patch: Partial<NewWatchlist>): Promise<Watchlist | null>;
  deleteWatchlist(id: string): Promise<boolean>;
  iocs(query: ListIocsQuery): Promise<IocList>;
  /** returns how many were new (existing type+value pairs are left alone) */
  addIocs(items: NewIoc[]): Promise<number>;
  deleteIoc(id: string): Promise<boolean>;
}
