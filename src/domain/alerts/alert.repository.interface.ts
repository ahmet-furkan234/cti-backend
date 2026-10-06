export type ChannelKind = 'slack' | 'smtp' | 'telegram' | 'webhook';
export type ChannelStatus = 'healthy' | 'degraded' | 'failing';
export type Trigger = 'kev' | 'critical' | 'sla' | 'epss' | 'sync' | 'digest';
export type Throttle = 'every' | 'asset6h' | 'daily';

export interface Channel {
  id: string;
  kind: ChannelKind;
  name: string;
  values: Record<string, string>;
  status: ChannelStatus;
  problem: string | null;
  lastTestAt: Date | null;
}
export type NewChannel = Pick<Channel, 'kind' | 'name' | 'values'>;

export interface Rule {
  id: string;
  name: string;
  trigger: Trigger;
  envs: string[];
  minRisk: number;
  exposedOnly: boolean;
  tag: string;
  channelIds: string[];
  throttle: Throttle;
  enabled: boolean;
  lastFiredAt: Date | null;
  evaluatedAt: Date;
  /** times it fired in the last 30 days */
  fired30: number;
}
export type NewRule = Omit<Rule, 'id' | 'lastFiredAt' | 'evaluatedAt' | 'fired30'>;

export interface LogEntry {
  id: string;
  ruleId: string | null;
  assetId: string | null;
  channelIds: string[];
  result: 'sent' | 'throttled' | 'failed';
  detail: string;
  at: Date;
}
export type NewLogEntry = Omit<LogEntry, 'id' | 'at'>;

/** A finding that may need to be announced. */
export interface AlertEvent {
  assetId: string;
  host: string;
  cveId: string;
  risk: number;
  line: string;
}

export interface IAlertRepository {
  channels(): Promise<Channel[]>;
  findChannel(id: string): Promise<Channel | null>;
  createChannel(input: NewChannel): Promise<Channel>;
  updateChannel(id: string, patch: Partial<NewChannel> & { status?: ChannelStatus; problem?: string | null; lastTestAt?: Date }): Promise<Channel | null>;
  deleteChannel(id: string): Promise<boolean>;

  rules(): Promise<Rule[]>;
  findRule(id: string): Promise<Rule | null>;
  createRule(input: NewRule): Promise<Rule>;
  updateRule(id: string, patch: Partial<NewRule>): Promise<Rule | null>;
  deleteRule(id: string): Promise<boolean>;
  markEvaluated(id: string, at: Date, fired: boolean): Promise<void>;

  log(limit: number): Promise<LogEntry[]>;
  addLog(entry: NewLogEntry): Promise<LogEntry>;
  /** assets this rule already notified within the window, for the per-asset throttle */
  recentlyNotifiedAssets(ruleId: string, since: Date): Promise<Set<string>>;

  /** matches first seen after `since` that pass the rule's filters */
  newMatches(rule: Rule, since: Date, severity: 'kev' | 'critical' | 'epss'): Promise<AlertEvent[]>;
  /** open matches whose fix window ends within `hours` (or is already over) */
  slaMatches(rule: Rule, hours: number): Promise<AlertEvent[]>;
  /** sources whose last run failed after `since` */
  failedSyncs(since: Date): Promise<{ source: string; error: string }[]>;
  digestCounts(): Promise<{ open: number; kev: number; critical: number }>;
}
