export type SyncSource = 'nvd' | 'kev' | 'epss';
export const SYNC_SOURCES: SyncSource[] = ['nvd', 'kev', 'epss'];

export type SyncStatus = 'idle' | 'running' | 'error';

/** Live progress of a running sync; `total` is null when it cannot be known (indeterminate). */
export interface SyncProgress {
  phase: 'full' | 'incremental' | 'download' | 'apply';
  done: number;
  total: number | null;
  /** `done` at the start of this phase (a resumed full load starts above 0): the ETA rate is measured from it. */
  baseDone: number;
  startedAt: string;
  updatedAt: string;
}

export interface SyncState {
  source: SyncSource;
  status: SyncStatus;
  lastSuccessAt: Date | null;
  lastStartedAt: Date | null;
  lastFinishedAt: Date | null;
  lastError: string | null;
  recordsProcessed: number;
  cursor: Record<string, unknown>;
  runRequestedAt: Date | null;
  progress: SyncProgress | null;
}

/** The API only reads status and queues run requests; the cti-sync-worker service executes and updates them. */
export interface ISyncStateRepository {
  get(source: SyncSource): Promise<SyncState>;
  all(): Promise<SyncState[]>;
  requestRun(source: SyncSource): Promise<void>;
  /** Removes the "queued" marker again (the job could not be enqueued). */
  clearRequest(source: SyncSource): Promise<void>;
}
