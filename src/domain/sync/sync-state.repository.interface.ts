export type SyncSource = 'nvd' | 'kev' | 'epss';
export const SYNC_SOURCES: SyncSource[] = ['nvd', 'kev', 'epss'];

export type SyncStatus = 'idle' | 'running' | 'error';

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
}

/** The API only reads status and queues run requests; the cti-sync-worker service executes and updates them. */
export interface ISyncStateRepository {
  get(source: SyncSource): Promise<SyncState>;
  all(): Promise<SyncState[]>;
  requestRun(source: SyncSource): Promise<void>;
  /** Removes the "queued" marker again (the job could not be enqueued). */
  clearRequest(source: SyncSource): Promise<void>;
}
