import type { SyncSource } from './sync-state.repository.interface.js';

/**
 * Contract with cti-sync-worker: this API enqueues, the worker consumes.
 * Keep `SYNC_QUEUE_NAME` and the payload shape in sync with cti-sync-worker/src/domain/sync/sync-job.ts.
 */
export const SYNC_QUEUE_NAME = 'cti-sync';
export const SYNC_JOB_NAME = 'sync';

export interface SyncJobData {
  source: SyncSource;
  trigger: 'manual';
  requestId: string;
  requestedBy: { id: string; email: string };
  requestedAt: string;
}
