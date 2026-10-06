import { Queue } from 'bullmq';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { ILogger, ISyncJobQueue } from '../../application/ports/ports.js';
import { SYNC_JOB_NAME, SYNC_QUEUE_NAME, type SyncJobData } from '../../domain/sync/sync-job.js';
import type { EnvConfig } from '../common/env.config.js';

/** `redis://[user:pass@]host:port[/db]` (or `rediss://` for TLS) → BullMQ connection options. */
export function redisConnection(url: string) {
  const u = new URL(url);
  return {
    host: u.hostname,
    port: Number(u.port || 6379),
    ...(u.username ? { username: decodeURIComponent(u.username) } : {}),
    ...(u.password ? { password: decodeURIComponent(u.password) } : {}),
    ...(u.pathname.length > 1 ? { db: Number(u.pathname.slice(1)) } : {}),
    ...(u.protocol === 'rediss:' ? { tls: {} } : {}),
    // Producer side: fail fast while Redis is down (→ API answers 503) instead of buffering commands.
    enableOfflineQueue: false,
    maxRetriesPerRequest: 1,
  };
}

@injectable()
export class BullMqSyncJobQueue implements ISyncJobQueue {
  private readonly queue: Queue<SyncJobData>;

  constructor(
    @inject(TYPES.EnvConfig) config: EnvConfig,
    @inject(TYPES.ILogger) logger: ILogger,
  ) {
    this.queue = new Queue<SyncJobData>(SYNC_QUEUE_NAME, { connection: redisConnection(config.REDIS_URL) });
    this.queue.on('error', (err) => logger.error({ err: String(err) }, 'sync queue connection error'));
  }

  async enqueue(job: SyncJobData): Promise<void> {
    await this.queue.add(SYNC_JOB_NAME, job, {
      // One pending/active manual job per source: clicking twice does not stack runs.
      // Finished jobs are removed so the same id can be used again.
      jobId: `manual-${job.source}`,
      removeOnComplete: true,
      removeOnFail: true,
    });
  }

  async ping(): Promise<boolean> {
    try {
      await this.queue.isPaused(); // any command is a round-trip to Redis
      return true;
    } catch {
      return false;
    }
  }

  close(): Promise<void> {
    return this.queue.close();
  }
}
