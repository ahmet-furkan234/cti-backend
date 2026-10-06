import { randomUUID } from 'crypto';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { ISyncStateRepository, SyncSource } from '../../../domain/sync/sync-state.repository.interface.js';
import { ConflictException, ServiceUnavailableException } from '../../../domain/common/exceptions.js';
import { AuditAction, Errors } from '../../../shared/strings.js';
import type { ILogger, ISyncJobQueue } from '../../ports/ports.js';
import { AuditService } from '../../audit/audit.service.js';
import { auditActor, type Actor } from '../../shared/actor.js';

@injectable()
export class GetSyncStatusUseCase {
  constructor(@inject(TYPES.ISyncStateRepository) private readonly state: ISyncStateRepository) {}
  execute() {
    return this.state.all();
  }
}

@injectable()
export class RequestSyncUseCase {
  constructor(
    @inject(TYPES.ISyncStateRepository) private readonly state: ISyncStateRepository,
    @inject(TYPES.ISyncJobQueue) private readonly queue: ISyncJobQueue,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
    @inject(TYPES.ILogger) private readonly logger: ILogger,
  ) {}

  async execute(actor: Actor, source: SyncSource): Promise<{ requestId: string }> {
    const current = await this.state.get(source);
    if (current.status === 'running') throw new ConflictException(Errors.syncRunning);

    const requestId = randomUUID();
    // "Queued" marker for the UI. It must be set BEFORE enqueueing: the worker clears it the moment the job starts,
    // so setting it afterwards can leave a fast job stuck as "queued" forever.
    await this.state.requestRun(source);
    try {
      await this.queue.enqueue({
        source,
        trigger: 'manual',
        requestId,
        requestedBy: { id: actor.id, email: actor.email },
        requestedAt: new Date().toISOString(),
      });
    } catch (err) {
      await this.state.clearRequest(source);
      this.logger.error({ err: String(err), source }, 'could not enqueue sync job');
      throw new ServiceUnavailableException(Errors.syncQueueUnavailable);
    }
    await this.audit.record(auditActor(actor), AuditAction.syncRequested, { type: 'sync', id: source }, { requestId });
    return { requestId };
  }
}
