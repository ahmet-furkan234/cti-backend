import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { Actor } from '../../../application/shared/actor.js';
import type { SyncSource } from '../../../domain/sync/sync-state.repository.interface.js';
import { GetSyncStatusUseCase, RequestSyncUseCase } from '../../../application/sync/use-cases/sync-status.use-cases.js';

@injectable()
export class SyncController {
  constructor(
    @inject(TYPES.GetSyncStatusUseCase)
    private readonly status_: GetSyncStatusUseCase,
    @inject(TYPES.RequestSyncUseCase)
    private readonly request_: RequestSyncUseCase,
  ) {}

  status() {
    return this.status_.execute();
  }
  run(a: Actor, source: SyncSource) {
    return this.request_.execute(a, source);
  }
}
