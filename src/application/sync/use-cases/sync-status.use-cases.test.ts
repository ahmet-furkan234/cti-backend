import 'reflect-metadata';
import { describe, expect, it, vi } from 'vitest';
import { ConflictException, ServiceUnavailableException } from '../../../domain/common/exceptions.js';
import type { SyncState } from '../../../domain/sync/sync-state.repository.interface.js';
import { RequestSyncUseCase } from './sync-status.use-cases.js';

const state = (status: SyncState['status']): SyncState => ({
  source: 'kev', status, lastSuccessAt: null, lastStartedAt: null, lastFinishedAt: null,
  lastError: null, recordsProcessed: 0, cursor: {}, runRequestedAt: null,
});
const actor = { id: 'u1', email: 'a@b.c', permissions: [], ip: null };

function setup(opts: { status?: SyncState['status']; enqueueFails?: boolean } = {}) {
  const repo = { get: vi.fn(async () => state(opts.status ?? 'idle')), all: vi.fn(), requestRun: vi.fn(async () => undefined), clearRequest: vi.fn(async () => undefined) };
  const queue = {
    enqueue: vi.fn(async () => { if (opts.enqueueFails) throw new Error('ECONNREFUSED'); }),
    ping: vi.fn(), close: vi.fn(),
  };
  const audit = { record: vi.fn(async () => undefined) };
  const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() };
  const uc = new RequestSyncUseCase(repo as never, queue as never, audit as never, logger);
  return { uc, repo, queue, audit };
}

describe('RequestSyncUseCase', () => {
  it('enqueues a manual job with requester info, marks the source queued and audits it', async () => {
    const { uc, queue, repo, audit } = setup();
    const { requestId } = await uc.execute(actor, 'kev');
    expect(queue.enqueue).toHaveBeenCalledWith(expect.objectContaining({ source: 'kev', trigger: 'manual', requestId, requestedBy: { id: 'u1', email: 'a@b.c' } }));
    expect(repo.requestRun).toHaveBeenCalledWith('kev');
    expect(audit.record).toHaveBeenCalledWith(expect.anything(), 'sync.requested', { type: 'sync', id: 'kev' }, { requestId });
  });

  it('marks the source queued before the job can start, so a fast worker cannot be overwritten', async () => {
    const { uc, queue, repo } = setup();
    await uc.execute(actor, 'kev');
    expect(repo.requestRun.mock.invocationCallOrder[0]).toBeLessThan(queue.enqueue.mock.invocationCallOrder[0]!);
  });

  it('refuses while the source is already running', async () => {
    const { uc, queue } = setup({ status: 'running' });
    await expect(uc.execute(actor, 'kev')).rejects.toBeInstanceOf(ConflictException);
    expect(queue.enqueue).not.toHaveBeenCalled();
  });

  it('answers 503-style when the queue is down and takes the queued marker back', async () => {
    const { uc, repo, audit } = setup({ enqueueFails: true });
    await expect(uc.execute(actor, 'kev')).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(repo.clearRequest).toHaveBeenCalledWith('kev');
    expect(audit.record).not.toHaveBeenCalled();
  });
});
