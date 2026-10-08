import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { IAuditRepository } from '../../domain/audit/audit.repository.interface.js';
import type { ILogger } from '../ports/ports.js';
import { tenant } from '../../shared/tenant.js';

export interface AuditActor {
  id: string | null;
  email: string | null;
  ip: string | null;
  /** defaults to the company in scope */
  companyId?: string | null;
}

@injectable()
export class AuditService {
  constructor(
    @inject(TYPES.IAuditRepository) private readonly repo: IAuditRepository,
    @inject(TYPES.ILogger) private readonly logger: ILogger,
  ) {}

  /** Never throws: auditing must not break the business operation. */
  async record(
    actor: AuditActor,
    action: string,
    target?: { type: string; id: string },
    meta: Record<string, unknown> = {},
  ): Promise<void> {
    try {
      await this.repo.create({
        companyId: actor.companyId ?? tenant.current()?.companyId ?? null,
        actorId: actor.id,
        actorEmail: actor.email,
        action,
        targetType: target?.type ?? null,
        targetId: target?.id ?? null,
        meta,
        ip: actor.ip,
      });
    } catch (err) {
      this.logger.error({ err, action }, 'audit write failed');
    }
  }
}
