import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { ListAuditLogUseCase } from '../../../application/audit/list-audit-log.use-case.js';
import { InvalidValueException } from '../../../domain/common/exceptions.js';
import { Errors } from '../../../shared/strings.js';

@injectable()
export class AuditController {
  constructor(
    @inject(TYPES.ListAuditLogUseCase)
    private readonly list_: ListAuditLogUseCase,
  ) {}

  list(q: {
    actorId?: string | undefined;
    action?: string | undefined;
    targetId?: string | undefined;
    from?: Date | undefined;
    to?: Date | undefined;
    limit: number;
    cursor?: string | undefined;
  }) {
    let before: { at: Date; id: string } | undefined;
    if (q.cursor) {
      const [at, id] = Buffer.from(q.cursor, "base64url")
        .toString("utf8")
        .split("|");
      if (!at || !id || Number.isNaN(Date.parse(at)))
        throw new InvalidValueException(Errors.invalidCursor);
      before = { at: new Date(at), id };
    }
    const { cursor: _c, ...rest } = q;
    return this.list_.execute({ ...rest, before });
  }
}
