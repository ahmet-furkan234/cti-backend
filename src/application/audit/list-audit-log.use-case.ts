import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { IAuditRepository, ListAuditQuery } from '../../domain/audit/audit.repository.interface.js';

@injectable()
export class ListAuditLogUseCase {
  constructor(@inject(TYPES.IAuditRepository) private readonly repo: IAuditRepository) {}

  async execute(query: ListAuditQuery) {
    const rows = await this.repo.list({ ...query, limit: query.limit + 1 });
    const hasMore = rows.length > query.limit;
    const items = hasMore ? rows.slice(0, query.limit) : rows;
    const last = items[items.length - 1];
    return {
      items,
      nextCursor: hasMore && last ? Buffer.from(`${last.at.toISOString()}|${last.id}`).toString('base64url') : null,
    };
  }
}
