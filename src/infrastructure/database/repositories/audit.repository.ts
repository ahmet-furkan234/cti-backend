import { and, desc, eq, gte, lte, sql } from 'drizzle-orm';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { AuditEntry, IAuditRepository, ListAuditQuery } from '../../../domain/audit/audit.repository.interface.js';
import { tenant } from '../../../shared/tenant.js';
import type { Database } from '../client.js';
import { auditLog } from '../schema/index.js';

@injectable()
export class AuditRepository implements IAuditRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  async create(e: Omit<AuditEntry, 'id' | 'at'>) {
    await this.db.insert(auditLog).values(e);
  }

  async list(q: ListAuditQuery): Promise<AuditEntry[]> {
    const conds = [eq(auditLog.companyId, tenant.id())];
    if (q.actorId) conds.push(eq(auditLog.actorId, q.actorId));
    if (q.action) conds.push(eq(auditLog.action, q.action));
    if (q.targetId) conds.push(eq(auditLog.targetId, q.targetId));
    if (q.from) conds.push(gte(auditLog.at, q.from));
    if (q.to) conds.push(lte(auditLog.at, q.to));
    if (q.before) conds.push(sql`(${auditLog.at}, ${auditLog.id}) < (${q.before.at.toISOString()}::timestamptz, ${q.before.id}::uuid)`);

    return this.db
      .select()
      .from(auditLog)
      .where(conds.length ? and(...conds) : undefined)
      .orderBy(desc(auditLog.at), desc(auditLog.id))
      .limit(q.limit);
  }
}
