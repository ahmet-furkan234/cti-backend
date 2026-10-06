export interface AuditEntry {
  id: string;
  actorId: string | null;
  actorEmail: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  meta: Record<string, unknown>;
  ip: string | null;
  at: Date;
}

export interface ListAuditQuery {
  actorId?: string | undefined;
  action?: string | undefined;
  targetId?: string | undefined;
  from?: Date | undefined;
  to?: Date | undefined;
  limit: number;
  /** ISO timestamp of the last item of the previous page (keyset). */
  before?: { at: Date; id: string } | undefined;
}

export interface IAuditRepository {
  create(entry: Omit<AuditEntry, 'id' | 'at'>): Promise<void>;
  list(query: ListAuditQuery): Promise<AuditEntry[]>;
}
