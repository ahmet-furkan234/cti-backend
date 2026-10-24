import { and, eq, inArray, sql } from 'drizzle-orm';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { IPushDeviceRepository, PushPlatform } from '../../../domain/alerts/push-device.repository.interface.js';
import { PERMISSIONS } from '../../../domain/rbac/permission-catalog.js';
import { tenant } from '../../../shared/tenant.js';
import type { Database } from '../client.js';
import { pushDevices } from '../schema/index.js';

const rowsOf = <T>(res: unknown): T[] => ((res as { rows?: T[] }).rows ?? []) as T[];

@injectable()
export class PushDeviceRepository implements IPushDeviceRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  async upsert(token: string, userId: string, platform: PushPlatform): Promise<void> {
    await this.db
      .insert(pushDevices)
      .values({ token, userId, platform, companyId: tenant.id() })
      .onConflictDoUpdate({ target: pushDevices.token, set: { userId, platform, companyId: tenant.id(), createdAt: new Date() } });
  }

  async remove(token: string, userId: string): Promise<void> {
    await this.db.delete(pushDevices).where(and(eq(pushDevices.token, token), eq(pushDevices.userId, userId)));
  }

  /** Same rule as computeEffectivePermissions(): a deny wins, a grant or a role gives the permission. */
  async tokensForCurrentCompany(): Promise<string[]> {
    const key = PERMISSIONS.ALERT_READ;
    const res = await this.db.execute(sql`
      select d.token from push_devices d
      join users u on u.id = d.user_id
      where d.company_id = ${tenant.id()} and u.status = 'active'
        and not exists (select 1 from user_permissions p where p.user_id = u.id and p.permission_key = ${key} and p.effect = 'deny')
        and (
          exists (select 1 from user_permissions p where p.user_id = u.id and p.permission_key = ${key} and p.effect = 'grant')
          or exists (select 1 from user_roles ur join role_permissions rp on rp.role_id = ur.role_id where ur.user_id = u.id and rp.permission_key = ${key})
        )`);
    return rowsOf<{ token: string }>(res).map((r) => r.token);
  }

  async purge(tokens: string[]): Promise<void> {
    if (tokens.length) await this.db.delete(pushDevices).where(inArray(pushDevices.token, tokens));
  }
}
