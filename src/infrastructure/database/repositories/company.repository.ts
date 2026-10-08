import { eq, sql } from 'drizzle-orm';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { Company, CompanyListItem, CompanyStatus, ICompanyRepository } from '../../../domain/company/company.repository.interface.js';
import type { Database } from '../client.js';
import { companies } from '../schema/index.js';

const toCompany = (r: typeof companies.$inferSelect): Company => ({
  id: r.id, name: r.name, isPlatform: r.isPlatform, status: r.status, createdAt: r.createdAt,
});

@injectable()
export class CompanyRepository implements ICompanyRepository {
  constructor(@inject(TYPES.DrizzleDatabase) private readonly db: Database) {}

  async findById(id: string) {
    const [r] = await this.db.select().from(companies).where(eq(companies.id, id)).limit(1);
    return r ? toCompany(r) : null;
  }

  async findByName(name: string) {
    const [r] = await this.db.select().from(companies).where(sql`lower(${companies.name}) = ${name.toLowerCase()}`).limit(1);
    return r ? toCompany(r) : null;
  }

  async findPlatform() {
    const [r] = await this.db.select().from(companies).where(eq(companies.isPlatform, true)).limit(1);
    return r ? toCompany(r) : null;
  }

  async list(): Promise<CompanyListItem[]> {
    const res = await this.db.execute(sql`select c.*,
      (select count(*)::int from users u where u.company_id = c.id) as users,
      (select count(*)::int from assets a where a.company_id = c.id and a.archived_at is null) as assets
      from companies c order by c.is_platform desc, lower(c.name)`);
    return ((res as unknown as { rows: Record<string, unknown>[] }).rows).map((r) => ({
      id: r['id'] as string, name: r['name'] as string, isPlatform: r['is_platform'] as boolean, status: r['status'] as CompanyStatus,
      createdAt: new Date(r['created_at'] as string), users: Number(r['users']), assets: Number(r['assets']),
    }));
  }

  async active() {
    return (await this.db.select().from(companies).where(eq(companies.status, 'active'))).map(toCompany);
  }

  async create(input: { name: string }) {
    const [r] = await this.db.insert(companies).values({ name: input.name }).returning();
    return toCompany(r!);
  }

  async update(id: string, patch: { name?: string; status?: CompanyStatus }) {
    const [r] = await this.db.update(companies).set({ ...patch, updatedAt: new Date() }).where(eq(companies.id, id)).returning();
    return r ? toCompany(r) : null;
  }
}
