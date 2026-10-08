import { inject, injectable } from 'inversify';
import { TYPES } from '../../shared/tokens.js';
import type { Company, CompanyStatus, ICompanyRepository } from '../../domain/company/company.repository.interface.js';
import type { IRoleRepository } from '../../domain/rbac/role.repository.interface.js';
import { COMPANY_ADMIN_ROLE } from '../../domain/rbac/permission-catalog.js';
import { AlreadyExistsException, InvalidStateException, InvalidValueException, NotFoundException } from '../../domain/common/exceptions.js';
import { EffectivePermissionService } from '../rbac/services/effective-permission.service.js';
import { InviteUserUseCase } from '../user/use-cases/user.use-cases.js';
import { AuditService } from '../audit/audit.service.js';
import { auditActor, type Actor } from '../shared/actor.js';
import { tenant } from '../../shared/tenant.js';
import { AuditAction, Entity, Errors } from '../../shared/strings.js';

const brief = (c: Company) => ({ id: c.id, name: c.name, isPlatform: c.isPlatform, status: c.status, createdAt: c.createdAt });

/** The platform company's view of the companies it hosts. */
@injectable()
export class CompanyUseCases {
  constructor(
    @inject(TYPES.ICompanyRepository) private readonly companies: ICompanyRepository,
    @inject(TYPES.IRoleRepository) private readonly roles: IRoleRepository,
    @inject(TYPES.InviteUserUseCase) private readonly invite: InviteUserUseCase,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
    @inject(TYPES.AuditService) private readonly audit: AuditService,
  ) {}

  async list() {
    return { items: await this.companies.list() };
  }

  /** Creates the company and, when an e-mail is given, an invitation for its first administrator. */
  async create(actor: Actor, input: { name: string; adminEmail?: string | undefined }) {
    const name = input.name.trim();
    if (await this.companies.findByName(name)) throw new AlreadyExistsException(Entity.company, 'name');
    const company = await this.companies.create({ name });
    await this.audit.record(auditActor(actor), AuditAction.companyCreated, { type: 'company', id: company.id }, { name });

    let invite: Awaited<ReturnType<InviteUserUseCase['execute']>> | null = null;
    if (input.adminEmail) {
      invite = await tenant.run({ companyId: company.id, platform: false }, async () => {
        const role = await this.roles.findByName(COMPANY_ADMIN_ROLE);
        if (!role) throw new InvalidValueException(Errors.rolesMissing);
        return this.invite.execute({ ...actor, companyId: company.id }, { email: input.adminEmail!, roleIds: [role.id] });
      });
    }
    return { company: brief(company), invite };
  }

  async update(actor: Actor, id: string, patch: { name?: string | undefined; status?: CompanyStatus | undefined }) {
    const company = await this.companies.findById(id);
    if (!company) throw new NotFoundException(Entity.company);
    if (patch.status === 'suspended' && company.isPlatform) throw new InvalidStateException(Errors.cannotSuspendPlatform);

    const changes: { name?: string; status?: CompanyStatus } = {};
    if (patch.name !== undefined && patch.name.trim() !== company.name) {
      const name = patch.name.trim();
      const clash = await this.companies.findByName(name);
      if (clash && clash.id !== id) throw new AlreadyExistsException(Entity.company, 'name');
      changes.name = name;
    }
    if (patch.status && patch.status !== company.status) changes.status = patch.status;
    if (Object.keys(changes).length === 0) return brief(company);

    const updated = (await this.companies.update(id, changes))!;
    // A suspension has to bite right away, not when each user's cached access expires.
    this.perms.invalidateAll();
    await this.audit.record(auditActor(actor), AuditAction.companyUpdated, { type: 'company', id }, changes);
    return brief(updated);
  }
}
