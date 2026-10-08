import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { Actor } from '../../../application/shared/actor.js';
import type { CompanyStatus } from '../../../domain/company/company.repository.interface.js';
import { CompanyUseCases } from '../../../application/company/company.use-cases.js';

@injectable()
export class CompanyController {
  constructor(@inject(TYPES.CompanyUseCases) private readonly uc: CompanyUseCases) {}

  list() { return this.uc.list(); }
  create(a: Actor, body: { name: string; adminEmail?: string | undefined }) { return this.uc.create(a, body); }
  update(a: Actor, id: string, body: { name?: string | undefined; status?: CompanyStatus | undefined }) { return this.uc.update(a, id, body); }
}
