import { Router, type Router as ExpressRouter } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { PERMISSIONS as P } from '../../../domain/rbac/permission-catalog.js';
import { CompanyController } from '../controllers/company.controller.js';
import { asyncWrapper as wrap } from '../middleware/async-wrapper.middleware.js';
import { AuthMiddleware } from '../middleware/auth.middleware.js';
import { actorOf } from '../request-actor.js';
import { validateRequest as check, valid } from '../middleware/validate.middleware.js';
import * as S from '../schemas/schemas.js';

/** Company management. The company:* permissions only ever exist inside the platform company, which is what gates this router. */
@injectable()
export class CompanyRouter {
  readonly router: ExpressRouter = Router();

  constructor(
    @inject(TYPES.CompanyController) private readonly c: CompanyController,
    @inject(TYPES.AuthMiddleware) private readonly auth: AuthMiddleware,
  ) {
    const r = this.router;
    const need = this.auth.requirePermission;
    r.use(this.auth.authenticate);

    r.get('/', need(P.COMPANY_READ, P.COMPANY_MANAGE), wrap(async (_req, res) => {
      res.json(await this.c.list());
    }));
    r.post('/', need(P.COMPANY_MANAGE), check({ body: S.createCompanyBody }), wrap(async (req, res) => {
      res.status(201).json(await this.c.create(actorOf(req), valid(req, { body: S.createCompanyBody }).body));
    }));
    r.patch('/:id', need(P.COMPANY_MANAGE), check({ params: S.idParams, body: S.updateCompanyBody }), wrap(async (req, res) => {
      const v = valid(req, { params: S.idParams, body: S.updateCompanyBody });
      res.json(await this.c.update(actorOf(req), v.params.id, v.body));
    }));
  }
}
