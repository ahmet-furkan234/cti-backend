import { Router, type Router as ExpressRouter } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { PERMISSIONS as P } from '../../../domain/rbac/permission-catalog.js';
import { CveController } from '../controllers/cve.controller.js';
import { VulnController } from '../controllers/vuln.controller.js';
import { asyncWrapper as wrap } from '../middleware/async-wrapper.middleware.js';
import { AuthMiddleware } from '../middleware/auth.middleware.js';
import { validateRequest as check, valid } from '../middleware/validate.middleware.js';
import * as S from '../schemas/schemas.js';

@injectable()
export class CveRouter {
  readonly router: ExpressRouter = Router();

  constructor(
    @inject(TYPES.CveController) private readonly c: CveController,
    @inject(TYPES.VulnController) private readonly vulns: VulnController,
    @inject(TYPES.AuthMiddleware) private readonly auth: AuthMiddleware,
  ) {
    const r = this.router;
    r.use(this.auth.authenticate);
    r.get('/', this.auth.requirePermission(P.CVE_READ), check({ query: S.searchCvesQuery }), wrap(async (req, res) => {
      res.json(await this.c.search(valid(req, { query: S.searchCvesQuery }).query));
    }));
    // Registered before '/:id' so "stats" is not parsed as a CVE id.
    r.get('/stats', this.auth.requirePermission(P.DASHBOARD_VIEW), wrap(async (_req, res) => {
      res.json(await this.c.stats());
    }));
    r.get('/:id', this.auth.requirePermission(P.CVE_READ), check({ params: S.cveIdParams }), wrap(async (req, res) => {
      res.json(await this.c.get(valid(req, { params: S.cveIdParams }).params.id));
    }));
    r.get('/:id/assets', this.auth.requirePermission(P.VULN_READ), check({ params: S.cveIdParams }), wrap(async (req, res) => {
      res.json(await this.vulns.forCve(valid(req, { params: S.cveIdParams }).params.id));
    }));
  }
}
