import { Router, type Router as ExpressRouter } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { PERMISSIONS as P } from '../../../domain/rbac/permission-catalog.js';
import { VulnController } from '../controllers/vuln.controller.js';
import { actorOf } from '../request-actor.js';
import { asyncWrapper as wrap } from '../middleware/async-wrapper.middleware.js';
import { AuthMiddleware } from '../middleware/auth.middleware.js';
import { validateRequest as check, valid } from '../middleware/validate.middleware.js';
import * as S from '../schemas/schemas.js';

@injectable()
export class VulnRouter {
  readonly router: ExpressRouter = Router();

  constructor(
    @inject(TYPES.VulnController) private readonly c: VulnController,
    @inject(TYPES.AuthMiddleware) private readonly auth: AuthMiddleware,
  ) {
    const r = this.router;
    r.use(this.auth.authenticate);
    r.get('/', this.auth.requirePermission(P.VULN_READ), check({ query: S.listVulnsQuery }), wrap(async (req, res) => {
      res.json(await this.c.list(valid(req, { query: S.listVulnsQuery }).query));
    }));
    r.post('/status', this.auth.requirePermission(P.VULN_UPDATE), check({ body: S.setVulnStatusBody }), wrap(async (req, res) => {
      const { ids, status } = valid(req, { body: S.setVulnStatusBody }).body;
      res.json(await this.c.setStatus(actorOf(req), ids, status));
    }));
    r.post('/rematch', this.auth.requirePermission(P.VULN_UPDATE), wrap(async (req, res) => {
      res.json(await this.c.rematch(actorOf(req)));
    }));
  }
}
