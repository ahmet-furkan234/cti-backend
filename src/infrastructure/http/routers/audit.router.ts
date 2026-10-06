import { Router, type Router as ExpressRouter } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { PERMISSIONS as P } from '../../../domain/rbac/permission-catalog.js';
import { AuditController } from '../controllers/audit.controller.js';
import { asyncWrapper as wrap } from '../middleware/async-wrapper.middleware.js';
import { AuthMiddleware } from '../middleware/auth.middleware.js';
import { validateRequest as check, valid } from '../middleware/validate.middleware.js';
import * as S from '../schemas/schemas.js';

@injectable()
export class AuditRouter {
  readonly router: ExpressRouter = Router();

  constructor(
    @inject(TYPES.AuditController) private readonly c: AuditController,
    @inject(TYPES.AuthMiddleware) private readonly auth: AuthMiddleware,
  ) {
    this.router.get('/', this.auth.authenticate, this.auth.requirePermission(P.AUDIT_READ), check({ query: S.auditQuery }), wrap(async (req, res) => {
      res.json(await this.c.list(valid(req, { query: S.auditQuery }).query));
    }));
  }
}
