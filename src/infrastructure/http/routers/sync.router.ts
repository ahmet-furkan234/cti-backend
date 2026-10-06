import { Router, type Router as ExpressRouter } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { PERMISSIONS as P } from '../../../domain/rbac/permission-catalog.js';
import { SyncController } from '../controllers/sync.controller.js';
import { asyncWrapper as wrap } from '../middleware/async-wrapper.middleware.js';
import { AuthMiddleware } from '../middleware/auth.middleware.js';
import { actorOf } from '../request-actor.js';
import { validateRequest as check, valid } from '../middleware/validate.middleware.js';
import * as S from '../schemas/schemas.js';

@injectable()
export class SyncRouter {
  readonly router: ExpressRouter = Router();

  constructor(
    @inject(TYPES.SyncController) private readonly c: SyncController,
    @inject(TYPES.AuthMiddleware) private readonly auth: AuthMiddleware,
  ) {
    const r = this.router;
    r.use(this.auth.authenticate);
    r.get('/', this.auth.requirePermission(P.SYNC_VIEW), wrap(async (_req, res) => {
      res.json(await this.c.status());
    }));
    r.post('/:source/run', this.auth.requirePermission(P.SYNC_RUN), check({ params: S.syncSourceParams }), wrap(async (req, res) => {
      const { requestId } = await this.c.run(actorOf(req), valid(req, { params: S.syncSourceParams }).params.source);
      res.status(202).json({ accepted: true, requestId });
    }));
  }
}
