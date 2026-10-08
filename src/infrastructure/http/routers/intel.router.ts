import { Router, type Router as ExpressRouter } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { PERMISSIONS as P } from '../../../domain/rbac/permission-catalog.js';
import { IntelController } from '../controllers/intel.controller.js';
import { actorOf } from '../request-actor.js';
import { asyncWrapper as wrap } from '../middleware/async-wrapper.middleware.js';
import { AuthMiddleware } from '../middleware/auth.middleware.js';
import { validateRequest as check, valid } from '../middleware/validate.middleware.js';
import * as S from '../schemas/schemas.js';

@injectable()
export class IntelRouter {
  readonly router: ExpressRouter = Router();

  constructor(
    @inject(TYPES.IntelController) private readonly c: IntelController,
    @inject(TYPES.AuthMiddleware) private readonly auth: AuthMiddleware,
  ) {
    const r = this.router;
    const read = this.auth.requirePermission(P.INTEL_READ);
    const manage = this.auth.requirePermission(P.INTEL_MANAGE);
    r.use(this.auth.authenticate);

    r.get('/watchlists', read, wrap(async (_req, res) => {
      res.json(await this.c.watchlists());
    }));
    r.post('/watchlists', manage, check({ body: S.watchlistBody }), wrap(async (req, res) => {
      res.status(201).json(await this.c.createWatchlist(actorOf(req), valid(req, { body: S.watchlistBody }).body));
    }));
    r.patch('/watchlists/:id', manage, check({ params: S.idParams, body: S.updateWatchlistBody }), wrap(async (req, res) => {
      const v = valid(req, { params: S.idParams, body: S.updateWatchlistBody });
      res.json(await this.c.updateWatchlist(actorOf(req), v.params.id, v.body as never));
    }));
    r.delete('/watchlists/:id', manage, check({ params: S.idParams }), wrap(async (req, res) => {
      await this.c.deleteWatchlist(actorOf(req), valid(req, { params: S.idParams }).params.id);
      res.status(204).end();
    }));

    r.get('/findings', read, check({ query: S.intelFindingsQuery }), wrap(async (req, res) => {
      res.json(await this.c.findings(valid(req, { query: S.intelFindingsQuery }).query));
    }));
    r.get('/new-kev', read, check({ query: S.intelDaysQuery }), wrap(async (req, res) => {
      res.json(await this.c.newKev(valid(req, { query: S.intelDaysQuery }).query.days));
    }));
    r.get('/iocs/:id/assets', read, check({ params: S.idParams }), wrap(async (req, res) => {
      res.json(await this.c.iocAssets(valid(req, { params: S.idParams }).params.id));
    }));
    r.get('/iocs', read, check({ query: S.listIocsQuery }), wrap(async (req, res) => {
      res.json(await this.c.iocs(valid(req, { query: S.listIocsQuery }).query));
    }));
    r.post('/iocs', manage, check({ body: S.addIocsBody }), wrap(async (req, res) => {
      res.status(201).json(await this.c.addIocs(actorOf(req), valid(req, { body: S.addIocsBody }).body.items));
    }));
    r.delete('/iocs/:id', manage, check({ params: S.idParams }), wrap(async (req, res) => {
      await this.c.deleteIoc(actorOf(req), valid(req, { params: S.idParams }).params.id);
      res.status(204).end();
    }));
  }
}
