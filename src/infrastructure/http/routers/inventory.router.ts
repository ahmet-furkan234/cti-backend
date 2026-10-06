import { Router, type Router as ExpressRouter } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { PERMISSIONS as P } from '../../../domain/rbac/permission-catalog.js';
import { InventoryController } from '../controllers/inventory.controller.js';
import { actorOf } from '../request-actor.js';
import { asyncWrapper as wrap } from '../middleware/async-wrapper.middleware.js';
import { AuthMiddleware } from '../middleware/auth.middleware.js';
import { validateRequest as check, valid } from '../middleware/validate.middleware.js';
import * as S from '../schemas/schemas.js';

@injectable()
export class InventoryRouter {
  readonly router: ExpressRouter = Router();

  constructor(
    @inject(TYPES.InventoryController) private readonly c: InventoryController,
    @inject(TYPES.AuthMiddleware) private readonly auth: AuthMiddleware,
  ) {
    const r = this.router;
    const read = this.auth.requirePermission(P.ASSET_READ);
    const write = this.auth.requirePermission(P.ASSET_WRITE);
    r.use(this.auth.authenticate);
    r.get('/', read, check({ query: S.listAssetsQuery }), wrap(async (req, res) => {
      res.json(await this.c.list(valid(req, { query: S.listAssetsQuery }).query));
    }));
    r.post('/', write, check({ body: S.createAssetBody }), wrap(async (req, res) => {
      res.status(201).json(await this.c.create(actorOf(req), valid(req, { body: S.createAssetBody }).body));
    }));
    // Static paths go before '/:id'.
    r.get('/imports', read, wrap(async (_req, res) => {
      res.json(await this.c.imports());
    }));
    r.post('/software/check', write, check({ body: S.checkSoftwareBody }), wrap(async (req, res) => {
      res.json(await this.c.checkSoftware(valid(req, { body: S.checkSoftwareBody }).body.items));
    }));
    r.get('/software/products', read, check({ query: S.productSearchQuery }), wrap(async (req, res) => {
      res.json(await this.c.searchProducts(valid(req, { query: S.productSearchQuery }).query.q));
    }));
    r.get('/software/aliases', read, wrap(async (_req, res) => {
      res.json(await this.c.aliases());
    }));
    r.post('/software/aliases', write, check({ body: S.aliasBody }), wrap(async (req, res) => {
      res.status(201).json(await this.c.createAlias(actorOf(req), valid(req, { body: S.aliasBody }).body));
    }));
    r.delete('/software/aliases/:id', write, check({ params: S.idParams }), wrap(async (req, res) => {
      await this.c.deleteAlias(actorOf(req), valid(req, { params: S.idParams }).params.id);
      res.status(204).end();
    }));
    r.post('/import', write, check({ body: S.importAssetsBody }), wrap(async (req, res) => {
      res.json(await this.c.import(actorOf(req), valid(req, { body: S.importAssetsBody }).body));
    }));
    r.get('/:id', read, check({ params: S.idParams }), wrap(async (req, res) => {
      res.json(await this.c.get(valid(req, { params: S.idParams }).params.id));
    }));
    r.patch('/:id', write, check({ params: S.idParams, body: S.updateAssetBody }), wrap(async (req, res) => {
      const v = valid(req, { params: S.idParams, body: S.updateAssetBody });
      res.json(await this.c.update(actorOf(req), v.params.id, v.body));
    }));
    r.delete('/:id', this.auth.requirePermission(P.ASSET_DELETE), check({ params: S.idParams }), wrap(async (req, res) => {
      await this.c.delete(actorOf(req), valid(req, { params: S.idParams }).params.id);
      res.status(204).end();
    }));
  }
}
