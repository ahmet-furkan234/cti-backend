import { Router, type Router as ExpressRouter } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { PERMISSIONS as P } from '../../../domain/rbac/permission-catalog.js';
import { RoleController } from '../controllers/role.controller.js';
import { asyncWrapper as wrap } from '../middleware/async-wrapper.middleware.js';
import { AuthMiddleware } from '../middleware/auth.middleware.js';
import { actorOf } from '../request-actor.js';
import { validateRequest as check, valid } from '../middleware/validate.middleware.js';
import * as S from '../schemas/schemas.js';

@injectable()
export class RoleRouter {
  readonly router: ExpressRouter = Router();

  constructor(
    @inject(TYPES.RoleController) private readonly c: RoleController,
    @inject(TYPES.AuthMiddleware) private readonly auth: AuthMiddleware,
  ) {
    const r = this.router;
    const need = this.auth.requirePermission;
    // Mounted at '/', so authenticate per route (a router-level use() would swallow unknown paths with 401).
    const authed = this.auth.authenticate;

    r.get('/permissions', authed, need(P.ROLE_READ, P.PERMISSION_ASSIGN), wrap(async (_req, res) => {
      res.json(await this.c.permissions());
    }));
    r.get('/roles', authed, need(P.ROLE_READ, P.USER_READ), wrap(async (_req, res) => {
      res.json(await this.c.list());
    }));
    r.post('/roles', authed, need(P.ROLE_MANAGE), check({ body: S.createRoleBody }), wrap(async (req, res) => {
      res.status(201).json(await this.c.create(actorOf(req), valid(req, { body: S.createRoleBody }).body));
    }));
    r.get('/roles/:id', authed, need(P.ROLE_READ), check({ params: S.idParams }), wrap(async (req, res) => {
      res.json(await this.c.get(valid(req, { params: S.idParams }).params.id));
    }));
    r.patch('/roles/:id', authed, need(P.ROLE_MANAGE), check({ params: S.idParams, body: S.updateRoleBody }), wrap(async (req, res) => {
      const v = valid(req, { params: S.idParams, body: S.updateRoleBody });
      res.json(await this.c.update(actorOf(req), v.params.id, v.body));
    }));
    r.delete('/roles/:id', authed, need(P.ROLE_MANAGE), check({ params: S.idParams }), wrap(async (req, res) => {
      await this.c.delete(actorOf(req), valid(req, { params: S.idParams }).params.id);
      res.status(204).end();
    }));
  }
}
