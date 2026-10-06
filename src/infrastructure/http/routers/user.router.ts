import { Router, type Router as ExpressRouter } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { PERMISSIONS as P } from '../../../domain/rbac/permission-catalog.js';
import { UserController } from '../controllers/user.controller.js';
import { asyncWrapper as wrap } from '../middleware/async-wrapper.middleware.js';
import { AuthMiddleware } from '../middleware/auth.middleware.js';
import { actorOf } from '../request-actor.js';
import { validateRequest as check, valid } from '../middleware/validate.middleware.js';
import * as S from '../schemas/schemas.js';

@injectable()
export class UserRouter {
  readonly router: ExpressRouter = Router();

  constructor(
    @inject(TYPES.UserController) private readonly c: UserController,
    @inject(TYPES.AuthMiddleware) private readonly auth: AuthMiddleware,
  ) {
    const r = this.router;
    const need = this.auth.requirePermission;
    r.use(this.auth.authenticate);

    r.get('/', need(P.USER_READ), check({ query: S.listUsersQuery }), wrap(async (req, res) => {
      res.json(await this.c.list(valid(req, { query: S.listUsersQuery }).query));
    }));
    r.post('/invite', need(P.USER_CREATE), check({ body: S.inviteBody }), wrap(async (req, res) => {
      res.status(201).json(await this.c.invite(actorOf(req), valid(req, { body: S.inviteBody }).body));
    }));
    r.get('/:id', need(P.USER_READ), check({ params: S.idParams }), wrap(async (req, res) => {
      res.json(await this.c.get(valid(req, { params: S.idParams }).params.id));
    }));
    r.patch('/:id', need(P.USER_UPDATE), check({ params: S.idParams, body: S.updateUserBody }), wrap(async (req, res) => {
      const v = valid(req, { params: S.idParams, body: S.updateUserBody });
      res.json(await this.c.update(actorOf(req), v.params.id, v.body));
    }));
    r.delete('/:id', need(P.USER_DELETE), check({ params: S.idParams }), wrap(async (req, res) => {
      await this.c.delete(actorOf(req), valid(req, { params: S.idParams }).params.id);
      res.status(204).end();
    }));
    r.put('/:id/permissions', need(P.PERMISSION_ASSIGN), check({ params: S.idParams, body: S.overridesBody }), wrap(async (req, res) => {
      const v = valid(req, { params: S.idParams, body: S.overridesBody });
      res.json(await this.c.setOverrides(actorOf(req), v.params.id, v.body.overrides));
    }));
    r.get('/:id/effective-permissions', need(P.USER_READ), check({ params: S.idParams }), wrap(async (req, res) => {
      res.json(await this.c.effective(valid(req, { params: S.idParams }).params.id));
    }));
    r.post('/:id/reset-password', need(P.USER_RESET_PASSWORD), check({ params: S.idParams }), wrap(async (req, res) => {
      res.status(201).json(await this.c.issueReset(actorOf(req), valid(req, { params: S.idParams }).params.id));
    }));
    r.post('/:id/revoke-sessions', need(P.USER_UPDATE), check({ params: S.idParams }), wrap(async (req, res) => {
      await this.c.revokeSessions(actorOf(req), valid(req, { params: S.idParams }).params.id);
      res.status(204).end();
    }));
  }
}
