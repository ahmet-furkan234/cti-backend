import { Router, type Router as ExpressRouter } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { PERMISSIONS as P } from '../../../domain/rbac/permission-catalog.js';
import { AlertController } from '../controllers/alert.controller.js';
import { actorOf } from '../request-actor.js';
import { asyncWrapper as wrap } from '../middleware/async-wrapper.middleware.js';
import { AuthMiddleware } from '../middleware/auth.middleware.js';
import { validateRequest as check, valid } from '../middleware/validate.middleware.js';
import * as S from '../schemas/schemas.js';

@injectable()
export class AlertRouter {
  readonly router: ExpressRouter = Router();

  constructor(
    @inject(TYPES.AlertController) private readonly c: AlertController,
    @inject(TYPES.AuthMiddleware) private readonly auth: AuthMiddleware,
  ) {
    const r = this.router;
    const read = this.auth.requirePermission(P.ALERT_READ);
    const manage = this.auth.requirePermission(P.ALERT_MANAGE);
    r.use(this.auth.authenticate);

    r.get('/channels', read, wrap(async (req, res) => {
      res.json(await this.c.channels(req.auth!.permissions.includes(P.ALERT_MANAGE)));
    }));
    r.post('/channels', manage, check({ body: S.channelBody }), wrap(async (req, res) => {
      res.status(201).json(await this.c.createChannel(actorOf(req), valid(req, { body: S.channelBody }).body));
    }));
    r.patch('/channels/:id', manage, check({ params: S.idParams, body: S.updateChannelBody }), wrap(async (req, res) => {
      const v = valid(req, { params: S.idParams, body: S.updateChannelBody });
      res.json(await this.c.updateChannel(actorOf(req), v.params.id, v.body));
    }));
    r.delete('/channels/:id', manage, check({ params: S.idParams }), wrap(async (req, res) => {
      await this.c.deleteChannel(actorOf(req), valid(req, { params: S.idParams }).params.id);
      res.status(204).end();
    }));
    r.post('/channels/:id/test', manage, check({ params: S.idParams }), wrap(async (req, res) => {
      res.json(await this.c.testChannel(valid(req, { params: S.idParams }).params.id));
    }));

    r.get('/rules', read, wrap(async (_req, res) => {
      res.json(await this.c.rules());
    }));
    r.post('/rules', manage, check({ body: S.ruleBody }), wrap(async (req, res) => {
      res.status(201).json(await this.c.createRule(actorOf(req), valid(req, { body: S.ruleBody }).body));
    }));
    r.patch('/rules/:id', manage, check({ params: S.idParams, body: S.updateRuleBody }), wrap(async (req, res) => {
      const v = valid(req, { params: S.idParams, body: S.updateRuleBody });
      res.json(await this.c.updateRule(actorOf(req), v.params.id, v.body as never));
    }));
    r.delete('/rules/:id', manage, check({ params: S.idParams }), wrap(async (req, res) => {
      await this.c.deleteRule(actorOf(req), valid(req, { params: S.idParams }).params.id);
      res.status(204).end();
    }));

    r.get('/log', read, wrap(async (_req, res) => {
      res.json(await this.c.log());
    }));
  }
}
