import { Router, type Router as ExpressRouter } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { PERMISSIONS as P } from '../../../domain/rbac/permission-catalog.js';
import { ReportController } from '../controllers/report.controller.js';
import { actorOf } from '../request-actor.js';
import { asyncWrapper as wrap } from '../middleware/async-wrapper.middleware.js';
import { AuthMiddleware } from '../middleware/auth.middleware.js';
import { validateRequest as check, valid } from '../middleware/validate.middleware.js';
import * as S from '../schemas/schemas.js';

@injectable()
export class ReportRouter {
  readonly router: ExpressRouter = Router();

  constructor(
    @inject(TYPES.ReportController) private readonly c: ReportController,
    @inject(TYPES.AuthMiddleware) private readonly auth: AuthMiddleware,
  ) {
    const r = this.router;
    const read = this.auth.requirePermission(P.REPORT_READ);
    const manage = this.auth.requirePermission(P.REPORT_MANAGE);
    r.use(this.auth.authenticate);

    r.get('/schedules', read, wrap(async (_req, res) => {
      res.json(await this.c.schedules());
    }));
    r.post('/schedules', manage, check({ body: S.scheduleBody }), wrap(async (req, res) => {
      res.status(201).json(await this.c.createSchedule(actorOf(req), valid(req, { body: S.scheduleBody }).body));
    }));
    r.patch('/schedules/:id', manage, check({ params: S.idParams, body: S.updateScheduleBody }), wrap(async (req, res) => {
      const v = valid(req, { params: S.idParams, body: S.updateScheduleBody });
      res.json(await this.c.updateSchedule(actorOf(req), v.params.id, v.body as never));
    }));
    r.delete('/schedules/:id', manage, check({ params: S.idParams }), wrap(async (req, res) => {
      await this.c.deleteSchedule(actorOf(req), valid(req, { params: S.idParams }).params.id);
      res.status(204).end();
    }));

    r.get('/runs', read, wrap(async (_req, res) => {
      res.json(await this.c.runs());
    }));
    r.post('/runs', manage, check({ body: S.generateReportBody }), wrap(async (req, res) => {
      res.status(201).json(await this.c.generate(actorOf(req), valid(req, { body: S.generateReportBody }).body));
    }));
    r.post('/runs/:id/retry', manage, check({ params: S.idParams }), wrap(async (req, res) => {
      res.status(201).json(await this.c.retry(actorOf(req), valid(req, { params: S.idParams }).params.id));
    }));
    r.get('/runs/:id/download', read, check({ params: S.idParams }), wrap(async (req, res) => {
      const file = await this.c.download(valid(req, { params: S.idParams }).params.id);
      res.setHeader('content-type', 'text/csv; charset=utf-8');
      res.setHeader('content-disposition', `attachment; filename="${file.filename.replace(/[^\w.\-]+/g, '_')}"`);
      res.send(file.content);
    }));
  }
}
