import { Router, type Router as ExpressRouter } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import { PERMISSIONS as P } from '../../../domain/rbac/permission-catalog.js';
import type { IPushDeviceRepository } from '../../../domain/alerts/push-device.repository.interface.js';
import { asyncWrapper as wrap } from '../middleware/async-wrapper.middleware.js';
import { AuthMiddleware } from '../middleware/auth.middleware.js';
import { validateRequest as check, valid } from '../middleware/validate.middleware.js';
import * as S from '../schemas/schemas.js';

/** Mobile app installs register their FCM token here so alerts can reach the phone. */
@injectable()
export class DeviceRouter {
  readonly router: ExpressRouter = Router();

  constructor(
    @inject(TYPES.IPushDeviceRepository) private readonly devices: IPushDeviceRepository,
    @inject(TYPES.AuthMiddleware) private readonly auth: AuthMiddleware,
  ) {
    const r = this.router;
    r.use(this.auth.authenticate);

    r.put('/', this.auth.requirePermission(P.ALERT_READ), check({ body: S.registerDeviceBody }), wrap(async (req, res) => {
      const b = valid(req, { body: S.registerDeviceBody }).body;
      await this.devices.upsert(b.token, req.auth!.userId, b.platform);
      res.status(204).end();
    }));

    // No permission needed: signing out must always be able to detach the phone.
    r.delete('/', check({ body: S.removeDeviceBody }), wrap(async (req, res) => {
      await this.devices.remove(valid(req, { body: S.removeDeviceBody }).body.token, req.auth!.userId);
      res.status(204).end();
    }));
  }
}
