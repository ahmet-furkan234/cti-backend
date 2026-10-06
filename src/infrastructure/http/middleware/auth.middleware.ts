import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { ITokenService } from '../../../application/ports/ports.js';
import { EffectivePermissionService } from '../../../application/rbac/services/effective-permission.service.js';
import { Errors, errorBody } from '../../../shared/strings.js';

@injectable()
export class AuthMiddleware {
  constructor(
    @inject(TYPES.ITokenService) private readonly tokens: ITokenService,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
  ) {}

  authenticate: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const header = req.headers.authorization;
      const claims = header?.startsWith('Bearer ') ? this.tokens.verifyAccessToken(header.slice(7)) : null;
      if (!claims) {
        res.status(401).json(errorBody(Errors.unauthorized));
        return;
      }
      const access = await this.perms.getAccess(claims.sub);
      if (!access || !access.active) {
        res.status(401).json(errorBody(Errors.accountUnavailable));
        return;
      }
      req.auth = { userId: claims.sub, email: access.email, permissions: access.permissions };
      next();
    } catch (err) {
      next(err);
    }
  };

  /** Passes when the user holds at least one of the given permissions. */
  requirePermission = (...keys: string[]): RequestHandler => {
    return (req, res, next) => {
      const held = req.auth?.permissions ?? [];
      if (keys.some((k) => held.includes(k))) return next();
      res.status(403).json(errorBody(Errors.forbiddenRequired(keys)));
    };
  };
}
