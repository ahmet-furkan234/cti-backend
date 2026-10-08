import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { ITokenService } from '../../../application/ports/ports.js';
import { EffectivePermissionService } from '../../../application/rbac/services/effective-permission.service.js';
import type { ICompanyRepository } from '../../../domain/company/company.repository.interface.js';
import { PERMISSIONS } from '../../../domain/rbac/permission-catalog.js';
import { tenant } from '../../../shared/tenant.js';
import { Errors, errorBody } from '../../../shared/strings.js';

/** Header a platform user sends to work inside another company. */
export const COMPANY_HEADER = 'x-company-id';

@injectable()
export class AuthMiddleware {
  constructor(
    @inject(TYPES.ITokenService) private readonly tokens: ITokenService,
    @inject(TYPES.EffectivePermissionService) private readonly perms: EffectivePermissionService,
    @inject(TYPES.ICompanyRepository) private readonly companies: ICompanyRepository,
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
      // Everything below runs inside one company: the user's own, or (platform managers only) the one they entered.
      let companyId = access.companyId;
      let platform = access.platform;
      const requested = req.header(COMPANY_HEADER);
      if (requested && requested !== access.companyId) {
        if (!access.platform || !access.permissions.includes(PERMISSIONS.COMPANY_MANAGE)) {
          res.status(403).json(errorBody(Errors.platformOnly));
          return;
        }
        const target = /^[0-9a-f-]{36}$/i.test(requested) ? await this.companies.findById(requested) : null;
        if (!target) {
          res.status(404).json(errorBody(Errors.invalidCompany));
          return;
        }
        companyId = target.id;
        platform = target.isPlatform;
      }
      req.auth = { userId: claims.sub, email: access.email, permissions: access.permissions, companyId, platform, homeCompanyId: access.companyId };
      tenant.run({ companyId, platform }, () => next());
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

  /** Like requirePermission, but a user may always act on their own `:id` record. */
  requirePermissionOrSelf = (...keys: string[]): RequestHandler => {
    const need = this.requirePermission(...keys);
    return (req, res, next) => (req.auth?.userId === req.params.id ? next() : need(req, res, next));
  };

  /** Global system operations are available only in the main platform company scope. */
  requirePlatform: RequestHandler = (req, res, next) => {
    if (req.auth?.platform) return next();
    res.status(403).json(errorBody(Errors.platformOnly));
  };
}
