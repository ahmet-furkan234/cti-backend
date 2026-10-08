import { Router, type Router as ExpressRouter } from 'express';
import rateLimit from 'express-rate-limit';
import { inject, injectable } from 'inversify';
import { TYPES } from '../../../shared/tokens.js';
import type { EnvConfig } from '../../common/env.config.js';
import { AuthController } from '../controllers/auth.controller.js';
import { asyncWrapper as wrap } from '../middleware/async-wrapper.middleware.js';
import { AuthMiddleware } from '../middleware/auth.middleware.js';
import { actorOf } from '../request-actor.js';
import { clearRefreshCookie, readRefreshCookie, setRefreshCookie } from '../middleware/refresh-cookie.js';
import { validateRequest as check, valid } from '../middleware/validate.middleware.js';
import * as S from '../schemas/schemas.js';
import { RefreshTokenInvalidException } from '../../../domain/auth/auth.exceptions.js';
import type { IssuedSession } from '../../../application/auth/session.service.js';
import { Errors, errorBody } from '../../../shared/strings.js';

const limiter = (windowMs: number, limit: number) =>
  rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: errorBody(Errors.tooManyRequests),
  });

@injectable()
export class AuthRouter {
  readonly router: ExpressRouter = Router();

  constructor(
    @inject(TYPES.AuthController) private readonly c: AuthController,
    @inject(TYPES.AuthMiddleware) private readonly auth: AuthMiddleware,
    @inject(TYPES.EnvConfig) private readonly config: EnvConfig,
  ) {
    const r = this.router;
    const strict = limiter(15 * 60_000, 30);
    const client = (req: import('express').Request) => ({ ip: req.ip ?? null, userAgent: req.headers['user-agent'] ?? null });

    const respond = (res: import('express').Response, session: IssuedSession, extra: Record<string, unknown> = {}, status = 200) => {
      setRefreshCookie(res, this.config, session.refreshToken, session.refreshExpiresAt);
      res.status(status).json({ accessToken: session.accessToken, expiresIn: session.expiresIn, ...extra });
    };

    r.post('/login', strict, check({ body: S.loginBody }), wrap(async (req, res) => {
      const b = valid(req, { body: S.loginBody }).body;
      const { userId, session } = await this.c.login({ ...b, ...client(req) });
      respond(res, session, { user: await this.c.me(userId) });
    }));

    r.post('/refresh', limiter(60_000, 60), wrap(async (req, res) => {
      const token = readRefreshCookie(req);
      if (!token) throw new RefreshTokenInvalidException();
      try {
        respond(res, await this.c.refresh(token, client(req)));
      } catch (err) {
        clearRefreshCookie(res, this.config);
        throw err;
      }
    }));

    r.post('/logout', wrap(async (req, res) => {
      await this.c.logout(readRefreshCookie(req));
      clearRefreshCookie(res, this.config);
      res.status(204).end();
    }));

    r.get('/me', this.auth.authenticate, wrap(async (req, res) => {
      res.json(await this.c.me(req.auth!.userId, req.auth!.companyId));
    }));

    r.post('/change-password', strict, this.auth.authenticate, check({ body: S.changePasswordBody }), wrap(async (req, res) => {
      await this.c.changePassword(actorOf(req), valid(req, { body: S.changePasswordBody }).body);
      clearRefreshCookie(res, this.config);
      res.status(204).end();
    }));

    // Public, token-gated flows (invite registration / password reset)
    r.get('/invitations/:token', strict, check({ params: S.tokenParams }), wrap(async (req, res) => {
      res.json(await this.c.inviteInfo(valid(req, { params: S.tokenParams }).params.token));
    }));
    r.post('/register', strict, check({ body: S.registerBody }), wrap(async (req, res) => {
      const b = valid(req, { body: S.registerBody }).body;
      const { userId, session } = await this.c.register({ ...b, ...client(req) });
      respond(res, session, { user: await this.c.me(userId) }, 201);
    }));
    r.get('/reset-tokens/:token', strict, check({ params: S.tokenParams }), wrap(async (req, res) => {
      res.json(await this.c.resetInfo(valid(req, { params: S.tokenParams }).params.token));
    }));
    r.post('/reset-password', strict, check({ body: S.resetPasswordBody }), wrap(async (req, res) => {
      const b = valid(req, { body: S.resetPasswordBody }).body;
      await this.c.resetPassword({ ...b, ip: req.ip ?? null });
      res.status(204).end();
    }));
  }
}
