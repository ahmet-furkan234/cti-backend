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

    // Native apps have no cookie jar to rely on: they send `x-client: mobile`, get the refresh token in the body
    // and keep it in the OS keychain. Web keeps the httpOnly cookie and never sees the token.
    const isMobile = (req: import('express').Request) => req.headers['x-client'] === 'mobile';
    const bodyToken = (req: import('express').Request): string | undefined => {
      const t = (req.body as { refreshToken?: unknown } | undefined)?.refreshToken;
      return isMobile(req) && typeof t === 'string' && t.length > 0 && t.length < 512 ? t : undefined;
    };

    const respond = (req: import('express').Request, res: import('express').Response, session: IssuedSession, extra: Record<string, unknown> = {}, status = 200) => {
      if (isMobile(req)) {
        res.status(status).json({ accessToken: session.accessToken, expiresIn: session.expiresIn, refreshToken: session.refreshToken, refreshExpiresAt: session.refreshExpiresAt, ...extra });
        return;
      }
      setRefreshCookie(res, this.config, session.refreshToken, session.refreshExpiresAt);
      res.status(status).json({ accessToken: session.accessToken, expiresIn: session.expiresIn, ...extra });
    };

    r.post('/login', strict, check({ body: S.loginBody }), wrap(async (req, res) => {
      const b = valid(req, { body: S.loginBody }).body;
      const { userId, session } = await this.c.login({ ...b, ...client(req) });
      respond(req, res, session, { user: await this.c.me(userId) });
    }));

    r.post('/refresh', limiter(60_000, 60), wrap(async (req, res) => {
      const token = bodyToken(req) ?? readRefreshCookie(req);
      if (!token) throw new RefreshTokenInvalidException();
      try {
        respond(req, res, await this.c.refresh(token, client(req)));
      } catch (err) {
        clearRefreshCookie(res, this.config);
        throw err;
      }
    }));

    r.post('/logout', wrap(async (req, res) => {
      await this.c.logout(bodyToken(req) ?? readRefreshCookie(req));
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
      respond(req, res, session, { user: await this.c.me(userId) }, 201);
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
