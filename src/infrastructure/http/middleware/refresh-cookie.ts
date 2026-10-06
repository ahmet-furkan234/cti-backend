import type { CookieOptions, Request, Response } from 'express';
import type { EnvConfig } from '../../common/env.config.js';

export const REFRESH_COOKIE = 'cti_rt';
const COOKIE_PATH = '/api/v1/auth';

const base = (config: EnvConfig): CookieOptions => ({
  httpOnly: true,
  secure: config.COOKIE_SECURE,
  sameSite: 'lax',
  path: COOKIE_PATH,
});

export const setRefreshCookie = (res: Response, config: EnvConfig, token: string, expires: Date) =>
  res.cookie(REFRESH_COOKIE, token, { ...base(config), expires });

export const clearRefreshCookie = (res: Response, config: EnvConfig) =>
  res.clearCookie(REFRESH_COOKIE, base(config));

export const readRefreshCookie = (req: Request): string | undefined =>
  (req.cookies as Record<string, string> | undefined)?.[REFRESH_COOKIE];
