import type { NextFunction, Request, Response } from 'express';
import {
  AccountLockedException, AlreadyExistsException, ConflictException, DomainException, ForbiddenException,
  InvalidStateException, InvalidValueException, NotFoundException, ServiceUnavailableException, UnauthorizedException,
} from '../../../domain/common/exceptions.js';
import {
  AuthTokenInvalidException, InvalidCredentialsException, RefreshTokenInvalidException, UserInactiveException,
} from '../../../domain/auth/auth.exceptions.js';
import { Errors, errorBody } from '../../../shared/strings.js';

function statusOf(err: DomainException): number {
  if (
    err instanceof InvalidCredentialsException || err instanceof UserInactiveException ||
    err instanceof RefreshTokenInvalidException || err instanceof UnauthorizedException
  ) return 401;
  if (err instanceof AccountLockedException) return 423;
  if (err instanceof ServiceUnavailableException) return 503;
  if (err instanceof AuthTokenInvalidException) return 400;
  if (err instanceof NotFoundException) return 404;
  if (err instanceof AlreadyExistsException || err instanceof ConflictException || err instanceof InvalidStateException) return 409;
  if (err instanceof InvalidValueException) return 422;
  if (err instanceof ForbiddenException) return 403;
  return 400;
}

export function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction): void {
  if (err instanceof DomainException) {
    const body: Record<string, unknown> = { error: err.code, message: err.message };
    if (err instanceof AccountLockedException) body['lockedUntil'] = err.lockedUntil;
    res.status(statusOf(err)).json(body);
    return;
  }
  if (err instanceof SyntaxError && 'body' in err) {
    res.status(400).json(errorBody(Errors.invalidJson));
    return;
  }
  (req as Request & { log?: { error: (o: unknown) => void } }).log?.error({ err });
  res.status(500).json(errorBody(Errors.internal));
}
