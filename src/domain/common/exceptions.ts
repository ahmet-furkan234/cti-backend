import { Errors, type ErrorDef } from '../../shared/strings.js';

export abstract class DomainException extends Error {
  public readonly code: string;

  protected constructor(def: ErrorDef) {
    super(def.message);
    this.name = this.constructor.name;
    this.code = def.code;
    if (Error.captureStackTrace) Error.captureStackTrace(this, this.constructor);
  }
}

export class NotFoundException extends DomainException {
  constructor(entity: string) {
    super(Errors.notFound(entity));
  }
}
export class AlreadyExistsException extends DomainException {
  constructor(entity: string, field: string) {
    super(Errors.alreadyExists(entity, field));
  }
}
export class ConflictException extends DomainException {
  constructor(def: ErrorDef) {
    super(def);
  }
}
export class InvalidStateException extends DomainException {
  constructor(def: ErrorDef) {
    super(def);
  }
}
export class InvalidValueException extends DomainException {
  constructor(def: ErrorDef) {
    super(def);
  }
}
export class ForbiddenException extends DomainException {
  constructor(def: ErrorDef) {
    super(def);
  }
}
export class UnauthorizedException extends DomainException {
  constructor(def: ErrorDef = Errors.unauthorized) {
    super(def);
  }
}
export class AccountLockedException extends DomainException {
  constructor(public readonly lockedUntil: Date) {
    super(Errors.accountLocked);
  }
}

/** A dependency (queue, broker …) is down; maps to HTTP 503 so clients know a retry may succeed. */
export class ServiceUnavailableException extends DomainException {
  constructor(def: ErrorDef) {
    super(def);
  }
}
