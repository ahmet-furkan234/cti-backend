import { DomainException } from '../common/exceptions.js';
import { Errors } from '../../shared/strings.js';

export class InvalidCredentialsException extends DomainException {
  constructor() {
    super(Errors.invalidCredentials);
  }
}
export class UserInactiveException extends DomainException {
  constructor() {
    super(Errors.userInactive);
  }
}
export class RefreshTokenInvalidException extends DomainException {
  constructor() {
    super(Errors.refreshTokenInvalid);
  }
}
export class AuthTokenInvalidException extends DomainException {
  constructor() {
    super(Errors.authTokenInvalid);
  }
}
