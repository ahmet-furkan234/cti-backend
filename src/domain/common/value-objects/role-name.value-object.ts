import { InvalidValueException } from '../exceptions.js';
import { Errors } from '../../../shared/strings.js';
import { attempt, ValueObject } from './value-object.js';

const ROLE_NAME_PATTERN = /^[a-z0-9][a-z0-9_\- ]*$/;

/** Lowercased role name, 2-50 characters. */
export class RoleName extends ValueObject<string> {
  static from(raw: string): RoleName {
    const value = raw.trim().toLowerCase();
    if (value.length < 2 || value.length > 50 || !ROLE_NAME_PATTERN.test(value)) {
      throw new InvalidValueException(Errors.invalidRoleName);
    }
    return new RoleName(value);
  }

  static tryFrom(raw: string): RoleName | null {
    return attempt(() => RoleName.from(raw));
  }
}
