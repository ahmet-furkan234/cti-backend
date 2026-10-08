import { InvalidValueException } from '../exceptions.js';
import { Errors } from '../../../shared/strings.js';
import { ValueObject } from './value-object.js';

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128; // also bounds argon2 work per request

export function meetsPasswordPolicy(raw: string): boolean {
  return raw.length >= PASSWORD_MIN_LENGTH
    && raw.length <= PASSWORD_MAX_LENGTH
    && /[a-z]/.test(raw)
    && /[A-Z]/.test(raw)
    && /[0-9]/.test(raw)
    && /[^\p{L}\p{N}\s]/u.test(raw)
    && !/\s/u.test(raw);
}

/**
 * A password that satisfies the policy, not yet hashed. It never prints itself
 * (toString / JSON / logging show a placeholder); only `reveal()` hands out the text, for hashing.
 */
export class PlainPassword extends ValueObject<string> {
  static from(raw: string): PlainPassword {
    if (!meetsPasswordPolicy(raw)) {
      throw new InvalidValueException(Errors.weakPassword(PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH));
    }
    return new PlainPassword(raw);
  }

  reveal(): string {
    return this.value;
  }

  override toString(): string {
    return '[REDACTED]';
  }

  override toJSON(): string {
    return '[REDACTED]';
  }
}
