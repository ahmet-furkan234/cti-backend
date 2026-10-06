import { InvalidValueException } from '../exceptions.js';
import { Errors } from '../../../shared/strings.js';
import { attempt, ValueObject } from './value-object.js';

const MAX_LENGTH = 254;
// Deliberately permissive: real validation is delivering mail; this only rejects obvious garbage.
const EMAIL_PATTERN = /^[^\s@]+@[^\s@.][^\s@]*\.[^\s@]+$/;

/** Normalised (trimmed, lowercased) email address — the login identity. */
export class Email extends ValueObject<string> {
  static from(raw: string): Email {
    const value = raw.trim().toLowerCase();
    if (value.length === 0 || value.length > MAX_LENGTH || !EMAIL_PATTERN.test(value)) {
      throw new InvalidValueException(Errors.invalidEmail);
    }
    return new Email(value);
  }

  static tryFrom(raw: string): Email | null {
    return attempt(() => Email.from(raw));
  }

  get localPart(): string {
    return this.value.slice(0, this.value.lastIndexOf('@'));
  }

  get domain(): string {
    return this.value.slice(this.value.lastIndexOf('@') + 1);
  }
}
