import { InvalidValueException } from '../exceptions.js';
import { Errors } from '../../../shared/strings.js';
import { attempt, ValueObject } from './value-object.js';

// module:action — lowercase words, `-` or `_` inside a word group (e.g. user:reset-password).
const PERMISSION_PATTERN = /^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*:[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$/;

/** A permission identifier such as `cve:read`. */
export class PermissionKey extends ValueObject<string> {
  static from(raw: string): PermissionKey {
    const value = raw.trim();
    if (!PERMISSION_PATTERN.test(value)) throw new InvalidValueException(Errors.invalidPermissionKey(raw));
    return new PermissionKey(value);
  }

  static tryFrom(raw: string): PermissionKey | null {
    return attempt(() => PermissionKey.from(raw));
  }

  /** Validates every key and removes duplicates (first occurrence wins). */
  static fromAll(raw: readonly string[]): PermissionKey[] {
    return [...new Map(raw.map((r) => PermissionKey.from(r)).map((k) => [k.value, k])).values()];
  }

  get module(): string {
    return this.value.slice(0, this.value.indexOf(':'));
  }

  get action(): string {
    return this.value.slice(this.value.indexOf(':') + 1);
  }
}
