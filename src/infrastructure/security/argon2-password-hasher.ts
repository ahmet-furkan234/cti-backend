import argon2 from 'argon2';
import { injectable } from 'inversify';
import type { IPasswordHasher } from '../../application/ports/ports.js';

@injectable()
export class Argon2PasswordHasher implements IPasswordHasher {
  hash(plain: string): Promise<string> {
    return argon2.hash(plain, { type: argon2.argon2id });
  }

  async verify(hash: string, plain: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, plain);
    } catch {
      return false;
    }
  }
}
