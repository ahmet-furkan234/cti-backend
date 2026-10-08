import { randomUUID } from 'crypto';
import { Email } from '../common/value-objects/email.value-object.js';

export type UserStatus = 'active' | 'disabled';

export interface UserProps {
  id?: string;
  /** the one company the user belongs to */
  companyId: string;
  email: string | Email;
  name: string;
  passwordHash: string;
  status?: UserStatus;
  failedLoginAttempts?: number;
  lockedUntil?: Date | null;
  lastLoginAt?: Date | null;
  createdAt?: Date;
  updatedAt?: Date;
}

export const MAX_FAILED_LOGINS = 5;
export const LOCK_MINUTES = 15;

export class User {
  public readonly id: string;
  public readonly companyId: string;
  public email: Email;
  public name: string;
  public passwordHash: string;
  public status: UserStatus;
  public failedLoginAttempts: number;
  public lockedUntil: Date | null;
  public lastLoginAt: Date | null;
  public readonly createdAt: Date;
  public updatedAt: Date;

  constructor(props: UserProps) {
    this.id = props.id ?? randomUUID();
    this.companyId = props.companyId;
    this.email = props.email instanceof Email ? props.email : Email.from(props.email);
    this.name = props.name.trim();
    this.passwordHash = props.passwordHash;
    this.status = props.status ?? 'active';
    this.failedLoginAttempts = props.failedLoginAttempts ?? 0;
    this.lockedUntil = props.lockedUntil ?? null;
    this.lastLoginAt = props.lastLoginAt ?? null;
    this.createdAt = props.createdAt ?? new Date();
    this.updatedAt = props.updatedAt ?? new Date();
  }

  get isActive(): boolean {
    return this.status === 'active';
  }

  isLocked(now = new Date()): boolean {
    return this.lockedUntil !== null && this.lockedUntil > now;
  }

  registerFailedLogin(now = new Date()): void {
    this.failedLoginAttempts += 1;
    if (this.failedLoginAttempts >= MAX_FAILED_LOGINS) {
      this.lockedUntil = new Date(now.getTime() + LOCK_MINUTES * 60_000);
      this.failedLoginAttempts = 0;
    }
    this.touch();
  }

  registerSuccessfulLogin(now = new Date()): void {
    this.failedLoginAttempts = 0;
    this.lockedUntil = null;
    this.lastLoginAt = now;
    this.touch();
  }

  changePasswordHash(hash: string): void {
    this.passwordHash = hash;
    this.failedLoginAttempts = 0;
    this.lockedUntil = null;
    this.touch();
  }

  rename(name: string): void {
    this.name = name.trim();
    this.touch();
  }

  setStatus(status: UserStatus): void {
    this.status = status;
    this.touch();
  }

  private touch(): void {
    this.updatedAt = new Date();
  }
}
