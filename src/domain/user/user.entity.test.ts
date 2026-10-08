import { describe, expect, it } from 'vitest';
import { LOCK_MINUTES, MAX_FAILED_LOGINS, User } from './user.entity.js';

const make = () => new User({ companyId: 'c1', email: '  Foo@Example.COM ', name: ' Foo ', passwordHash: 'h' });

describe('User', () => {
  it('normalises email and name', () => {
    const u = make();
    expect(u.email.value).toBe('foo@example.com');
    expect(u.name).toBe('Foo');
  });

  it('locks after the maximum number of failed logins and resets the counter', () => {
    const u = make();
    const now = new Date('2026-01-01T00:00:00Z');
    for (let i = 0; i < MAX_FAILED_LOGINS; i++) u.registerFailedLogin(now);
    expect(u.isLocked(now)).toBe(true);
    expect(u.lockedUntil?.getTime()).toBe(now.getTime() + LOCK_MINUTES * 60_000);
    expect(u.failedLoginAttempts).toBe(0);
    expect(u.isLocked(new Date(now.getTime() + (LOCK_MINUTES + 1) * 60_000))).toBe(false);
  });

  it('clears failures and lock on successful login', () => {
    const u = make();
    u.registerFailedLogin();
    u.registerSuccessfulLogin();
    expect(u.failedLoginAttempts).toBe(0);
    expect(u.lastLoginAt).not.toBeNull();
  });
});
