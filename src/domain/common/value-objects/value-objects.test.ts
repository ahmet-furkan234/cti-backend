import { describe, expect, it } from 'vitest';
import { InvalidValueException } from '../exceptions.js';
import { CveId, Email, PermissionKey, PlainPassword, RoleName } from './index.js';

describe('Email', () => {
  it('normalises case and whitespace', () => {
    expect(Email.from('  Foo.Bar@Example.COM ').value).toBe('foo.bar@example.com');
  });
  it('exposes local part and domain', () => {
    const e = Email.from('a+tag@sub.example.com');
    expect([e.localPart, e.domain]).toEqual(['a+tag', 'sub.example.com']);
  });
  it.each(['', 'no-at-sign', 'a@b', 'a b@c.com', '@x.com', 'a@.com', `${'x'.repeat(250)}@e.com`])('rejects %j', (bad) => {
    expect(() => Email.from(bad)).toThrow(InvalidValueException);
    expect(Email.tryFrom(bad)).toBeNull();
  });
  it('compares by value', () => {
    expect(Email.from('A@b.co').equals(Email.from('a@B.co'))).toBe(true);
    expect(Email.from('a@b.co').equals(Email.from('c@b.co'))).toBe(false);
    expect(Email.from('a@b.co').equals(null)).toBe(false);
  });
});

describe('PlainPassword', () => {
  it('enforces the length policy', () => {
    expect(() => PlainPassword.from('short')).toThrow(InvalidValueException);
    expect(() => PlainPassword.from('x'.repeat(129))).toThrow(InvalidValueException);
    expect(PlainPassword.from('x'.repeat(12)).reveal()).toBe('x'.repeat(12));
  });
  it('never leaks through string conversion or JSON (logs, error dumps)', () => {
    const p = PlainPassword.from('Correct-Horse-Battery-9!');
    expect(String(p)).toBe('[REDACTED]');
    expect(`${p}`).toBe('[REDACTED]');
    expect(JSON.stringify({ p })).toBe('{"p":"[REDACTED]"}');
  });
});

describe('CveId', () => {
  it('uppercases and exposes the year', () => {
    const id = CveId.from(' cve-2024-6387 ');
    expect(id.value).toBe('CVE-2024-6387');
    expect(id.year).toBe(2024);
  });
  it.each(['CVE-24-1234', 'CVE-2024-12', 'CVE2024-1234', 'CVE-2024-12a4', ''])('rejects %j', (bad) => {
    expect(CveId.tryFrom(bad)).toBeNull();
  });
});

describe('PermissionKey', () => {
  it('parses module and action', () => {
    const k = PermissionKey.from('user:reset-password');
    expect([k.module, k.action]).toEqual(['user', 'reset-password']);
  });
  it.each(['nocolon', 'Upper:case', 'a:', ':b', 'a:b:c', 'a b:c', '1a:b'])('rejects %j', (bad) => {
    expect(PermissionKey.tryFrom(bad)).toBeNull();
  });
  it('fromAll validates every key and de-duplicates', () => {
    expect(PermissionKey.fromAll(['cve:read', 'cve:read', 'audit:read']).map(String)).toEqual(['cve:read', 'audit:read']);
    expect(() => PermissionKey.fromAll(['cve:read', 'bad'])).toThrow(InvalidValueException);
  });
});

describe('RoleName', () => {
  it('lowercases and trims', () => {
    expect(RoleName.from('  Security Analyst ').value).toBe('security analyst');
  });
  it.each(['a', 'x'.repeat(51), '-lead', 'bad!name', ''])('rejects %j', (bad) => {
    expect(RoleName.tryFrom(bad)).toBeNull();
  });
});
