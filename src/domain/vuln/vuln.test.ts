import { describe, expect, it } from 'vitest';
import { componentsOf, toComponent } from './components.js';
import { matchVersion, parseCpe } from './matching.js';
import { riskScore, slaHoursLeft } from './risk.js';
import { compareVersions, upstreamVersion } from './version.js';

describe('versions', () => {
  it('drops epoch and distro suffix', () => {
    expect(upstreamVersion('1:8.9p1-3ubuntu0.6')).toBe('8.9p1');
    expect(upstreamVersion('2.4.57')).toBe('2.4.57');
  });
  it('orders numerically, not lexically', () => {
    expect(compareVersions('1.10.0', '1.9.0')).toBeGreaterThan(0);
    expect(compareVersions('8.9p1', '9.3')).toBeLessThan(0);
    expect(compareVersions('1.0', '1.0.0')).toBe(0);
  });
});

describe('cpe matching', () => {
  const ssh = [{ c: 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*', vsi: '8.5', vee: '9.3' }];
  it('parses vendor and product', () => {
    expect(parseCpe('cpe:2.3:a:openbsd:openssh:8.9:*:*:*:*:*:*:*')).toEqual({ vendor: 'openbsd', product: 'openssh', version: '8.9' });
  });
  it('flags versions inside the range and reports the fix', () => {
    expect(matchVersion(ssh, 'openbsd:openssh', '8.9p1')).toEqual({ vulnerable: true, fixedIn: '9.3' });
  });
  it('ignores versions outside the range', () => {
    expect(matchVersion(ssh, 'openbsd:openssh', '9.3').vulnerable).toBe(false);
    expect(matchVersion(ssh, 'openbsd:openssh', '8.4').vulnerable).toBe(false);
  });
  it('matches a pinned version exactly', () => {
    const pinned = [{ c: 'cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*' }];
    expect(matchVersion(pinned, 'f5:nginx', '1.18.0').vulnerable).toBe(true);
    expect(matchVersion(pinned, 'f5:nginx', '1.18.1').vulnerable).toBe(false);
  });
  it('ignores other products', () => {
    expect(matchVersion(ssh, 'openssl:openssl', '8.9').vulnerable).toBe(false);
  });
});

describe('components', () => {
  it('maps well-known names to NVD vendor:product', () => {
    expect(toComponent('OpenSSH', '8.9p1')).toMatchObject({ vendor: 'openbsd', product: 'openssh' });
  });
  it('slugs unknown names and leaves the vendor to be resolved', () => {
    expect(toComponent('My Tool', '1.0')).toMatchObject({ vendor: null, product: 'my_tool' });
  });
  it('derives components from the form answers of an asset', () => {
    const out = componentsOf({ type: 'web', os: null, software: [], attrs: { webserver: 'nginx', webserver_version: '1.18.0' } });
    expect(out).toEqual([{ label: 'nginx', vendor: 'f5', product: 'nginx', version: '1.18.0' }]);
  });
  it('treats "other" as unknown', () => {
    expect(componentsOf({ type: 'web', os: null, software: [], attrs: { webserver: 'other' } })).toEqual([]);
  });
});

describe('risk', () => {
  it('adds the factors and caps at 100', () => {
    expect(riskScore({ cvss: 10, kev: true, epss: 1, exposed: true, env: 'prod' })).toBe(100);
    expect(riskScore({ cvss: 5, kev: false, epss: 0, exposed: false, env: 'dev' })).toBe(18);
  });
  it('counts the fix window down and stops once handled', () => {
    const base = { cvss: 9.8, kev: true, firstSeenAt: new Date(Date.now() - 80 * 3_600_000) };
    expect(slaHoursLeft({ ...base, status: 'open' })).toBe(-8);
    expect(slaHoursLeft({ ...base, status: 'mitigated' })).toBeNull();
  });
});
