import { describe, expect, it } from 'vitest';
import { ProductIndex, compact, editDistance } from './product-index.js';

const index = new ProductIndex([
  { pair: 'openbsd:openssh', cves: 120 }, { pair: 'openssl:openssl', cves: 300 }, { pair: 'f5:nginx', cves: 90 },
  { pair: 'apache:http_server', cves: 400 }, { pair: 'openvpn:openvpn', cves: 40 }, { pair: 'acme:server', cves: 3 }, { pair: 'other:server', cves: 2 },
]);

describe('product index', () => {
  it('normalises spelling', () => {
    expect(compact('Open-SSH_Server 2')).toBe('opensshserver2');
  });
  it('bounds the edit distance', () => {
    expect(editDistance('openssh', 'opnssh', 2)).toBe(1);
    expect(editDistance('abc', 'xyzxyz', 1)).toBe(2);
  });
  it('finds a product by exact name, spelling variant and underscores', () => {
    expect(index.pairsOf('openssh')).toEqual(['openbsd:openssh']);
    expect(index.pairsOf('Open SSH')).toEqual(['openbsd:openssh']);
    expect(index.pairsOf('HTTP Server')).toEqual(['apache:http_server']);
  });
  it('returns every vendor of a shared product name', () => {
    expect(index.pairsOf('server').sort()).toEqual(['acme:server', 'other:server']);
  });
  it('does not invent a match for a typo, but suggests the near ones', () => {
    expect(index.has('opnssh')).toBe(false);
    expect(index.suggest('opnssh')[0]?.product).toBe('openssh');
    expect(index.suggest('ngnix')[0]?.product).toBe('nginx');
  });
  it('treats a prefix as autocomplete, most used first', () => {
    expect(index.suggest('open').map((s) => s.product)).toEqual(['openssl', 'openssh', 'openvpn']);
  });
  it('suggests nothing for noise', () => {
    expect(index.suggest('zzzzzzzz')).toEqual([]);
    expect(index.suggest('a')).toEqual([]);
  });
});

describe('team-defined names', () => {
  const withAlias = new ProductIndex([{ pair: 'openbsd:openssh', cves: 120 }, { pair: 'f5:nginx', cves: 90 }], [{ name: 'Our Gateway', pair: 'f5:nginx' }]);
  it('resolves an alias, ahead of any product of the same name', () => {
    expect(withAlias.pairsOf('our gateway')).toEqual(['f5:nginx']);
    expect(withAlias.pairsOf('Our-Gateway')).toEqual(['f5:nginx']);
  });
  it('offers aliases in the picker and marks them', () => {
    expect(withAlias.search('our')[0]).toMatchObject({ product: 'Our Gateway', alias: true, cves: 90 });
  });
  it('offers the team names, then the shortlist in its groups, before anything is typed', () => {
    const list = withAlias.search('');
    expect(list.map((s) => s.product)).toEqual(['Our Gateway', 'nginx', 'openssh']);
    expect(list.map((s) => s.group)).toEqual([undefined, 'web', 'tools']);
  });
  it('leaves out shortlist products the CVE data barely knows', () => {
    expect(new ProductIndex([{ pair: 'x:nginx', cves: 2 }]).search('')).toEqual([]);
  });
  it('lists an exact match first in the picker', () => {
    expect(withAlias.search('nginx')[0]?.product).toBe('nginx');
  });
});
