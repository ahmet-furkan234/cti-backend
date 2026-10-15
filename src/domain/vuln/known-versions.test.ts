import { describe, expect, it } from 'vitest';
import { RELEASE_SOURCES, newestFirst, simpleVersion, tagVersions, versionsFromMatches } from './known-versions.js';

describe('known versions', () => {
  it('simplifies versions and rejects pre-releases', () => {
    expect(simpleVersion('9.6p1')).toBe('9.6');
    expect(simpleVersion('1.2.3')).toBe('1.2.3');
    expect(simpleVersion('9.0rc1')).toBeNull();
    expect(simpleVersion('*')).toBeNull();
  });
  it('collects exact versions and range ends for the product only', () => {
    const v = versionsFromMatches([
      { c: 'cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*' },
      { c: 'cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*', vsi: '7.4', vee: '9.7' },
      { c: 'cpe:2.3:a:other:thing:1.0:*:*:*:*:*:*:*' },
    ], ['openbsd:openssh']);
    expect(newestFirst(v)).toEqual(['9.7', '8.9', '7.4']);
  });
  it('reads release tags', () => {
    expect(RELEASE_SOURCES['openssh']!.tag('V_9_9_P1')).toBe('9.9');
    expect(RELEASE_SOURCES['nginx']!.tag('release-1.27.2')).toBe('1.27.2');
    expect(RELEASE_SOURCES['openssh']!.tag('V_9_9_P1_RC1')).toBeNull();
  });
  it('reads versions from a git ref advertisement', () => {
    const ad = '003fabc refs/tags/V_9_8_P1\n0041def refs/tags/V_9_9_P1\n0042fed refs/tags/V_9_9_P1^{}\n0030aaa refs/tags/V_9_9_P1_RC1\n';
    expect(newestFirst(tagVersions(ad, RELEASE_SOURCES['openssh']!.tag))).toEqual(['9.9', '9.8']);
  });
});
