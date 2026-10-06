import { describe, expect, it } from 'vitest';
import { componentsOf } from './components.js';
import { osComponent } from './os.js';

describe('operating system', () => {
  it('needs a build number for Windows and picks the release from it', () => {
    expect(osComponent('Windows Server', '10.0.17763.5329')).toMatchObject({ vendor: 'microsoft', product: 'windows_server_2019', version: '10.0.17763.5329' });
    expect(osComponent('Windows 10', '10.0.19045.4170')?.product).toBe('windows_10_22h2');
    expect(osComponent('Windows 11', '10.0.26100.1')?.product).toBe('windows_11_24h2');
    expect(osComponent('Windows Server', '2019')).toBeNull();
    expect(osComponent('Windows 10', '10.0.99999.1')).toBeNull();
  });
  it('uses the major release for Debian and Red Hat, as the CVE data does', () => {
    expect(osComponent('Debian', '12.5')).toMatchObject({ product: 'debian_linux', version: '12.0' });
    expect(osComponent('Red Hat Enterprise Linux', '9.2')).toMatchObject({ product: 'enterprise_linux', version: '9.0' });
  });
  it('keeps Ubuntu and macOS versions as written; ignores what it cannot match', () => {
    expect(osComponent('Ubuntu', '22.04 LTS')).toMatchObject({ vendor: 'canonical', product: 'ubuntu_linux', version: '22.04 LTS' });
    expect(osComponent('macOS', '14.5')).toMatchObject({ product: 'macos', version: '14.5' });
    expect(osComponent('SUSE', '15')).toBeNull();
    expect(osComponent('other', '1')).toBeNull();
    expect(osComponent('Ubuntu', '')).toBeNull();
  });
  it('adds the operating system to what a server is matched on', () => {
    const c = componentsOf({ type: 'server', os: null, software: [], attrs: { os: 'Ubuntu', os_version: '22.04 LTS' } });
    expect(c).toEqual([{ label: 'Ubuntu', vendor: 'canonical', product: 'ubuntu_linux', version: '22.04 LTS' }]);
  });
});
