/**
 * Single source of truth for permission keys. The catalog is synced to the
 * `permissions` table at startup; roles and assignments are managed at runtime.
 */
export const PERMISSIONS = {
  CVE_READ:            'cve:read',
  DASHBOARD_VIEW:      'dashboard:view',
  SYNC_VIEW:           'sync:view',
  SYNC_RUN:            'sync:run',
  USER_READ:           'user:read',
  USER_CREATE:         'user:create',
  USER_UPDATE:         'user:update',
  USER_DELETE:         'user:delete',
  USER_RESET_PASSWORD: 'user:reset-password',
  ROLE_READ:           'role:read',
  ROLE_MANAGE:         'role:manage',
  PERMISSION_ASSIGN:   'permission:assign',
  AUDIT_READ:          'audit:read',
  ASSET_READ:          'asset:read',
  ASSET_WRITE:         'asset:write',
  ASSET_DELETE:        'asset:delete',
  VULN_READ:           'vuln:read',
  VULN_UPDATE:         'vuln:update',
  ALERT_READ:          'alert:read',
  ALERT_MANAGE:        'alert:manage',
  INTEL_READ:          'intel:read',
  INTEL_MANAGE:        'intel:manage',
  REPORT_READ:         'report:read',
  REPORT_MANAGE:       'report:manage',
} as const;

export type PermissionKey = typeof PERMISSIONS[keyof typeof PERMISSIONS];

export interface PermissionDefinition {
  key: PermissionKey;
  module: string;
  description: string;
}

export const PERMISSION_CATALOG: PermissionDefinition[] = [
  { key: PERMISSIONS.CVE_READ,            module: 'cve',       description: 'Search and view CVEs' },
  { key: PERMISSIONS.DASHBOARD_VIEW,      module: 'dashboard', description: 'View dashboard statistics' },
  { key: PERMISSIONS.SYNC_VIEW,           module: 'sync',      description: 'View data source sync status' },
  { key: PERMISSIONS.SYNC_RUN,            module: 'sync',      description: 'Trigger data source sync' },
  { key: PERMISSIONS.USER_READ,           module: 'user',      description: 'List and view users' },
  { key: PERMISSIONS.USER_CREATE,         module: 'user',      description: 'Invite users' },
  { key: PERMISSIONS.USER_UPDATE,         module: 'user',      description: 'Edit users, roles and sessions' },
  { key: PERMISSIONS.USER_DELETE,         module: 'user',      description: 'Delete users' },
  { key: PERMISSIONS.USER_RESET_PASSWORD, module: 'user',      description: 'Issue password reset links' },
  { key: PERMISSIONS.ROLE_READ,           module: 'role',      description: 'List and view roles' },
  { key: PERMISSIONS.ROLE_MANAGE,         module: 'role',      description: 'Create, edit and delete roles' },
  { key: PERMISSIONS.PERMISSION_ASSIGN,   module: 'role',      description: 'Grant/deny permissions directly to users' },
  { key: PERMISSIONS.AUDIT_READ,          module: 'audit',     description: 'View the audit log' },
  { key: PERMISSIONS.ASSET_READ,          module: 'asset',     description: 'View the asset inventory' },
  { key: PERMISSIONS.ASSET_WRITE,         module: 'asset',     description: 'Add, edit and import assets' },
  { key: PERMISSIONS.ASSET_DELETE,        module: 'asset',     description: 'Delete assets' },
  { key: PERMISSIONS.VULN_READ,           module: 'vuln',      description: 'View vulnerabilities found on assets' },
  { key: PERMISSIONS.VULN_UPDATE,         module: 'vuln',      description: 'Change vulnerability status and re-run matching' },
  { key: PERMISSIONS.ALERT_READ,          module: 'alert',     description: 'View alert rules, channels and history' },
  { key: PERMISSIONS.ALERT_MANAGE,        module: 'alert',     description: 'Manage alert rules and channels' },
  { key: PERMISSIONS.INTEL_READ,          module: 'intel',     description: 'View watchlists and indicators' },
  { key: PERMISSIONS.INTEL_MANAGE,        module: 'intel',     description: 'Manage watchlists and indicators' },
  { key: PERMISSIONS.REPORT_READ,         module: 'report',    description: 'View and download reports' },
  { key: PERMISSIONS.REPORT_MANAGE,       module: 'report',    description: 'Schedule and generate reports' },
];

const ALL = PERMISSION_CATALOG.map((p) => p.key);

/** Day-to-day security operations: inventory, vulnerabilities, alerts, intel and reports. */
const OPERATIONS: PermissionKey[] = [
  PERMISSIONS.ASSET_READ, PERMISSIONS.ASSET_WRITE, PERMISSIONS.ASSET_DELETE, PERMISSIONS.VULN_READ, PERMISSIONS.VULN_UPDATE,
  PERMISSIONS.ALERT_READ, PERMISSIONS.ALERT_MANAGE, PERMISSIONS.INTEL_READ, PERMISSIONS.INTEL_MANAGE,
  PERMISSIONS.REPORT_READ, PERMISSIONS.REPORT_MANAGE,
];

export interface SystemRoleDefinition {
  name: string;
  description: string;
  permissions: PermissionKey[];
  /** Permissions always equal the whole catalog (re-synced at startup). */
  allPermissions?: boolean;
}

export const SYSTEM_ROLES: SystemRoleDefinition[] = [
  { name: 'super_admin', description: 'Full access', permissions: ALL, allPermissions: true },
  {
    name: 'admin',
    description: 'Manages users and operations',
    permissions: [
      PERMISSIONS.CVE_READ, PERMISSIONS.DASHBOARD_VIEW, PERMISSIONS.SYNC_VIEW, PERMISSIONS.SYNC_RUN,
      PERMISSIONS.USER_READ, PERMISSIONS.USER_CREATE, PERMISSIONS.USER_UPDATE, PERMISSIONS.USER_DELETE,
      PERMISSIONS.USER_RESET_PASSWORD, PERMISSIONS.ROLE_READ, PERMISSIONS.AUDIT_READ,
      ...OPERATIONS,
    ],
  },
  {
    name: 'analyst',
    description: 'Threat analyst',
    permissions: [PERMISSIONS.CVE_READ, PERMISSIONS.DASHBOARD_VIEW, PERMISSIONS.SYNC_VIEW, ...OPERATIONS],
  },
  {
    name: 'viewer',
    description: 'Read-only',
    permissions: [
      PERMISSIONS.CVE_READ, PERMISSIONS.DASHBOARD_VIEW, PERMISSIONS.ASSET_READ, PERMISSIONS.VULN_READ,
      PERMISSIONS.ALERT_READ, PERMISSIONS.INTEL_READ, PERMISSIONS.REPORT_READ,
    ],
  },
];

export const SUPER_ADMIN_ROLE = 'super_admin';
