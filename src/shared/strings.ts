/**
 * Every user-facing / externally visible string of the app lives here:
 * error codes + messages, validation messages, audit action names, entity names
 * and links sent to the web app. Keep wording changes (or translation) in this file only.
 */

export interface ErrorDef {
  code: string;
  message: string;
}

const def = (code: string, message: string): ErrorDef => ({ code, message });

/** Standard JSON error body: `{ error, message }`. */
export const errorBody = (d: ErrorDef) => ({ error: d.code, message: d.message });

export const Entity = {
  user: 'User',
  role: 'Role',
  cve: 'CVE',
  asset: 'Asset',
  vulnerability: 'Vulnerability',
  channel: 'Alert channel',
  rule: 'Alert rule',
  watchlist: 'Watchlist',
  indicator: 'Indicator',
  schedule: 'Report schedule',
  report: 'Report',
  softwareName: 'Software name',
} as const;

export const Errors = {
  // ---- generic / HTTP
  routeNotFound: def('NOT_FOUND', 'Route not found'),
  unauthorized: def('UNAUTHORIZED', 'Missing or invalid token'),
  accountUnavailable: def('UNAUTHORIZED', 'Account unavailable'),
  forbiddenRequired: (keys: string[]) => def('FORBIDDEN', `Required: ${keys.join(' | ')}`),
  tooManyRequests: def('TOO_MANY_REQUESTS', 'Too many requests, try again later'),
  validation: def('VALIDATION_ERROR', 'Request validation failed'),
  invalidJson: def('INVALID_JSON', 'Malformed JSON body'),
  internal: def('INTERNAL_SERVER_ERROR', 'An unexpected error occurred'),
  invalidCursor: def('INVALID_CURSOR', 'Invalid cursor'),
  invalidEmail: def('INVALID_EMAIL', 'Enter a valid email address'),
  weakPassword: (min: number, max: number) =>
    def('WEAK_PASSWORD', `Password must be between ${min} and ${max} characters`),
  invalidCveId: def('INVALID_CVE_ID', 'Invalid CVE id (expected CVE-YYYY-NNNN)'),
  invalidPermissionKey: (key: string) => def('INVALID_PERMISSION_KEY', `Invalid permission key: ${key} (expected module:action)`),
  invalidRoleName: def('INVALID_ROLE_NAME', 'Role names are 2-50 characters: letters, digits, space, _ and -'),
  notFound: (entity: string) => def('NOT_FOUND', `${entity} not found`),
  alreadyExists: (entity: string, field: string) =>
    def('ALREADY_EXISTS', `${entity} with this ${field} already exists`),

  // ---- auth
  invalidCredentials: def('INVALID_CREDENTIALS', 'Invalid email or password'),
  userInactive: def('USER_INACTIVE', 'User account is disabled'),
  accountLocked: def('ACCOUNT_LOCKED', 'Account is temporarily locked'),
  refreshTokenInvalid: def('REFRESH_TOKEN_INVALID', 'Refresh token is invalid or expired'),
  authTokenInvalid: def('AUTH_TOKEN_INVALID', 'This link is invalid or has expired'),

  // ---- users
  rolesMissing: def('INVALID_VALUE', 'One or more roles do not exist'),
  selfRoleChange: def('SELF_ROLE_CHANGE', 'You cannot change your own roles'),
  selfDisable: def('SELF_DISABLE', 'You cannot disable yourself'),
  selfDelete: def('SELF_DELETE', 'You cannot delete yourself'),
  selfPermissionChange: def('SELF_PERMISSION_CHANGE', 'You cannot change your own permissions'),
  lastSuperAdmin: def('LAST_SUPER_ADMIN', 'The last active super_admin cannot be removed'),
  insufficientPrivilege: def(
    'INSUFFICIENT_PRIVILEGE',
    'You cannot manage a user with more privileges than you have',
  ),
  privilegeEscalation: (keys: string[]) =>
    def('PRIVILEGE_ESCALATION', `You cannot grant permissions you do not hold: ${keys.join(', ')}`),
  unknownPermissions: (keys: string[]) => def('INVALID_VALUE', `Unknown permissions: ${keys.join(', ')}`),
  duplicateOverrides: def('INVALID_VALUE', 'Duplicate permission keys in overrides'),

  // ---- roles
  systemRoleNameImmutable: def('SYSTEM_ROLE_IMMUTABLE', 'System role names cannot be changed'),
  superAdminPermissionsImmutable: def('SYSTEM_ROLE_IMMUTABLE', 'super_admin always holds every permission'),
  systemRoleUndeletable: def('SYSTEM_ROLE_IMMUTABLE', 'System roles cannot be deleted'),
  roleInUse: (count: number) => def('ROLE_IN_USE', `Role is assigned to ${count} user(s)`),

  // ---- inventory / alerts / reports
  assetIdentityRequired: def('INVALID_VALUE', 'An asset needs a name or an address'),
  channelDeliveryFailed: (why: string) => def('CHANNEL_DELIVERY_FAILED', `Could not deliver the message: ${why}`),
  unknownProduct: (pair: string) => def('UNKNOWN_PRODUCT', `The CVE data has no product ${pair}`),
  reportNotReady: def('REPORT_NOT_READY', 'This report has no downloadable file'),

  // ---- sync
  syncRunning: def('SYNC_RUNNING', 'Sync is already running'),
  syncQueueUnavailable: def('SYNC_QUEUE_UNAVAILABLE', 'The job queue is unavailable; try again shortly'),
} as const;

export const Validation = {
  passwordMin: 'Password must be at least 12 characters',
  roleNameChars: 'Only letters, digits, space, _ and -',
  productNeedsVendor: 'product filter requires vendor',
  invalidCveId: 'Invalid CVE id',
} as const;

export const AuditAction = {
  authLogin: 'auth.login',
  authLoginFailed: 'auth.login_failed',
  authLoginBlocked: 'auth.login_blocked',
  authRegistered: 'auth.registered',
  authPasswordChanged: 'auth.password_changed',
  authPasswordReset: 'auth.password_reset',
  authRefreshReuseDetected: 'auth.refresh_reuse_detected',
  assetCreated: 'asset.created',
  assetUpdated: 'asset.updated',
  assetDeleted: 'asset.deleted',
  assetsImported: 'asset.imported',
  softwareAliasChanged: 'asset.software_alias_changed',
  vulnStatusChanged: 'vuln.status_changed',
  vulnRematched: 'vuln.rematched',
  channelCreated: 'alert.channel_created',
  channelUpdated: 'alert.channel_updated',
  channelDeleted: 'alert.channel_deleted',
  ruleCreated: 'alert.rule_created',
  ruleUpdated: 'alert.rule_updated',
  ruleDeleted: 'alert.rule_deleted',
  watchlistChanged: 'intel.watchlist_changed',
  indicatorChanged: 'intel.indicator_changed',
  reportScheduleChanged: 'report.schedule_changed',
  reportGenerated: 'report.generated',
  userInvited: 'user.invited',
  userUpdated: 'user.updated',
  userDeleted: 'user.deleted',
  userPermissionsChanged: 'user.permissions_changed',
  userPasswordResetIssued: 'user.password_reset_issued',
  userSessionsRevoked: 'user.sessions_revoked',
  roleCreated: 'role.created',
  roleUpdated: 'role.updated',
  roleDeleted: 'role.deleted',
  syncRequested: 'sync.requested',
} as const;

/** Paths of the web app that links sent to users point to. */
export const WebPath = {
  register: (token: string) => `/register?token=${token}`,
  resetPassword: (token: string) => `/reset-password?token=${token}`,
} as const;
