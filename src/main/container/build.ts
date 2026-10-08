import 'reflect-metadata';
import { Container } from 'inversify';
import type { ISyncJobQueue } from '../../application/ports/ports.js';
import { TYPES } from '../../shared/tokens.js';
import { EnvConfig } from '../../infrastructure/common/env.config.js';
import { createLogger } from '../../infrastructure/common/logger.js';
import { createDatabase } from '../../infrastructure/database/client.js';
import { Argon2PasswordHasher } from '../../infrastructure/security/argon2-password-hasher.js';
import { JwtTokenService } from '../../infrastructure/security/jwt-token.service.js';
import { UserRepository } from '../../infrastructure/database/repositories/user.repository.js';
import { PermissionRepository, RoleRepository } from '../../infrastructure/database/repositories/rbac.repository.js';
import { AuthTokenRepository, RefreshTokenRepository } from '../../infrastructure/database/repositories/auth.repositories.js';
import { AuditRepository } from '../../infrastructure/database/repositories/audit.repository.js';
import { CveRepository } from '../../infrastructure/database/repositories/cve.repository.js';
import { AssetRepository } from '../../infrastructure/database/repositories/asset.repository.js';
import { VulnRepository } from '../../infrastructure/database/repositories/vuln.repository.js';
import { AlertRepository } from '../../infrastructure/database/repositories/alert.repository.js';
import { ChannelDispatcher } from '../../infrastructure/notify/channel-dispatcher.js';
import { AlertEvaluatorService } from '../../application/alerts/alert-evaluator.service.js';
import { AlertUseCases } from '../../application/alerts/alert.use-cases.js';
import { AlertController } from '../../infrastructure/http/controllers/alert.controller.js';
import { AlertRouter } from '../../infrastructure/http/routers/alert.router.js';
import { IntelRepository } from '../../infrastructure/database/repositories/intel.repository.js';
import { IntelUseCases } from '../../application/intel/intel.use-cases.js';
import { IntelController } from '../../infrastructure/http/controllers/intel.controller.js';
import { IntelRouter } from '../../infrastructure/http/routers/intel.router.js';
import { ReportRepository } from '../../infrastructure/database/repositories/report.repository.js';
import { ReportService } from '../../application/report/report.service.js';
import { ReportUseCases } from '../../application/report/report.use-cases.js';
import { ReportController } from '../../infrastructure/http/controllers/report.controller.js';
import { ReportRouter } from '../../infrastructure/http/routers/report.router.js';
import { SyncStateRepository } from '../../infrastructure/database/repositories/sync-state.repository.js';
import { BullMqSyncJobQueue } from '../../infrastructure/queue/bullmq-sync-job-queue.js';
import { EffectivePermissionService } from '../../application/rbac/services/effective-permission.service.js';
import { CatalogBootstrapService } from '../../application/rbac/services/catalog-bootstrap.service.js';
import { AuditService } from '../../application/audit/audit.service.js';
import { SessionService } from '../../application/auth/session.service.js';
import { LoginUseCase } from '../../application/auth/use-cases/login.use-case.js';
import { RefreshSessionUseCase } from '../../application/auth/use-cases/refresh-session.use-case.js';
import { LogoutUseCase } from '../../application/auth/use-cases/logout.use-case.js';
import { GetMeUseCase } from '../../application/auth/use-cases/get-me.use-case.js';
import { ChangePasswordUseCase } from '../../application/auth/use-cases/change-password.use-case.js';
import {
  GetAuthTokenInfoUseCase, RegisterWithInviteUseCase, ResetPasswordUseCase,
} from '../../application/auth/use-cases/auth-token.use-cases.js';
import {
  CreateUserUseCase, DeleteUserUseCase, GetUserEffectivePermissionsUseCase, GetUserUseCase, InviteUserUseCase,
  IssuePasswordResetUseCase, ListUserSessionsUseCase, ListUsersUseCase, RevokeUserSessionUseCase, RevokeUserSessionsUseCase, SetUserPermissionOverridesUseCase,
  UpdateUserUseCase,
} from '../../application/user/use-cases/user.use-cases.js';
import {
  CreateRoleUseCase, DeleteRoleUseCase, GetRoleUseCase, ListPermissionsUseCase, ListRolesUseCase, UpdateRoleUseCase,
} from '../../application/rbac/use-cases/role.use-cases.js';
import { ListAuditLogUseCase } from '../../application/audit/list-audit-log.use-case.js';
import { GetCveStatsUseCase, GetCveUseCase, SearchCvesUseCase } from '../../application/cve/use-cases/cve.use-cases.js';
import { GetSyncStatusUseCase, RequestSyncUseCase } from '../../application/sync/use-cases/sync-status.use-cases.js';
import { ProductCatalogService } from '../../application/vuln/product-catalog.service.js';
import { MatchAssetsService } from '../../application/vuln/match-assets.service.js';
import {
  CreateAssetUseCase, DeleteAssetUseCase, GetAssetUseCase, ImportAssetsUseCase, ListAssetsUseCase, ListImportsUseCase, UpdateAssetUseCase, CheckSoftwareUseCase, SoftwareCatalogUseCases,
} from '../../application/inventory/inventory.use-cases.js';
import { ListCveAssetsUseCase, ListVulnsUseCase, RematchVulnsUseCase, SetVulnStatusUseCase } from '../../application/vuln/vuln.use-cases.js';
import { InventoryController } from '../../infrastructure/http/controllers/inventory.controller.js';
import { VulnController } from '../../infrastructure/http/controllers/vuln.controller.js';
import { InventoryRouter } from '../../infrastructure/http/routers/inventory.router.js';
import { VulnRouter } from '../../infrastructure/http/routers/vuln.router.js';
import { AuthMiddleware } from '../../infrastructure/http/middleware/auth.middleware.js';
import { AuditController } from '../../infrastructure/http/controllers/audit.controller.js';
import { AuthController } from '../../infrastructure/http/controllers/auth.controller.js';
import { CveController } from '../../infrastructure/http/controllers/cve.controller.js';
import { RoleController } from '../../infrastructure/http/controllers/role.controller.js';
import { SyncController } from '../../infrastructure/http/controllers/sync.controller.js';
import { UserController } from '../../infrastructure/http/controllers/user.controller.js';
import { CompanyRepository } from '../../infrastructure/database/repositories/company.repository.js';
import { CompanyUseCases } from '../../application/company/company.use-cases.js';
import { CompanyController } from '../../infrastructure/http/controllers/company.controller.js';
import { CompanyRouter } from '../../infrastructure/http/routers/company.router.js';
import { AuditRouter } from '../../infrastructure/http/routers/audit.router.js';
import { AuthRouter } from '../../infrastructure/http/routers/auth.router.js';
import { CveRouter } from '../../infrastructure/http/routers/cve.router.js';
import { RoleRouter } from '../../infrastructure/http/routers/role.router.js';
import { SyncRouter } from '../../infrastructure/http/routers/sync.router.js';
import { UserRouter } from '../../infrastructure/http/routers/user.router.js';

export interface BuiltContainer {
  container: Container;
  shutdown: () => Promise<void>;
}

/** Single place where every token is bound to its implementation. */
export function buildContainer(): BuiltContainer {
  const container = new Container({ defaultScope: 'Singleton' });
  const config = new EnvConfig();
  const logger = createLogger(config);
  const { db, pool } = createDatabase(config.DATABASE_URL);

  container.bind(TYPES.EnvConfig).toConstantValue(config);
  container.bind(TYPES.ILogger).toConstantValue(logger);
  container.bind(TYPES.DrizzleDatabase).toConstantValue(db);
  container.bind(TYPES.IPasswordHasher).to(Argon2PasswordHasher);
  container.bind(TYPES.ITokenService).to(JwtTokenService);

  container.bind(TYPES.IUserRepository).to(UserRepository);
  container.bind(TYPES.IRoleRepository).to(RoleRepository);
  container.bind(TYPES.IPermissionRepository).to(PermissionRepository);
  container.bind(TYPES.IRefreshTokenRepository).to(RefreshTokenRepository);
  container.bind(TYPES.IAuthTokenRepository).to(AuthTokenRepository);
  container.bind(TYPES.IAuditRepository).to(AuditRepository);
  container.bind(TYPES.ICveRepository).to(CveRepository);
  container.bind(TYPES.ISyncStateRepository).to(SyncStateRepository);
  container.bind(TYPES.ISyncJobQueue).to(BullMqSyncJobQueue);
  container.bind(TYPES.IAssetRepository).to(AssetRepository);
  container.bind(TYPES.IVulnRepository).to(VulnRepository);
  container.bind(TYPES.IAlertRepository).to(AlertRepository);
  container.bind(TYPES.IIntelRepository).to(IntelRepository);
  container.bind(TYPES.IReportRepository).to(ReportRepository);
  container.bind(TYPES.ICompanyRepository).to(CompanyRepository);
  container.bind(TYPES.IChannelDispatcher).to(ChannelDispatcher);

  container.bind(TYPES.EffectivePermissionService).to(EffectivePermissionService);
  container.bind(TYPES.CatalogBootstrapService).to(CatalogBootstrapService);
  container.bind(TYPES.AuditService).to(AuditService);
  container.bind(TYPES.SessionService).to(SessionService);
  container.bind(TYPES.ProductCatalogService).to(ProductCatalogService);
  container.bind(TYPES.MatchAssetsService).to(MatchAssetsService);
  container.bind(TYPES.AlertEvaluatorService).to(AlertEvaluatorService);
  container.bind(TYPES.AlertUseCases).to(AlertUseCases);
  container.bind(TYPES.IntelUseCases).to(IntelUseCases);
  container.bind(TYPES.ReportService).to(ReportService);
  container.bind(TYPES.ReportUseCases).to(ReportUseCases);

  container.bind(TYPES.LoginUseCase).to(LoginUseCase);
  container.bind(TYPES.RefreshSessionUseCase).to(RefreshSessionUseCase);
  container.bind(TYPES.LogoutUseCase).to(LogoutUseCase);
  container.bind(TYPES.GetMeUseCase).to(GetMeUseCase);
  container.bind(TYPES.ChangePasswordUseCase).to(ChangePasswordUseCase);
  container.bind(TYPES.GetAuthTokenInfoUseCase).to(GetAuthTokenInfoUseCase);
  container.bind(TYPES.RegisterWithInviteUseCase).to(RegisterWithInviteUseCase);
  container.bind(TYPES.ResetPasswordUseCase).to(ResetPasswordUseCase);

  container.bind(TYPES.ListUsersUseCase).to(ListUsersUseCase);
  container.bind(TYPES.GetUserUseCase).to(GetUserUseCase);
  container.bind(TYPES.InviteUserUseCase).to(InviteUserUseCase);
  container.bind(TYPES.CreateUserUseCase).to(CreateUserUseCase);
  container.bind(TYPES.UpdateUserUseCase).to(UpdateUserUseCase);
  container.bind(TYPES.DeleteUserUseCase).to(DeleteUserUseCase);
  container.bind(TYPES.SetUserPermissionOverridesUseCase).to(SetUserPermissionOverridesUseCase);
  container.bind(TYPES.GetUserEffectivePermissionsUseCase).to(GetUserEffectivePermissionsUseCase);
  container.bind(TYPES.IssuePasswordResetUseCase).to(IssuePasswordResetUseCase);
  container.bind(TYPES.RevokeUserSessionsUseCase).to(RevokeUserSessionsUseCase);
  container.bind(TYPES.ListUserSessionsUseCase).to(ListUserSessionsUseCase);
  container.bind(TYPES.RevokeUserSessionUseCase).to(RevokeUserSessionUseCase);

  container.bind(TYPES.ListRolesUseCase).to(ListRolesUseCase);
  container.bind(TYPES.GetRoleUseCase).to(GetRoleUseCase);
  container.bind(TYPES.CreateRoleUseCase).to(CreateRoleUseCase);
  container.bind(TYPES.UpdateRoleUseCase).to(UpdateRoleUseCase);
  container.bind(TYPES.DeleteRoleUseCase).to(DeleteRoleUseCase);
  container.bind(TYPES.ListPermissionsUseCase).to(ListPermissionsUseCase);
  container.bind(TYPES.ListAuditLogUseCase).to(ListAuditLogUseCase);

  container.bind(TYPES.SearchCvesUseCase).to(SearchCvesUseCase);
  container.bind(TYPES.GetCveUseCase).to(GetCveUseCase);
  container.bind(TYPES.GetCveStatsUseCase).to(GetCveStatsUseCase);
  container.bind(TYPES.GetSyncStatusUseCase).to(GetSyncStatusUseCase);
  container.bind(TYPES.RequestSyncUseCase).to(RequestSyncUseCase);

  container.bind(TYPES.ListAssetsUseCase).to(ListAssetsUseCase);
  container.bind(TYPES.GetAssetUseCase).to(GetAssetUseCase);
  container.bind(TYPES.CreateAssetUseCase).to(CreateAssetUseCase);
  container.bind(TYPES.UpdateAssetUseCase).to(UpdateAssetUseCase);
  container.bind(TYPES.DeleteAssetUseCase).to(DeleteAssetUseCase);
  container.bind(TYPES.ImportAssetsUseCase).to(ImportAssetsUseCase);
  container.bind(TYPES.ListImportsUseCase).to(ListImportsUseCase);
  container.bind(TYPES.CheckSoftwareUseCase).to(CheckSoftwareUseCase);
  container.bind(TYPES.SoftwareCatalogUseCases).to(SoftwareCatalogUseCases);
  container.bind(TYPES.ListVulnsUseCase).to(ListVulnsUseCase);
  container.bind(TYPES.ListCveAssetsUseCase).to(ListCveAssetsUseCase);
  container.bind(TYPES.SetVulnStatusUseCase).to(SetVulnStatusUseCase);
  container.bind(TYPES.RematchVulnsUseCase).to(RematchVulnsUseCase);

  container.bind(TYPES.CompanyUseCases).to(CompanyUseCases);
  container.bind(TYPES.CompanyController).to(CompanyController);
  container.bind(TYPES.CompanyRouter).to(CompanyRouter);
  container.bind(TYPES.AuthMiddleware).to(AuthMiddleware);
  container.bind(TYPES.AuthController).to(AuthController);
  container.bind(TYPES.AuthRouter).to(AuthRouter);
  container.bind(TYPES.UserController).to(UserController);
  container.bind(TYPES.UserRouter).to(UserRouter);
  container.bind(TYPES.RoleController).to(RoleController);
  container.bind(TYPES.RoleRouter).to(RoleRouter);
  container.bind(TYPES.AuditController).to(AuditController);
  container.bind(TYPES.AuditRouter).to(AuditRouter);
  container.bind(TYPES.CveController).to(CveController);
  container.bind(TYPES.CveRouter).to(CveRouter);
  container.bind(TYPES.InventoryController).to(InventoryController);
  container.bind(TYPES.InventoryRouter).to(InventoryRouter);
  container.bind(TYPES.VulnController).to(VulnController);
  container.bind(TYPES.VulnRouter).to(VulnRouter);
  container.bind(TYPES.AlertController).to(AlertController);
  container.bind(TYPES.AlertRouter).to(AlertRouter);
  container.bind(TYPES.IntelController).to(IntelController);
  container.bind(TYPES.IntelRouter).to(IntelRouter);
  container.bind(TYPES.ReportController).to(ReportController);
  container.bind(TYPES.ReportRouter).to(ReportRouter);
  container.bind(TYPES.SyncController).to(SyncController);
  container.bind(TYPES.SyncRouter).to(SyncRouter);

  return {
    container,
    shutdown: async () => {
      await container.get<ISyncJobQueue>(TYPES.ISyncJobQueue).close();
      await pool.end();
    },
  };
}
