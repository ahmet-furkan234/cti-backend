import 'dotenv/config';
import 'reflect-metadata';
import { TYPES } from '../../shared/tokens.js';
import type { EnvConfig } from '../common/env.config.js';
import type { IPasswordHasher } from '../../application/ports/ports.js';
import type { IRoleRepository } from '../../domain/rbac/role.repository.interface.js';
import type { ICompanyRepository } from '../../domain/company/company.repository.interface.js';
import type { IUserRepository } from '../../domain/user/user.repository.interface.js';
import type { CatalogBootstrapService } from '../../application/rbac/services/catalog-bootstrap.service.js';
import { User } from '../../domain/user/user.entity.js';
import { SUPER_ADMIN_ROLE } from '../../domain/rbac/permission-catalog.js';
import { buildContainer } from '../../main/container/build.js';
import { runMigrations } from './migrate.runner.js';

/** Idempotent: syncs the permission catalog + system roles and creates the first super admin if none exists. */
const { container, shutdown } = buildContainer();
const config = container.get<EnvConfig>(TYPES.EnvConfig);
await runMigrations(config.DATABASE_URL);
await container.get<CatalogBootstrapService>(TYPES.CatalogBootstrapService).run();

const users = container.get<IUserRepository>(TYPES.IUserRepository);
const platform = (await container.get<ICompanyRepository>(TYPES.ICompanyRepository).findPlatform())!;
const roles = container.get<IRoleRepository>(TYPES.IRoleRepository);
const superRole = (await roles.findByName(SUPER_ADMIN_ROLE))!;

if ((await roles.memberIds(superRole.id)).length > 0) {
  console.log('A super_admin already exists - nothing to do.');
} else if (!config.SEED_ADMIN_EMAIL || !config.SEED_ADMIN_PASSWORD) {
  console.error('Set SEED_ADMIN_EMAIL and SEED_ADMIN_PASSWORD (min 12 chars) to create the first admin.');
  process.exitCode = 1;
} else {
  const hasher = container.get<IPasswordHasher>(TYPES.IPasswordHasher);
  const admin = new User({
    companyId: platform.id,
    email: config.SEED_ADMIN_EMAIL,
    name: 'Super Admin',
    passwordHash: await hasher.hash(config.SEED_ADMIN_PASSWORD),
  });
  await users.create(admin);
  await users.replaceRoles(admin.id, [superRole.id]);
  console.log(`Created super_admin ${admin.email.value}`);
}
await shutdown();
