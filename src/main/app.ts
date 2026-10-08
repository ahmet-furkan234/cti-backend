import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { type Express } from 'express';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import type { Container } from 'inversify';
import { TYPES } from '../shared/tokens.js';
import type { EnvConfig } from '../infrastructure/common/env.config.js';
import type { Database } from '../infrastructure/database/client.js';
import type { ISyncJobQueue } from '../application/ports/ports.js';
import { errorHandler } from '../infrastructure/http/middleware/error-handler.middleware.js';
import type { AuditRouter } from '../infrastructure/http/routers/audit.router.js';
import type { AuthRouter } from '../infrastructure/http/routers/auth.router.js';
import type { CompanyRouter } from '../infrastructure/http/routers/company.router.js';
import type { CveRouter } from '../infrastructure/http/routers/cve.router.js';
import type { InventoryRouter } from '../infrastructure/http/routers/inventory.router.js';
import type { VulnRouter } from '../infrastructure/http/routers/vuln.router.js';
import type { AlertRouter } from '../infrastructure/http/routers/alert.router.js';
import type { IntelRouter } from '../infrastructure/http/routers/intel.router.js';
import type { ReportRouter } from '../infrastructure/http/routers/report.router.js';
import type { RoleRouter } from '../infrastructure/http/routers/role.router.js';
import type { SyncRouter } from '../infrastructure/http/routers/sync.router.js';
import type { UserRouter } from '../infrastructure/http/routers/user.router.js';
import { sql } from 'drizzle-orm';
import { Errors, errorBody } from '../shared/strings.js';

export function createApp(container: Container): Express {
  const config = container.get<EnvConfig>(TYPES.EnvConfig);
  const logger = container.get<{ raw: import('pino').Logger }>(TYPES.ILogger);
  const db = container.get<Database>(TYPES.DrizzleDatabase);
  const app = express();

  app.set('trust proxy', config.TRUST_PROXY);
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(pinoHttp({ logger: logger.raw, autoLogging: { ignore: (req) => req.url === '/health' } }));
  app.use(
    cors({
      origin: (origin, cb) => cb(null, !origin || config.ALLOWED_ORIGINS.includes(origin)),
      credentials: true,
    }),
  );
  app.use(express.json({ limit: '1mb' }));
  app.use(cookieParser());

  app.get('/health', (_req, res) => void res.json({ status: 'ok' }));
  app.get('/ready', async (_req, res) => {
    const queue = container.get<ISyncJobQueue>(TYPES.ISyncJobQueue);
    const [database, redis] = await Promise.all([
      db.execute(sql`select 1`).then(() => true, () => false),
      queue.ping(),
    ]);
    // The API works without Redis except for queueing sync requests, so it stays "ready" but says so.
    res.status(database ? 200 : 503).json({ status: database ? 'ready' : 'db_unavailable', database, queue: redis });
  });

  const v1 = express.Router();
  v1.use('/auth', container.get<AuthRouter>(TYPES.AuthRouter).router);
  v1.use('/users', container.get<UserRouter>(TYPES.UserRouter).router);
  v1.use('/', container.get<RoleRouter>(TYPES.RoleRouter).router);
  v1.use('/companies', container.get<CompanyRouter>(TYPES.CompanyRouter).router);
  v1.use('/audit', container.get<AuditRouter>(TYPES.AuditRouter).router);
  v1.use('/cves', container.get<CveRouter>(TYPES.CveRouter).router);
  v1.use('/assets', container.get<InventoryRouter>(TYPES.InventoryRouter).router);
  v1.use('/vulns', container.get<VulnRouter>(TYPES.VulnRouter).router);
  v1.use('/alerts', container.get<AlertRouter>(TYPES.AlertRouter).router);
  v1.use('/intel', container.get<IntelRouter>(TYPES.IntelRouter).router);
  v1.use('/reports', container.get<ReportRouter>(TYPES.ReportRouter).router);
  v1.use('/sync', container.get<SyncRouter>(TYPES.SyncRouter).router);
  app.use('/api/v1', v1);

  app.use((_req, res) => void res.status(404).json(errorBody(Errors.routeNotFound)));
  app.use(errorHandler);
  return app;
}
