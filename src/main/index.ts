import 'dotenv/config';
import 'reflect-metadata';
import { TYPES } from '../shared/tokens.js';
import type { EnvConfig } from '../infrastructure/common/env.config.js';
import type { ILogger } from '../application/ports/ports.js';
import type { CatalogBootstrapService } from '../application/rbac/services/catalog-bootstrap.service.js';
import { runMigrations } from '../infrastructure/database/migrate.runner.js';
import type { AlertEvaluatorService } from '../application/alerts/alert-evaluator.service.js';
import type { ReportService } from '../application/report/report.service.js';
import { buildContainer } from './container/build.js';
import { createApp } from './app.js';

async function main(): Promise<void> {
  const { container, shutdown } = buildContainer();
  const config = container.get<EnvConfig>(TYPES.EnvConfig);
  const logger = container.get<ILogger>(TYPES.ILogger);

  await runMigrations(config.DATABASE_URL);
  await container.get<CatalogBootstrapService>(TYPES.CatalogBootstrapService).run();

  const server = createApp(container).listen(config.PORT, () => logger.info({ port: config.PORT }, 'cti-api listening'));

  // Alert rules and report schedules look at what changed since they last ran; a pass a minute is plenty for hourly/daily feeds.
  let evaluating = false;
  const alertTimer = setInterval(() => {
    if (evaluating) return;
    evaluating = true;
    const logTickError = (err: unknown) => logger.error({ err }, 'background tick failed');
    Promise.all([
      container.get<AlertEvaluatorService>(TYPES.AlertEvaluatorService).tick().catch(logTickError),
      container.get<ReportService>(TYPES.ReportService).tick().catch(logTickError),
    ]).finally(() => (evaluating = false));
  }, 60_000);
  alertTimer.unref();

  const stop = () => {
    clearInterval(alertTimer);
    server.close(() => void shutdown().then(() => process.exit(0)));
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
