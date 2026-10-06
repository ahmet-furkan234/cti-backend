import 'dotenv/config';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { resolve } from 'path';
import { createDatabase } from './client.js';
import { SQL } from './sql.js';

/** Extensions can't be expressed in the drizzle schema, so they're ensured before migrating. */
export async function runMigrations(url: string): Promise<void> {
  const { db, pool } = createDatabase(url);
  try {
    await pool.query(SQL.ensureTrigramExtension);
    await migrate(db, { migrationsFolder: resolve(import.meta.dirname, 'migrations') });
  } finally {
    await pool.end();
  }
}

if (process.argv[1] && import.meta.filename === process.argv[1]) {
  runMigrations(process.env['DATABASE_URL']!)
    .then(() => console.log('migrations applied'))
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}
