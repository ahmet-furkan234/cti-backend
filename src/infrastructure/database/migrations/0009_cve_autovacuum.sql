-- The sync worker rewrites thousands of cve rows per run. With the defaults (20% of the table) dead rows pile up
-- (hundreds of thousands seen), the table bloats and the planner works from stale statistics.
-- Storage parameters are not expressible in the drizzle schema, hence a custom migration.
ALTER TABLE "cve" SET (autovacuum_vacuum_scale_factor = 0.02, autovacuum_analyze_scale_factor = 0.02);
