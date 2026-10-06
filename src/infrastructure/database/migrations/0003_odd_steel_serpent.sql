DROP INDEX "iocs_value_idx";--> statement-breakpoint
ALTER TABLE "report_runs" ADD COLUMN "schedule_id" uuid;--> statement-breakpoint
CREATE UNIQUE INDEX "iocs_uq" ON "iocs" USING btree ("type","value");