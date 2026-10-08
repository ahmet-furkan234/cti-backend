CREATE TABLE "companies" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"is_platform" boolean DEFAULT false NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "roles" DROP CONSTRAINT "roles_name_unique";--> statement-breakpoint
DROP INDEX "assets_name_uq";--> statement-breakpoint
DROP INDEX "iocs_uq";--> statement-breakpoint
DROP INDEX "software_aliases_name_uq";--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "company_id" uuid;--> statement-breakpoint
ALTER TABLE "roles" ADD COLUMN "company_id" uuid;--> statement-breakpoint
ALTER TABLE "auth_tokens" ADD COLUMN "company_id" uuid;--> statement-breakpoint
ALTER TABLE "audit_log" ADD COLUMN "company_id" uuid;--> statement-breakpoint
ALTER TABLE "asset_imports" ADD COLUMN "company_id" uuid;--> statement-breakpoint
ALTER TABLE "assets" ADD COLUMN "company_id" uuid;--> statement-breakpoint
ALTER TABLE "alert_channels" ADD COLUMN "company_id" uuid;--> statement-breakpoint
ALTER TABLE "alert_log" ADD COLUMN "company_id" uuid;--> statement-breakpoint
ALTER TABLE "alert_rules" ADD COLUMN "company_id" uuid;--> statement-breakpoint
ALTER TABLE "iocs" ADD COLUMN "company_id" uuid;--> statement-breakpoint
ALTER TABLE "watchlists" ADD COLUMN "company_id" uuid;--> statement-breakpoint
ALTER TABLE "report_runs" ADD COLUMN "company_id" uuid;--> statement-breakpoint
ALTER TABLE "report_schedules" ADD COLUMN "company_id" uuid;--> statement-breakpoint
ALTER TABLE "software_aliases" ADD COLUMN "company_id" uuid;--> statement-breakpoint
-- Everything that exists today belongs to the main (platform) company.
INSERT INTO "companies" ("name", "is_platform") VALUES ('Platform', true);--> statement-breakpoint
UPDATE "users" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform");--> statement-breakpoint
ALTER TABLE "users" ALTER COLUMN "company_id" SET NOT NULL;--> statement-breakpoint
UPDATE "asset_imports" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform");--> statement-breakpoint
ALTER TABLE "asset_imports" ALTER COLUMN "company_id" SET NOT NULL;--> statement-breakpoint
UPDATE "assets" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform");--> statement-breakpoint
ALTER TABLE "assets" ALTER COLUMN "company_id" SET NOT NULL;--> statement-breakpoint
UPDATE "alert_channels" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform");--> statement-breakpoint
ALTER TABLE "alert_channels" ALTER COLUMN "company_id" SET NOT NULL;--> statement-breakpoint
UPDATE "alert_log" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform");--> statement-breakpoint
ALTER TABLE "alert_log" ALTER COLUMN "company_id" SET NOT NULL;--> statement-breakpoint
UPDATE "alert_rules" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform");--> statement-breakpoint
ALTER TABLE "alert_rules" ALTER COLUMN "company_id" SET NOT NULL;--> statement-breakpoint
UPDATE "iocs" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform");--> statement-breakpoint
ALTER TABLE "iocs" ALTER COLUMN "company_id" SET NOT NULL;--> statement-breakpoint
UPDATE "watchlists" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform");--> statement-breakpoint
ALTER TABLE "watchlists" ALTER COLUMN "company_id" SET NOT NULL;--> statement-breakpoint
UPDATE "report_runs" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform");--> statement-breakpoint
ALTER TABLE "report_runs" ALTER COLUMN "company_id" SET NOT NULL;--> statement-breakpoint
UPDATE "report_schedules" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform");--> statement-breakpoint
ALTER TABLE "report_schedules" ALTER COLUMN "company_id" SET NOT NULL;--> statement-breakpoint
UPDATE "software_aliases" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform");--> statement-breakpoint
ALTER TABLE "software_aliases" ALTER COLUMN "company_id" SET NOT NULL;--> statement-breakpoint
UPDATE "roles" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform") WHERE NOT "is_system";--> statement-breakpoint
UPDATE "audit_log" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform");--> statement-breakpoint
UPDATE "auth_tokens" SET "company_id" = (SELECT "id" FROM "companies" WHERE "is_platform") WHERE "purpose" = 'invite';--> statement-breakpoint
CREATE UNIQUE INDEX "companies_name_uq" ON "companies" USING btree (lower("name"));--> statement-breakpoint
CREATE UNIQUE INDEX "companies_one_platform_uq" ON "companies" USING btree ("is_platform") WHERE "companies"."is_platform";--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "roles" ADD CONSTRAINT "roles_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "auth_tokens" ADD CONSTRAINT "auth_tokens_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "asset_imports" ADD CONSTRAINT "asset_imports_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "assets" ADD CONSTRAINT "assets_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_channels" ADD CONSTRAINT "alert_channels_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_log" ADD CONSTRAINT "alert_log_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alert_rules" ADD CONSTRAINT "alert_rules_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "iocs" ADD CONSTRAINT "iocs_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "watchlists" ADD CONSTRAINT "watchlists_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_runs" ADD CONSTRAINT "report_runs_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_schedules" ADD CONSTRAINT "report_schedules_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "software_aliases" ADD CONSTRAINT "software_aliases_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "users_company_idx" ON "users" USING btree ("company_id");--> statement-breakpoint
CREATE UNIQUE INDEX "roles_scope_name_uq" ON "roles" USING btree (coalesce("company_id"::text, ''),"name");--> statement-breakpoint
CREATE INDEX "audit_company_idx" ON "audit_log" USING btree ("company_id","at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "assets_company_idx" ON "assets" USING btree ("company_id");--> statement-breakpoint
CREATE UNIQUE INDEX "assets_name_uq" ON "assets" USING btree ("company_id",lower("name"));--> statement-breakpoint
CREATE UNIQUE INDEX "iocs_uq" ON "iocs" USING btree ("company_id","type","value");--> statement-breakpoint
CREATE UNIQUE INDEX "software_aliases_name_uq" ON "software_aliases" USING btree ("company_id",lower("name"));