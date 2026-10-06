CREATE TABLE "asset_imports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"source" text NOT NULL,
	"kind" text NOT NULL,
	"rows" integer DEFAULT 0 NOT NULL,
	"created" integer DEFAULT 0 NOT NULL,
	"updated" integer DEFAULT 0 NOT NULL,
	"skipped" integer DEFAULT 0 NOT NULL,
	"status" text DEFAULT 'healthy' NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "asset_software" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid NOT NULL,
	"vendor" text,
	"product" text NOT NULL,
	"version" text
);
--> statement-breakpoint
CREATE TABLE "assets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"type" text NOT NULL,
	"name" text NOT NULL,
	"addr" text,
	"os" text,
	"env" text DEFAULT 'prod' NOT NULL,
	"criticality" text DEFAULT 'medium' NOT NULL,
	"exposed" boolean DEFAULT false NOT NULL,
	"source" text DEFAULT 'manual' NOT NULL,
	"owner" text,
	"tags" text[] DEFAULT '{}'::text[] NOT NULL,
	"attrs" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"archived_at" timestamp with time zone,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "asset_vulns" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"asset_id" uuid NOT NULL,
	"cve_id" text NOT NULL,
	"component" text NOT NULL,
	"installed_version" text,
	"fixed_version" text,
	"status" text DEFAULT 'open' NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"status_changed_at" timestamp with time zone,
	"status_changed_by" uuid
);
--> statement-breakpoint
CREATE TABLE "alert_channels" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"kind" text NOT NULL,
	"name" text NOT NULL,
	"values" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"status" text DEFAULT 'healthy' NOT NULL,
	"problem" text,
	"last_test_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "alert_log" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"rule_id" uuid,
	"channel_ids" uuid[] DEFAULT '{}'::uuid[] NOT NULL,
	"result" text NOT NULL,
	"detail" text DEFAULT '' NOT NULL,
	"at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "alert_rules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"trigger" text NOT NULL,
	"envs" text[] DEFAULT '{}'::text[] NOT NULL,
	"min_risk" integer DEFAULT 0 NOT NULL,
	"exposed_only" boolean DEFAULT false NOT NULL,
	"tag" text DEFAULT '' NOT NULL,
	"channel_ids" uuid[] DEFAULT '{}'::uuid[] NOT NULL,
	"throttle" text DEFAULT 'every' NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"last_fired_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "iocs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"type" text NOT NULL,
	"value" text NOT NULL,
	"source" text DEFAULT 'Manual' NOT NULL,
	"confidence" integer DEFAULT 50 NOT NULL,
	"expires_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "watchlists" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"vendors" text[] DEFAULT '{}'::text[] NOT NULL,
	"products" text[] DEFAULT '{}'::text[] NOT NULL,
	"tag" text DEFAULT '' NOT NULL,
	"min_cvss" real DEFAULT 0 NOT NULL,
	"kev_only" boolean DEFAULT false NOT NULL,
	"min_epss" integer DEFAULT 0 NOT NULL,
	"channel_id" uuid,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "report_runs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"template" text NOT NULL,
	"scope" text,
	"formats" text[] DEFAULT '{csv}'::text[] NOT NULL,
	"status" text DEFAULT 'generating' NOT NULL,
	"manual" boolean DEFAULT false NOT NULL,
	"size_bytes" integer,
	"content" text,
	"error" text,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "report_schedules" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"template" text NOT NULL,
	"scope" text,
	"freq" text NOT NULL,
	"recipients" text[] DEFAULT '{}'::text[] NOT NULL,
	"formats" text[] DEFAULT '{csv}'::text[] NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "asset_software" ADD CONSTRAINT "asset_software_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "asset_vulns" ADD CONSTRAINT "asset_vulns_asset_id_assets_id_fk" FOREIGN KEY ("asset_id") REFERENCES "public"."assets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "asset_imports_at_idx" ON "asset_imports" USING btree ("created_at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "asset_software_asset_idx" ON "asset_software" USING btree ("asset_id");--> statement-breakpoint
CREATE UNIQUE INDEX "assets_name_uq" ON "assets" USING btree (lower("name"));--> statement-breakpoint
CREATE INDEX "assets_type_idx" ON "assets" USING btree ("type");--> statement-breakpoint
CREATE INDEX "assets_env_idx" ON "assets" USING btree ("env");--> statement-breakpoint
CREATE INDEX "assets_seen_idx" ON "assets" USING btree ("last_seen_at" DESC NULLS LAST);--> statement-breakpoint
CREATE UNIQUE INDEX "asset_vulns_uq" ON "asset_vulns" USING btree ("asset_id","cve_id","component");--> statement-breakpoint
CREATE INDEX "asset_vulns_cve_idx" ON "asset_vulns" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "asset_vulns_status_idx" ON "asset_vulns" USING btree ("status");--> statement-breakpoint
CREATE INDEX "alert_log_at_idx" ON "alert_log" USING btree ("at" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "iocs_type_idx" ON "iocs" USING btree ("type");--> statement-breakpoint
CREATE INDEX "iocs_value_idx" ON "iocs" USING btree ("value");--> statement-breakpoint
CREATE INDEX "report_runs_at_idx" ON "report_runs" USING btree ("created_at" DESC NULLS LAST);