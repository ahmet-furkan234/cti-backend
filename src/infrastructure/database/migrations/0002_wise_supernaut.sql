ALTER TABLE "alert_log" ADD COLUMN "asset_id" uuid;--> statement-breakpoint
ALTER TABLE "alert_rules" ADD COLUMN "evaluated_at" timestamp with time zone DEFAULT now() NOT NULL;