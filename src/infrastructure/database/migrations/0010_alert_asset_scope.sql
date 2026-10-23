ALTER TABLE alert_rules ADD COLUMN asset_ids uuid[] NOT NULL DEFAULT '{}'::uuid[];
