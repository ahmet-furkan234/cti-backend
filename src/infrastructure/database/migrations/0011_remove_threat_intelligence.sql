DROP TABLE IF EXISTS watchlists;
--> statement-breakpoint
DROP TABLE IF EXISTS iocs;
--> statement-breakpoint
DELETE FROM permissions WHERE key IN ('intel:read', 'intel:manage');
