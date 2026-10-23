CREATE INDEX "cve_kev_published_idx" ON "cve" USING btree ("published" DESC NULLS LAST,"id" DESC NULLS LAST) WHERE "cve"."is_kev";--> statement-breakpoint
CREATE INDEX "cve_kev_modified_idx" ON "cve" USING btree ("last_modified" DESC NULLS LAST,"id" DESC NULLS LAST) WHERE "cve"."is_kev";--> statement-breakpoint
CREATE INDEX "cve_kev_cvss_idx" ON "cve" USING btree ("cvss_score" DESC NULLS LAST,"id" DESC NULLS LAST) WHERE "cve"."is_kev";--> statement-breakpoint
CREATE INDEX "cve_kev_epss_idx" ON "cve" USING btree ("epss" DESC NULLS LAST,"id" DESC NULLS LAST) WHERE "cve"."is_kev";--> statement-breakpoint
CREATE INDEX "cve_severity_idx" ON "cve" USING btree ("cvss_severity");