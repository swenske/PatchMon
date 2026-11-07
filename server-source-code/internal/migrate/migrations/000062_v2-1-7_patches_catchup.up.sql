-- 2-1-3_with-patches-1 databases stop at version 49 under the old fork
-- numbering (47 api tokens, 48 prometheus, 49 oidc trust), so golang-migrate
-- skips upstream 000048 and 000049 on them. Re-apply both; no-op elsewhere.

ALTER TABLE settings
    ADD COLUMN IF NOT EXISTS compliance_body_limit TEXT;

ALTER TABLE settings
    ADD COLUMN IF NOT EXISTS agent_ping_body_limit TEXT;

CREATE INDEX IF NOT EXISTS idx_hosts_machine_id ON hosts (machine_id);
