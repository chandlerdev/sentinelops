-- Phase 2: scan engine. Findings carry enough detail to be fixed and re-tested; runs record how they ended.
ALTER TABLE scan_run
    ADD COLUMN work_dir      VARCHAR(255) NULL,
    ADD COLUMN exit_code     INT          NULL,
    ADD COLUMN finding_count INT          NOT NULL DEFAULT 0;

ALTER TABLE finding
    ADD COLUMN target_id     VARCHAR(36)   NULL,
    ADD COLUMN tool          VARCHAR(32)   NULL,
    ADD COLUMN rule_id       VARCHAR(255)  NULL,
    ADD COLUMN location      VARCHAR(1024) NULL,
    ADD COLUMN description   TEXT          NULL,
    ADD COLUMN remediation   TEXT          NULL,
    ADD COLUMN reference_ids VARCHAR(1024) NULL,
    ADD COLUMN fingerprint   VARCHAR(64)   NULL,
    ADD COLUMN last_seen_at  DATETIME      NULL;

CREATE INDEX idx_finding_fingerprint ON finding(engagement_id, fingerprint);
CREATE INDEX idx_scan_status ON scan_run(status, created_at);
