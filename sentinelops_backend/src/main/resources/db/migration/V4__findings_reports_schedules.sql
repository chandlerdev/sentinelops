-- Phases 3-5: finding workflow, retests, authenticated scans, OpenAPI import, schedules.

ALTER TABLE finding
    ADD COLUMN validated    BOOLEAN      NOT NULL DEFAULT FALSE,
    ADD COLUMN validated_by VARCHAR(255) NULL,
    ADD COLUMN validated_at DATETIME     NULL,
    ADD COLUMN found_mode   VARCHAR(16)  NULL,
    ADD COLUMN fix_notes    TEXT         NULL,
    ADD COLUMN fixed_at     DATETIME     NULL;

ALTER TABLE retest
    ADD COLUMN scan_run_id VARCHAR(36) NULL;

ALTER TABLE scan_run
    ADD COLUMN purpose VARCHAR(16) NOT NULL DEFAULT 'SCAN';

ALTER TABLE target
    ADD COLUMN openapi_url VARCHAR(512) NULL;

ALTER TABLE authorization_record
    ADD COLUMN allow_authenticated BOOLEAN NOT NULL DEFAULT FALSE;

-- One stored header (e.g. Authorization: Bearer ...) per target for authenticated scans. Value is encrypted (AES-GCM).
CREATE TABLE target_credential (
    target_id   VARCHAR(36)  PRIMARY KEY,
    header_name VARCHAR(64)  NOT NULL,
    enc_value   TEXT         NOT NULL,
    created_by  VARCHAR(255) NOT NULL,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_cred_target FOREIGN KEY (target_id) REFERENCES target(id)
) ENGINE=InnoDB;

CREATE TABLE scan_schedule (
    id               VARCHAR(36)  PRIMARY KEY,
    engagement_id    VARCHAR(36)  NOT NULL,
    target_id        VARCHAR(36)  NOT NULL,
    category         VARCHAR(16)  NOT NULL,
    mode             VARCHAR(16)  NOT NULL DEFAULT 'PASSIVE',
    interval_days    INT          NOT NULL,
    next_run_at      DATETIME     NOT NULL,
    enabled          BOOLEAN      NOT NULL DEFAULT TRUE,
    denied_in_a_row  INT          NOT NULL DEFAULT 0,
    last_result      VARCHAR(512) NULL,
    created_by       VARCHAR(255) NOT NULL,
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_sched_engagement FOREIGN KEY (engagement_id) REFERENCES engagement(id),
    CONSTRAINT fk_sched_target FOREIGN KEY (target_id) REFERENCES target(id)
) ENGINE=InnoDB;

CREATE INDEX idx_sched_due ON scan_schedule(enabled, next_run_at);
CREATE INDEX idx_finding_target ON finding(target_id, tool);
