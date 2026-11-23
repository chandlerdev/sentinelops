-- Phase 1: targets, ownership verification, scoped authorizations, global settings.
-- Portable between MariaDB 10.4 and MySQL 8.0 (plain ALTER/CREATE only).

ALTER TABLE app_user ADD COLUMN client_id VARCHAR(36) NULL;
ALTER TABLE app_user ADD COLUMN active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE app_user ADD CONSTRAINT fk_user_client FOREIGN KEY (client_id) REFERENCES client(id);

CREATE TABLE target (
    id                      VARCHAR(36)  PRIMARY KEY,
    engagement_id           VARCHAR(36)  NOT NULL,
    kind                    VARCHAR(16)  NOT NULL,
    target_value            VARCHAR(255) NOT NULL,
    base_url                VARCHAR(512),
    label                   VARCHAR(255),
    technology              VARCHAR(16),
    lab                     BOOLEAN      NOT NULL DEFAULT FALSE,
    verification_status     VARCHAR(16)  NOT NULL DEFAULT 'UNVERIFIED',
    verified_at             DATETIME NULL,
    verification_expires_at DATETIME NULL,
    created_by              VARCHAR(255) NOT NULL,
    created_at              DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_target_eng_value UNIQUE (engagement_id, target_value),
    CONSTRAINT fk_target_engagement FOREIGN KEY (engagement_id) REFERENCES engagement(id)
) ENGINE=InnoDB;

CREATE TABLE target_verification (
    id               VARCHAR(36)  PRIMARY KEY,
    target_id        VARCHAR(36)  NOT NULL,
    method           VARCHAR(16)  NOT NULL,
    token            VARCHAR(64),
    status           VARCHAR(16)  NOT NULL DEFAULT 'PENDING',
    expires_at       DATETIME     NOT NULL,
    verified_at      DATETIME NULL,
    last_checked_at  DATETIME NULL,
    detail           VARCHAR(512),
    approver_name    VARCHAR(255),
    approver_contact VARCHAR(255),
    network_ack_by   VARCHAR(255),
    network_ack_at   DATETIME NULL,
    evidence_ref     VARCHAR(512),
    created_by       VARCHAR(255) NOT NULL,
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_verification_target FOREIGN KEY (target_id) REFERENCES target(id)
) ENGINE=InnoDB;

-- Authorizations are now per engagement and cover a set of targets (not one technology).
ALTER TABLE authorization_record DROP INDEX uq_auth_eng_tech;
ALTER TABLE authorization_record MODIFY technology VARCHAR(16) NULL;
ALTER TABLE authorization_record MODIFY scope_hosts TEXT NULL;
ALTER TABLE authorization_record MODIFY status VARCHAR(20) NOT NULL DEFAULT 'DRAFT';
ALTER TABLE authorization_record ADD COLUMN title             VARCHAR(255) NULL;
ALTER TABLE authorization_record ADD COLUMN requested_by      VARCHAR(255) NULL;
ALTER TABLE authorization_record ADD COLUMN approver_name     VARCHAR(255) NULL;
ALTER TABLE authorization_record ADD COLUMN approver_contact  VARCHAR(255) NULL;
ALTER TABLE authorization_record ADD COLUMN emergency_contact VARCHAR(255) NULL;
ALTER TABLE authorization_record ADD COLUMN permitted_methods VARCHAR(255) NULL;
ALTER TABLE authorization_record ADD COLUMN excluded_assets   TEXT NULL;
ALTER TABLE authorization_record ADD COLUMN approved_by       VARCHAR(255) NULL;
ALTER TABLE authorization_record ADD COLUMN approved_at       DATETIME NULL;
ALTER TABLE authorization_record ADD COLUMN decision_note     VARCHAR(1024) NULL;
ALTER TABLE authorization_record ADD COLUMN created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;

CREATE TABLE authorization_scope (
    authorization_id VARCHAR(36) NOT NULL,
    target_id        VARCHAR(36) NOT NULL,
    PRIMARY KEY (authorization_id, target_id),
    CONSTRAINT fk_scope_auth   FOREIGN KEY (authorization_id) REFERENCES authorization_record(id),
    CONSTRAINT fk_scope_target FOREIGN KEY (target_id) REFERENCES target(id)
) ENGINE=InnoDB;

-- Scan runs and findings now hang off a target; the old technology column becomes optional.
ALTER TABLE scan_run MODIFY technology VARCHAR(16) NULL;
ALTER TABLE scan_run ADD COLUMN target_id VARCHAR(36) NULL;
ALTER TABLE scan_run ADD COLUMN category VARCHAR(16) NULL;
ALTER TABLE scan_run ADD COLUMN resolved_addresses VARCHAR(512) NULL;
ALTER TABLE scan_run ADD CONSTRAINT fk_scan_target FOREIGN KEY (target_id) REFERENCES target(id);
ALTER TABLE finding MODIFY technology VARCHAR(16) NULL;

CREATE TABLE system_setting (
    setting_key   VARCHAR(100) PRIMARY KEY,
    setting_value VARCHAR(512) NOT NULL,
    updated_by    VARCHAR(255),
    updated_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
INSERT INTO system_setting (setting_key, setting_value) VALUES ('active_scanning_enabled', 'false');

CREATE INDEX idx_target_engagement ON target(engagement_id);
CREATE INDEX idx_verification_target ON target_verification(target_id);
CREATE INDEX idx_audit_created ON audit_log(created_at);
