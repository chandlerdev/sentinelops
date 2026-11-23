-- SentinelOps schema (MySQL 8). Owned by Flyway; Hibernate only validates.
CREATE TABLE app_user (
    id          VARCHAR(36)  PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    email       VARCHAR(255) NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,
    role        VARCHAR(20)  NOT NULL,
    org         VARCHAR(255),
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE client (
    id          VARCHAR(36)  PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    contact     VARCHAR(255) NOT NULL,
    tier        VARCHAR(64),
    compliance  VARCHAR(255),
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE engagement (
    id            VARCHAR(36)  PRIMARY KEY,
    name          VARCHAR(255) NOT NULL,
    state         VARCHAR(32)  NOT NULL DEFAULT 'NEW',
    environment   VARCHAR(64),
    window_start  DATETIME,
    window_end    DATETIME,
    client_id     VARCHAR(36)  NOT NULL,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_engagement_client FOREIGN KEY (client_id) REFERENCES client(id)
) ENGINE=InnoDB;

CREATE TABLE authorization_record (
    id            VARCHAR(36)  PRIMARY KEY,
    engagement_id VARCHAR(36)  NOT NULL,
    technology    VARCHAR(16)  NOT NULL,
    scope_hosts   TEXT         NOT NULL,
    window_start  DATETIME,
    window_end    DATETIME,
    status        VARCHAR(16)  NOT NULL DEFAULT 'DRAFT',
    signed_by     VARCHAR(255),
    signed_at     DATETIME,
    expires_at    DATETIME,
    allow_active  BOOLEAN      NOT NULL DEFAULT FALSE,
    roe_reference VARCHAR(255),
    CONSTRAINT uq_auth_eng_tech UNIQUE (engagement_id, technology),
    CONSTRAINT fk_auth_engagement FOREIGN KEY (engagement_id) REFERENCES engagement(id)
) ENGINE=InnoDB;

CREATE TABLE scan_run (
    id               VARCHAR(36)  PRIMARY KEY,
    engagement_id    VARCHAR(36)  NOT NULL,
    authorization_id VARCHAR(36)  NOT NULL,
    technology       VARCHAR(16)  NOT NULL,
    target_host      VARCHAR(255) NOT NULL,
    mode             VARCHAR(16)  NOT NULL DEFAULT 'PASSIVE',
    status           VARCHAR(16)  NOT NULL DEFAULT 'QUEUED',
    tool             VARCHAR(64),
    started_at       DATETIME,
    ended_at         DATETIME,
    evidence_uri     VARCHAR(512),
    error            VARCHAR(1024),
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scan_engagement FOREIGN KEY (engagement_id) REFERENCES engagement(id),
    CONSTRAINT fk_scan_auth FOREIGN KEY (authorization_id) REFERENCES authorization_record(id)
) ENGINE=InnoDB;

CREATE TABLE finding (
    id            VARCHAR(36)  PRIMARY KEY,
    engagement_id VARCHAR(36)  NOT NULL,
    scan_run_id   VARCHAR(36),
    task_id       VARCHAR(64),
    technology    VARCHAR(16)  NOT NULL,
    title         VARCHAR(512) NOT NULL,
    severity      VARCHAR(16)  NOT NULL,
    cvss_vector   VARCHAR(128),
    cvss_score    DOUBLE,
    status        VARCHAR(20)  NOT NULL DEFAULT 'OPEN',
    evidence_ref  VARCHAR(512),
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_finding_engagement FOREIGN KEY (engagement_id) REFERENCES engagement(id),
    CONSTRAINT fk_finding_scan FOREIGN KEY (scan_run_id) REFERENCES scan_run(id)
) ENGINE=InnoDB;

CREATE TABLE retest (
    id         VARCHAR(36)  PRIMARY KEY,
    finding_id VARCHAR(36)  NOT NULL,
    result     VARCHAR(20)  NOT NULL,
    tested_by  VARCHAR(255),
    tested_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    notes      VARCHAR(1024),
    CONSTRAINT fk_retest_finding FOREIGN KEY (finding_id) REFERENCES finding(id)
) ENGINE=InnoDB;

CREATE TABLE audit_log (
    id         VARCHAR(36)  PRIMARY KEY,
    actor      VARCHAR(255) NOT NULL,
    action     VARCHAR(128) NOT NULL,
    entity     VARCHAR(64)  NOT NULL,
    entity_id  VARCHAR(36),
    detail     TEXT,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE INDEX idx_engagement_client ON engagement(client_id);
CREATE INDEX idx_auth_engagement ON authorization_record(engagement_id);
CREATE INDEX idx_scan_engagement ON scan_run(engagement_id);
CREATE INDEX idx_finding_engagement ON finding(engagement_id);
CREATE INDEX idx_audit_entity ON audit_log(entity, entity_id);
