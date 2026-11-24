-- Phase 0 of the logic-testing engine: stored test accounts (2+ roles) per target, used by later phases
-- (auth/session abuse, IDOR, checkout abuse) to act as "User A" / "User B" against the target's own login.

CREATE TABLE test_identity (
    id              VARCHAR(36)  NOT NULL PRIMARY KEY,
    target_id       VARCHAR(36)  NOT NULL,
    label           VARCHAR(64)  NOT NULL,
    login_url       VARCHAR(512) NOT NULL,
    username_field  VARCHAR(64)  NOT NULL DEFAULT 'email',
    password_field  VARCHAR(64)  NOT NULL DEFAULT 'password',
    username        VARCHAR(255) NOT NULL,
    enc_password    TEXT         NOT NULL,
    token_path      VARCHAR(128) NULL,
    session_type    VARCHAR(16)  NOT NULL DEFAULT 'HEADER_BEARER',
    created_by      VARCHAR(255) NOT NULL,
    created_at      DATETIME(6)  NOT NULL,
    CONSTRAINT fk_test_identity_target FOREIGN KEY (target_id) REFERENCES target(id) ON DELETE CASCADE
);

CREATE INDEX idx_test_identity_target ON test_identity (target_id);
