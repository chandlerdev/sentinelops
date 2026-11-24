-- Phase 4 of the logic-testing engine (E/J: checkout, coupon, business logic). One request shape, replayed
-- three ways: as-is, tampered on one field, and sent N times at once. Generalizes several of your checklist
-- IDs (ECOM-02/03/04 parameter tampering, ECOM-05/09 duplicate/reuse, BUS-03/07 coupon abuse / race
-- conditions) into one reusable probe, since every target's actual checkout API is different.

CREATE TABLE business_logic_probe (
    id             VARCHAR(36)  NOT NULL PRIMARY KEY,
    target_id      VARCHAR(36)  NOT NULL,
    label          VARCHAR(64)  NOT NULL,
    request_url    VARCHAR(512) NOT NULL,
    http_method    VARCHAR(8)   NOT NULL DEFAULT 'POST',
    body_template  TEXT         NOT NULL,
    tampered_field VARCHAR(128) NULL,
    tampered_value VARCHAR(512) NULL,
    concurrency    INT          NOT NULL DEFAULT 5,
    identity_id    VARCHAR(36)  NULL,
    created_by     VARCHAR(255) NOT NULL,
    created_at     DATETIME(6)  NOT NULL,
    CONSTRAINT fk_business_logic_probe_target   FOREIGN KEY (target_id)   REFERENCES target(id)       ON DELETE CASCADE,
    CONSTRAINT fk_business_logic_probe_identity FOREIGN KEY (identity_id) REFERENCES test_identity(id) ON DELETE CASCADE
);

CREATE INDEX idx_business_logic_probe_target ON business_logic_probe (target_id);
