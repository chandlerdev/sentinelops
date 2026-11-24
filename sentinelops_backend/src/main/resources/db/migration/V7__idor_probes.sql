-- Phase 2 of the logic-testing engine (D: authorization / IDOR). A probe pairs two stored test identities
-- with their OWN object id on one URL template, so the engine can try each identity's id with the other
-- identity's session and see whether the server checks ownership, not just "is someone logged in".

CREATE TABLE idor_probe (
    id               VARCHAR(36)  NOT NULL PRIMARY KEY,
    target_id        VARCHAR(36)  NOT NULL,
    label            VARCHAR(64)  NOT NULL,
    url_template     VARCHAR(512) NOT NULL,
    identity_a_id    VARCHAR(36)  NOT NULL,
    resource_id_a    VARCHAR(128) NOT NULL,
    identity_b_id    VARCHAR(36)  NOT NULL,
    resource_id_b    VARCHAR(128) NOT NULL,
    created_by       VARCHAR(255) NOT NULL,
    created_at       DATETIME(6)  NOT NULL,
    CONSTRAINT fk_idor_probe_target     FOREIGN KEY (target_id)     REFERENCES target(id)        ON DELETE CASCADE,
    CONSTRAINT fk_idor_probe_identity_a FOREIGN KEY (identity_a_id) REFERENCES test_identity(id)  ON DELETE CASCADE,
    CONSTRAINT fk_idor_probe_identity_b FOREIGN KEY (identity_b_id) REFERENCES test_identity(id)  ON DELETE CASCADE
);

CREATE INDEX idx_idor_probe_target ON idor_probe (target_id);
