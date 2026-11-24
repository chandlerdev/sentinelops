-- Phase 3 of the logic-testing engine (H: file/directory, FILE-06 extension/type bypass). Uploads a small,
-- inert marker file under a dangerous extension and, if accepted, tries to fetch it back at a configured
-- location to prove it was really stored with that extension - not just that the upload call returned 200.

CREATE TABLE upload_probe (
    id                     VARCHAR(36)  NOT NULL PRIMARY KEY,
    target_id              VARCHAR(36)  NOT NULL,
    label                  VARCHAR(64)  NOT NULL,
    upload_url             VARCHAR(512) NOT NULL,
    field_name             VARCHAR(64)  NOT NULL DEFAULT 'file',
    retrieval_url_template VARCHAR(512) NOT NULL,
    identity_id            VARCHAR(36)  NULL,
    created_by             VARCHAR(255) NOT NULL,
    created_at             DATETIME(6)  NOT NULL,
    CONSTRAINT fk_upload_probe_target   FOREIGN KEY (target_id)   REFERENCES target(id)       ON DELETE CASCADE,
    CONSTRAINT fk_upload_probe_identity FOREIGN KEY (identity_id) REFERENCES test_identity(id) ON DELETE CASCADE
);

CREATE INDEX idx_upload_probe_target ON upload_probe (target_id);
