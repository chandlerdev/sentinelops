-- Phase 6 of the logic-testing engine (L: dependency / SCA scanning). Unlike every other check, this one
-- scans a MANIFEST FILE you upload (package-lock.json), not a live target - it never sends anything to the
-- target's own infrastructure, only to the public npm registry's advisory data, so it needs no scan gate.

CREATE TABLE dependency_manifest (
    id                VARCHAR(36)   NOT NULL PRIMARY KEY,
    target_id         VARCHAR(36)   NOT NULL,
    label             VARCHAR(64)   NOT NULL,
    ecosystem         VARCHAR(16)   NOT NULL DEFAULT 'NPM',
    manifest_content  MEDIUMTEXT    NOT NULL,
    created_by        VARCHAR(255)  NOT NULL,
    created_at        DATETIME(6)   NOT NULL,
    CONSTRAINT fk_dependency_manifest_target FOREIGN KEY (target_id) REFERENCES target(id) ON DELETE CASCADE
);

CREATE INDEX idx_dependency_manifest_target ON dependency_manifest (target_id);
