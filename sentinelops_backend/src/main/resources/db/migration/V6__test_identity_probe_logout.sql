-- Phase 1 (auth/session module): two more optional endpoints per test identity, so the engine can tell
-- whether a session is still authenticated (probe_url) and can trigger a logout (logout_url).

ALTER TABLE test_identity
    ADD COLUMN probe_url     VARCHAR(512) NULL,
    ADD COLUMN logout_url    VARCHAR(512) NULL,
    ADD COLUMN logout_method VARCHAR(8)   NOT NULL DEFAULT 'POST';
