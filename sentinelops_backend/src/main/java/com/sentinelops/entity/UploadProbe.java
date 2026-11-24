package com.sentinelops.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Phase 3 of the logic-testing engine (H: file upload / extension bypass, FILE-06; see
 * PENTEST_COVERAGE_PLAN.md). Uploads a small, inert marker file under a dangerous extension and tries to
 * fetch it back at {@code retrievalUrlTemplate} (contains the placeholder "{filename}") to prove it was
 * really stored under that name, not just that the upload call returned a success status.
 */
@Entity
@Table(name = "upload_probe")
public class UploadProbe {
    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "target_id", nullable = false, length = 36)
    private String targetId;

    @Column(nullable = false, length = 64)
    private String label;

    @Column(name = "upload_url", nullable = false, length = 512)
    private String uploadUrl;

    @Column(name = "field_name", nullable = false, length = 64)
    private String fieldName = "file";

    @Column(name = "retrieval_url_template", nullable = false, length = 512)
    private String retrievalUrlTemplate;

    /** Optional: the test identity whose session uploads the file. Null = an anonymous (unauthenticated) upload. */
    @Column(name = "identity_id", length = 36)
    private String identityId;

    @Column(name = "created_by", nullable = false)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected UploadProbe() {}

    public UploadProbe(String id, String targetId, String label, String uploadUrl, String fieldName,
                       String retrievalUrlTemplate, String identityId, String createdBy) {
        this.id = id;
        this.targetId = targetId;
        this.label = label;
        this.uploadUrl = uploadUrl;
        this.fieldName = fieldName == null || fieldName.isBlank() ? "file" : fieldName;
        this.retrievalUrlTemplate = retrievalUrlTemplate;
        this.identityId = identityId;
        this.createdBy = createdBy;
    }

    public String getId() { return id; }
    public String getTargetId() { return targetId; }
    public String getLabel() { return label; }
    public String getUploadUrl() { return uploadUrl; }
    public String getFieldName() { return fieldName; }
    public String getRetrievalUrlTemplate() { return retrievalUrlTemplate; }
    public String getIdentityId() { return identityId; }
    public String getCreatedBy() { return createdBy; }
    public Instant getCreatedAt() { return createdAt; }
}
