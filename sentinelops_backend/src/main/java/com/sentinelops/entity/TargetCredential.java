package com.sentinelops.entity;

import jakarta.persistence.*;
import java.time.Instant;

/** One encrypted request header (e.g. Authorization) used for authenticated scans of a target. */
@Entity
@Table(name = "target_credential")
public class TargetCredential {
    @Id
    @Column(name = "target_id", length = 36)
    private String targetId;

    @Column(name = "header_name", nullable = false, length = 64)
    private String headerName;

    @Column(name = "enc_value", nullable = false, columnDefinition = "TEXT")
    private String encValue;

    @Column(name = "created_by", nullable = false)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected TargetCredential() {}

    public TargetCredential(String targetId, String headerName, String encValue, String createdBy) {
        this.targetId = targetId;
        this.headerName = headerName;
        this.encValue = encValue;
        this.createdBy = createdBy;
    }

    public String getTargetId() { return targetId; }
    public String getHeaderName() { return headerName; }
    public String getEncValue() { return encValue; }
    public String getCreatedBy() { return createdBy; }
    public Instant getCreatedAt() { return createdAt; }
}
