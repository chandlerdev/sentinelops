package com.sentinelops.entity;

import jakarta.persistence.*;

import java.time.Instant;

/** A domain, IP address or CIDR range registered in an engagement. Never scanned until verified and authorized. */
@Entity
@Table(name = "target")
public class Target {
    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "engagement_id", nullable = false, length = 36)
    private String engagementId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private TargetKind kind;

    /** Normalized hostname, IP literal or CIDR. */
    @Column(name = "target_value", nullable = false)
    private String value;

    @Column(name = "base_url", length = 512)
    private String baseUrl;

    private String label;

    /** OpenAPI / Swagger definition of the target's API (must be on the target's own host). */
    @Column(name = "openapi_url", length = 512)
    private String openApiUrl;

    @Enumerated(EnumType.STRING)
    @Column(length = 16)
    private Technology technology;

    /** Controlled-laboratory asset (e.g. our own Juice Shop). Only ADMIN can create one. */
    @Column(nullable = false)
    private boolean lab = false;

    /**
     * Explicitly authorized even though it resolves to this server itself (e.g. another of our own apps
     * sharing this box). Only ADMIN can set this. Ownership verification is still required as normal -
     * this only lifts the "this is our own server" address check, never a generic private/loopback/
     * link-local/metadata/reserved range.
     */
    @Column(name = "shared_host_exception", nullable = false)
    private boolean sharedHostException = false;

    @Enumerated(EnumType.STRING)
    @Column(name = "verification_status", nullable = false, length = 16)
    private TargetStatus verificationStatus = TargetStatus.UNVERIFIED;

    @Column(name = "verified_at")
    private Instant verifiedAt;

    @Column(name = "verification_expires_at")
    private Instant verificationExpiresAt;

    @Column(name = "created_by", nullable = false)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected Target() {}

    public Target(String id, String engagementId, TargetKind kind, String value, String createdBy) {
        this.id = id;
        this.engagementId = engagementId;
        this.kind = kind;
        this.value = value;
        this.createdBy = createdBy;
    }

    /** True only while the ownership verification is still within its validity period. */
    public boolean isVerifiedAt(Instant now) {
        return verificationStatus == TargetStatus.VERIFIED
                && verificationExpiresAt != null && verificationExpiresAt.isAfter(now);
    }

    /** Verified (and not expired) OR a lab asset (the lab allowlist is re-checked by the scope validator). */
    public boolean isOwnershipEstablishedAt(Instant now) {
        return lab || isVerifiedAt(now);
    }

    public String getId() { return id; }
    public String getEngagementId() { return engagementId; }
    public TargetKind getKind() { return kind; }
    public String getValue() { return value; }
    public String getBaseUrl() { return baseUrl; }
    public void setBaseUrl(String v) { this.baseUrl = v; }
    public String getOpenApiUrl() { return openApiUrl; }
    public void setOpenApiUrl(String v) { this.openApiUrl = v; }
    public String getLabel() { return label; }
    public void setLabel(String v) { this.label = v; }
    public Technology getTechnology() { return technology; }
    public void setTechnology(Technology v) { this.technology = v; }
    public boolean isLab() { return lab; }
    public void setLab(boolean v) { this.lab = v; }
    public boolean isSharedHostException() { return sharedHostException; }
    public void setSharedHostException(boolean v) { this.sharedHostException = v; }
    public TargetStatus getVerificationStatus() { return verificationStatus; }
    public void setVerificationStatus(TargetStatus v) { this.verificationStatus = v; }
    public Instant getVerifiedAt() { return verifiedAt; }
    public void setVerifiedAt(Instant v) { this.verifiedAt = v; }
    public Instant getVerificationExpiresAt() { return verificationExpiresAt; }
    public void setVerificationExpiresAt(Instant v) { this.verificationExpiresAt = v; }
    public String getCreatedBy() { return createdBy; }
    public Instant getCreatedAt() { return createdAt; }
}
