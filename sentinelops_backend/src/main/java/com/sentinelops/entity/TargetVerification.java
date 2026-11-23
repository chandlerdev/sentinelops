package com.sentinelops.entity;

import jakarta.persistence.*;

import java.time.Instant;

/** One ownership-verification attempt (challenge) for a target. Tokens are time-limited. */
@Entity
@Table(name = "target_verification")
public class TargetVerification {
    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "target_id", nullable = false, length = 36)
    private String targetId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private VerificationMethod method;

    @Column(length = 64)
    private String token;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private ChallengeStatus status = ChallengeStatus.PENDING;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "verified_at")
    private Instant verifiedAt;

    @Column(name = "last_checked_at")
    private Instant lastCheckedAt;

    @Column(length = 512)
    private String detail;

    // Manual (IP / CIDR) approval record
    @Column(name = "approver_name") private String approverName;
    @Column(name = "approver_contact") private String approverContact;
    @Column(name = "network_ack_by") private String networkAckBy;
    @Column(name = "network_ack_at") private Instant networkAckAt;
    @Column(name = "evidence_ref", length = 512) private String evidenceRef;

    @Column(name = "created_by", nullable = false)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected TargetVerification() {}

    public TargetVerification(String id, String targetId, VerificationMethod method, String token,
                              Instant expiresAt, String createdBy) {
        this.id = id;
        this.targetId = targetId;
        this.method = method;
        this.token = token;
        this.expiresAt = expiresAt;
        this.createdBy = createdBy;
    }

    public String getId() { return id; }
    public String getTargetId() { return targetId; }
    public VerificationMethod getMethod() { return method; }
    public String getToken() { return token; }
    public ChallengeStatus getStatus() { return status; }
    public void setStatus(ChallengeStatus v) { this.status = v; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getVerifiedAt() { return verifiedAt; }
    public void setVerifiedAt(Instant v) { this.verifiedAt = v; }
    public Instant getLastCheckedAt() { return lastCheckedAt; }
    public void setLastCheckedAt(Instant v) { this.lastCheckedAt = v; }
    public String getDetail() { return detail; }
    public void setDetail(String v) { this.detail = v == null ? null : (v.length() > 500 ? v.substring(0, 500) : v); }
    public String getApproverName() { return approverName; }
    public void setApproverName(String v) { this.approverName = v; }
    public String getApproverContact() { return approverContact; }
    public void setApproverContact(String v) { this.approverContact = v; }
    public String getNetworkAckBy() { return networkAckBy; }
    public void setNetworkAckBy(String v) { this.networkAckBy = v; }
    public Instant getNetworkAckAt() { return networkAckAt; }
    public void setNetworkAckAt(Instant v) { this.networkAckAt = v; }
    public String getEvidenceRef() { return evidenceRef; }
    public void setEvidenceRef(String v) { this.evidenceRef = v; }
    public String getCreatedBy() { return createdBy; }
    public Instant getCreatedAt() { return createdAt; }
}
