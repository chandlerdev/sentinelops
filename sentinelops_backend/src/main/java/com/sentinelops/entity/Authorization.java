package com.sentinelops.entity;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * The control point of the platform. An authorization belongs to an engagement and covers a set of
 * verified targets for a time window and a set of permitted assessment methods.
 * A scan may only run when a matching authorization is SIGNED, in-window, not expired, covers the target,
 * and the target is not excluded. Ownership verification alone is NOT permission to test.
 */
@Entity
@Table(name = "authorization_record")
public class Authorization {
    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "engagement_id", nullable = false, length = 36)
    private String engagementId;

    private String title;

    @Column(name = "requested_by")
    private String requestedBy;

    /** The client-side person responsible for the systems who approves the testing. */
    @Column(name = "approver_name")
    private String approverName;

    @Column(name = "approver_contact")
    private String approverContact;

    @Column(name = "emergency_contact")
    private String emergencyContact;

    /** Comma-separated ScanCategory names. */
    @Column(name = "permitted_methods")
    private String permittedMethods = "";

    /** Comma-separated hosts / IPs / CIDRs that are explicitly out of scope. */
    @Column(name = "excluded_assets", columnDefinition = "TEXT")
    private String excludedAssets = "";

    @Column(name = "window_start")
    private Instant windowStart;

    @Column(name = "window_end")
    private Instant windowEnd;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AuthStatus status = AuthStatus.DRAFT;

    @Column(name = "signed_by")
    private String signedBy;

    @Column(name = "signed_at")
    private Instant signedAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "allow_active", nullable = false)
    private boolean allowActive = false;

    /** The client allows scanning with a logged-in session / API token we hold for the target. */
    @Column(name = "allow_authenticated", nullable = false)
    private boolean allowAuthenticated = false;

    /** Reference to the written approval evidence (document id, ticket, e-mail). */
    @Column(name = "roe_reference")
    private String roeReference;

    /** Platform user who approved / rejected / revoked. */
    @Column(name = "approved_by")
    private String approvedBy;

    @Column(name = "approved_at")
    private Instant approvedAt;

    @Column(name = "decision_note", length = 1024)
    private String decisionNote;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "authorization_scope", joinColumns = @JoinColumn(name = "authorization_id"))
    @Column(name = "target_id", length = 36)
    private Set<String> targetIds = new LinkedHashSet<>();

    protected Authorization() {}

    public Authorization(String id, String engagementId, String requestedBy) {
        this.id = id;
        this.engagementId = engagementId;
        this.requestedBy = requestedBy;
    }

    private static List<String> split(String csv) {
        if (csv == null || csv.isBlank()) return List.of();
        return Arrays.stream(csv.split(",")).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());
    }

    public Set<ScanCategory> getPermittedMethodSet() {
        return split(permittedMethods).stream().map(ScanCategory::valueOf)
                .collect(Collectors.toCollection(() -> EnumSet.noneOf(ScanCategory.class)));
    }

    public void setPermittedMethodSet(Collection<ScanCategory> v) {
        this.permittedMethods = v == null ? "" : v.stream().map(Enum::name).sorted().collect(Collectors.joining(","));
    }

    public List<String> getExcludedAssetList() { return split(excludedAssets); }

    public void setExcludedAssetList(Collection<String> v) {
        this.excludedAssets = v == null ? "" : String.join(",", v);
    }

    public String getId() { return id; }
    public String getEngagementId() { return engagementId; }
    public String getTitle() { return title; }
    public void setTitle(String v) { this.title = v; }
    public String getRequestedBy() { return requestedBy; }
    public String getApproverName() { return approverName; }
    public void setApproverName(String v) { this.approverName = v; }
    public String getApproverContact() { return approverContact; }
    public void setApproverContact(String v) { this.approverContact = v; }
    public String getEmergencyContact() { return emergencyContact; }
    public void setEmergencyContact(String v) { this.emergencyContact = v; }
    public AuthStatus getStatus() { return status; }
    public void setStatus(AuthStatus status) { this.status = status; }
    public Instant getWindowStart() { return windowStart; }
    public void setWindowStart(Instant v) { this.windowStart = v; }
    public Instant getWindowEnd() { return windowEnd; }
    public void setWindowEnd(Instant v) { this.windowEnd = v; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant v) { this.expiresAt = v; }
    public boolean isAllowAuthenticated() { return allowAuthenticated; }
    public void setAllowAuthenticated(boolean v) { this.allowAuthenticated = v; }
    public boolean isAllowActive() { return allowActive; }
    public void setAllowActive(boolean v) { this.allowActive = v; }
    public String getSignedBy() { return signedBy; }
    public void setSignedBy(String v) { this.signedBy = v; }
    public Instant getSignedAt() { return signedAt; }
    public void setSignedAt(Instant v) { this.signedAt = v; }
    public String getRoeReference() { return roeReference; }
    public void setRoeReference(String v) { this.roeReference = v; }
    public String getApprovedBy() { return approvedBy; }
    public void setApprovedBy(String v) { this.approvedBy = v; }
    public Instant getApprovedAt() { return approvedAt; }
    public void setApprovedAt(Instant v) { this.approvedAt = v; }
    public String getDecisionNote() { return decisionNote; }
    public void setDecisionNote(String v) { this.decisionNote = v; }
    public Instant getCreatedAt() { return createdAt; }
    public Set<String> getTargetIds() { return targetIds; }
}
