package com.sentinelops.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "finding")
public class Finding {
    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "engagement_id", nullable = false, length = 36)
    private String engagementId;

    @Column(name = "scan_run_id", length = 36)
    private String scanRunId;

    @Column(name = "task_id", length = 64)
    private String taskId;

    @Enumerated(EnumType.STRING)
    @Column(length = 16)
    private Technology technology;

    @Column(nullable = false, length = 512)
    private String title;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Severity severity;

    @Column(name = "cvss_vector", length = 128)
    private String cvssVector;

    @Column(name = "cvss_score")
    private Double cvssScore;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private FindingStatus status = FindingStatus.OPEN;

    @Column(name = "evidence_ref", length = 512)
    private String evidenceRef;

    @Column(name = "target_id", length = 36)
    private String targetId;

    @Column(length = 32)
    private String tool;

    @Column(name = "rule_id")
    private String ruleId;

    @Column(length = 1024)
    private String location;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(columnDefinition = "TEXT")
    private String remediation;

    @Column(name = "reference_ids", length = 1024)
    private String referenceIds;

    /** Stable hash of target + tool + rule + location; the same issue found again is not duplicated. */
    @Column(length = 64)
    private String fingerprint;

    @Column(name = "last_seen_at")
    private Instant lastSeenAt;

    /** A scanner result is a candidate until a tester confirms it; clients only see confirmed findings. */
    @Column(nullable = false)
    private boolean validated = false;

    @Column(name = "validated_by")
    private String validatedBy;

    @Column(name = "validated_at")
    private Instant validatedAt;

    /** Mode of the scan that first found it (a passive retest cannot prove an active finding fixed). */
    @Enumerated(EnumType.STRING)
    @Column(name = "found_mode", length = 16)
    private ScanMode foundMode;

    @Column(name = "fix_notes", columnDefinition = "TEXT")
    private String fixNotes;

    @Column(name = "fixed_at")
    private Instant fixedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected Finding() {}

    public Finding(String id, String engagementId, String scanRunId, Technology technology,
                   String title, Severity severity) {
        this.id = id;
        this.engagementId = engagementId;
        this.scanRunId = scanRunId;
        this.technology = technology;
        this.title = title;
        this.severity = severity;
    }

    public String getId() { return id; }
    public String getEngagementId() { return engagementId; }
    public String getScanRunId() { return scanRunId; }
    public String getTaskId() { return taskId; }
    public void setTaskId(String v) { this.taskId = v; }
    public Technology getTechnology() { return technology; }
    public String getTitle() { return title; }
    public Severity getSeverity() { return severity; }
    public String getCvssVector() { return cvssVector; }
    public void setCvssVector(String v) { this.cvssVector = v; }
    public Double getCvssScore() { return cvssScore; }
    public void setCvssScore(Double v) { this.cvssScore = v; }
    public FindingStatus getStatus() { return status; }
    public void setStatus(FindingStatus v) { this.status = v; }
    public String getEvidenceRef() { return evidenceRef; }
    public void setEvidenceRef(String v) { this.evidenceRef = v; }
    public String getTargetId() { return targetId; }
    public void setTargetId(String v) { this.targetId = v; }
    public String getTool() { return tool; }
    public void setTool(String v) { this.tool = v; }
    public String getRuleId() { return ruleId; }
    public void setRuleId(String v) { this.ruleId = v; }
    public String getLocation() { return location; }
    public void setLocation(String v) { this.location = v; }
    public String getDescription() { return description; }
    public void setDescription(String v) { this.description = v; }
    public String getRemediation() { return remediation; }
    public void setRemediation(String v) { this.remediation = v; }
    public String getReferenceIds() { return referenceIds; }
    public void setReferenceIds(String v) { this.referenceIds = v; }
    public String getFingerprint() { return fingerprint; }
    public void setFingerprint(String v) { this.fingerprint = v; }
    public Instant getLastSeenAt() { return lastSeenAt; }
    public void setLastSeenAt(Instant v) { this.lastSeenAt = v; }
    public boolean isValidated() { return validated; }
    public void setValidated(boolean v) { this.validated = v; }
    public String getValidatedBy() { return validatedBy; }
    public void setValidatedBy(String v) { this.validatedBy = v; }
    public Instant getValidatedAt() { return validatedAt; }
    public void setValidatedAt(Instant v) { this.validatedAt = v; }
    public ScanMode getFoundMode() { return foundMode; }
    public void setFoundMode(ScanMode v) { this.foundMode = v; }
    public String getFixNotes() { return fixNotes; }
    public void setFixNotes(String v) { this.fixNotes = v; }
    public Instant getFixedAt() { return fixedAt; }
    public void setFixedAt(Instant v) { this.fixedAt = v; }
    public Instant getCreatedAt() { return createdAt; }
}
