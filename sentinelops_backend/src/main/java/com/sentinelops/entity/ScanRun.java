package com.sentinelops.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "scan_run")
public class ScanRun {
    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "engagement_id", nullable = false, length = 36)
    private String engagementId;

    @Column(name = "authorization_id", nullable = false, length = 36)
    private String authorizationId;

    @Enumerated(EnumType.STRING)
    @Column(length = 16)
    private Technology technology;

    @Column(name = "target_host", nullable = false)
    private String targetHost;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private ScanMode mode = ScanMode.PASSIVE;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private ScanStatus status = ScanStatus.QUEUED;

    private String tool;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "ended_at")
    private Instant endedAt;

    @Column(name = "evidence_uri")
    private String evidenceUri;

    @Column(length = 1024)
    private String error;

    @Column(name = "target_id", length = 36)
    private String targetId;

    @Enumerated(EnumType.STRING)
    @Column(length = 16)
    private ScanCategory category;

    /** Addresses the target resolved to when the gate passed (comma-separated). */
    @Column(name = "resolved_addresses", length = 512)
    private String resolvedAddresses;

    /** SCAN (requested), RETEST (re-check of a fixed finding) or SCHEDULED. */
    @Column(nullable = false, length = 16)
    private String purpose = "SCAN";

    @Column(name = "work_dir")
    private String workDir;

    @Column(name = "exit_code")
    private Integer exitCode;

    @Column(name = "finding_count", nullable = false)
    private int findingCount = 0;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected ScanRun() {}

    public ScanRun(String id, String engagementId, String authorizationId, Technology technology,
                   String targetHost, ScanMode mode, String tool) {
        this.id = id;
        this.engagementId = engagementId;
        this.authorizationId = authorizationId;
        this.technology = technology;
        this.targetHost = targetHost;
        this.mode = mode;
        this.tool = tool;
    }

    public String getId() { return id; }
    public String getEngagementId() { return engagementId; }
    public String getAuthorizationId() { return authorizationId; }
    public Technology getTechnology() { return technology; }
    public String getTargetHost() { return targetHost; }
    public ScanMode getMode() { return mode; }
    public void setMode(ScanMode v) { this.mode = v; }
    public ScanStatus getStatus() { return status; }
    public void setStatus(ScanStatus v) { this.status = v; }
    public String getTool() { return tool; }
    public Instant getStartedAt() { return startedAt; }
    public void setStartedAt(Instant v) { this.startedAt = v; }
    public Instant getEndedAt() { return endedAt; }
    public void setEndedAt(Instant v) { this.endedAt = v; }
    public String getEvidenceUri() { return evidenceUri; }
    public void setEvidenceUri(String v) { this.evidenceUri = v; }
    public String getTargetId() { return targetId; }
    public void setTargetId(String v) { this.targetId = v; }
    public ScanCategory getCategory() { return category; }
    public void setCategory(ScanCategory v) { this.category = v; }
    public String getResolvedAddresses() { return resolvedAddresses; }
    public void setResolvedAddresses(String v) { this.resolvedAddresses = v; }
    public String getError() { return error; }
    public void setError(String v) { this.error = v; }
    public String getPurpose() { return purpose; }
    public void setPurpose(String v) { this.purpose = v; }
    public String getWorkDir() { return workDir; }
    public void setWorkDir(String v) { this.workDir = v; }
    public Integer getExitCode() { return exitCode; }
    public void setExitCode(Integer v) { this.exitCode = v; }
    public int getFindingCount() { return findingCount; }
    public void setFindingCount(int v) { this.findingCount = v; }
    public Instant getCreatedAt() { return createdAt; }
}
