package com.sentinelops.entity;

import jakarta.persistence.*;
import java.time.Instant;

/** A recurring scan. Every run goes through the full authorization gate; a schedule never bypasses it. */
@Entity
@Table(name = "scan_schedule")
public class ScanSchedule {
    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "engagement_id", nullable = false, length = 36)
    private String engagementId;

    @Column(name = "target_id", nullable = false, length = 36)
    private String targetId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private ScanCategory category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private ScanMode mode = ScanMode.PASSIVE;

    @Column(name = "interval_days", nullable = false)
    private int intervalDays;

    @Column(name = "next_run_at", nullable = false)
    private Instant nextRunAt;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "denied_in_a_row", nullable = false)
    private int deniedInARow = 0;

    @Column(name = "last_result", length = 512)
    private String lastResult;

    @Column(name = "created_by", nullable = false)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected ScanSchedule() {}

    public ScanSchedule(String id, String engagementId, String targetId, ScanCategory category, ScanMode mode,
                        int intervalDays, Instant nextRunAt, String createdBy) {
        this.id = id;
        this.engagementId = engagementId;
        this.targetId = targetId;
        this.category = category;
        this.mode = mode;
        this.intervalDays = intervalDays;
        this.nextRunAt = nextRunAt;
        this.createdBy = createdBy;
    }

    public String getId() { return id; }
    public String getEngagementId() { return engagementId; }
    public String getTargetId() { return targetId; }
    public ScanCategory getCategory() { return category; }
    public ScanMode getMode() { return mode; }
    public int getIntervalDays() { return intervalDays; }
    public Instant getNextRunAt() { return nextRunAt; }
    public void setNextRunAt(Instant v) { this.nextRunAt = v; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean v) { this.enabled = v; }
    public int getDeniedInARow() { return deniedInARow; }
    public void setDeniedInARow(int v) { this.deniedInARow = v; }
    public String getLastResult() { return lastResult; }
    public void setLastResult(String v) { this.lastResult = v; }
    public String getCreatedBy() { return createdBy; }
    public Instant getCreatedAt() { return createdAt; }
}
