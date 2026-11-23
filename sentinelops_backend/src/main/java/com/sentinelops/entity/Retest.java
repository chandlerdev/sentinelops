package com.sentinelops.entity;

import jakarta.persistence.*;
import java.time.Instant;

/** Result of re-checking a finding after the client reported it fixed. */
@Entity
@Table(name = "retest")
public class Retest {
    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "finding_id", nullable = false, length = 36)
    private String findingId;

    /** PASS (no longer found) or FAIL (still found). */
    @Column(nullable = false, length = 20)
    private String result;

    @Column(name = "tested_by")
    private String testedBy;

    @Column(name = "tested_at", nullable = false)
    private Instant testedAt = Instant.now();

    @Column(length = 1024)
    private String notes;

    @Column(name = "scan_run_id", length = 36)
    private String scanRunId;

    protected Retest() {}

    public Retest(String id, String findingId, String result, String testedBy, String notes, String scanRunId) {
        this.id = id;
        this.findingId = findingId;
        this.result = result;
        this.testedBy = testedBy;
        this.notes = notes;
        this.scanRunId = scanRunId;
    }

    public String getId() { return id; }
    public String getFindingId() { return findingId; }
    public String getResult() { return result; }
    public String getTestedBy() { return testedBy; }
    public Instant getTestedAt() { return testedAt; }
    public String getNotes() { return notes; }
    public String getScanRunId() { return scanRunId; }
}
