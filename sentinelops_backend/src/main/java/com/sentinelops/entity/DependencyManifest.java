package com.sentinelops.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Phase 6 of the logic-testing engine (L: dependency / SCA scanning; see PENTEST_COVERAGE_PLAN.md). Unlike
 * every other check, this scans an uploaded MANIFEST FILE (a package-lock.json), never the target's live
 * infrastructure, so creating or scanning one needs no authorization gate - only normal engagement access.
 */
@Entity
@Table(name = "dependency_manifest")
public class DependencyManifest {
    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "target_id", nullable = false, length = 36)
    private String targetId;

    @Column(nullable = false, length = 64)
    private String label;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private DependencyEcosystem ecosystem = DependencyEcosystem.NPM;

    @Column(name = "manifest_content", nullable = false, columnDefinition = "MEDIUMTEXT")
    private String manifestContent;

    @Column(name = "created_by", nullable = false)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected DependencyManifest() {}

    public DependencyManifest(String id, String targetId, String label, DependencyEcosystem ecosystem,
                              String manifestContent, String createdBy) {
        this.id = id;
        this.targetId = targetId;
        this.label = label;
        this.ecosystem = ecosystem;
        this.manifestContent = manifestContent;
        this.createdBy = createdBy;
    }

    public String getId() { return id; }
    public String getTargetId() { return targetId; }
    public String getLabel() { return label; }
    public DependencyEcosystem getEcosystem() { return ecosystem; }
    public String getManifestContent() { return manifestContent; }
    public String getCreatedBy() { return createdBy; }
    public Instant getCreatedAt() { return createdAt; }
}
