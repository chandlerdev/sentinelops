package com.sentinelops.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Phase 2 of the logic-testing engine (D: authorization / IDOR). Pairs two stored {@link TestIdentity}
 * rows with their OWN object id on one URL template (e.g. "/api/orders/{id}"), so the engine can try each
 * identity's id with the OTHER identity's session and see whether the server checks ownership.
 */
@Entity
@Table(name = "idor_probe")
public class IdorProbe {
    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "target_id", nullable = false, length = 36)
    private String targetId;

    @Column(nullable = false, length = 64)
    private String label;

    /** Contains the literal placeholder "{id}" exactly once, e.g. "https://app.example.com/api/orders/{id}". */
    @Column(name = "url_template", nullable = false, length = 512)
    private String urlTemplate;

    @Column(name = "identity_a_id", nullable = false, length = 36)
    private String identityAId;

    @Column(name = "resource_id_a", nullable = false, length = 128)
    private String resourceIdA;

    @Column(name = "identity_b_id", nullable = false, length = 36)
    private String identityBId;

    @Column(name = "resource_id_b", nullable = false, length = 128)
    private String resourceIdB;

    @Column(name = "created_by", nullable = false)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected IdorProbe() {}

    public IdorProbe(String id, String targetId, String label, String urlTemplate, String identityAId,
                     String resourceIdA, String identityBId, String resourceIdB, String createdBy) {
        this.id = id;
        this.targetId = targetId;
        this.label = label;
        this.urlTemplate = urlTemplate;
        this.identityAId = identityAId;
        this.resourceIdA = resourceIdA;
        this.identityBId = identityBId;
        this.resourceIdB = resourceIdB;
        this.createdBy = createdBy;
    }

    public String getId() { return id; }
    public String getTargetId() { return targetId; }
    public String getLabel() { return label; }
    public String getUrlTemplate() { return urlTemplate; }
    public String getIdentityAId() { return identityAId; }
    public String getResourceIdA() { return resourceIdA; }
    public String getIdentityBId() { return identityBId; }
    public String getResourceIdB() { return resourceIdB; }
    public String getCreatedBy() { return createdBy; }
    public Instant getCreatedAt() { return createdAt; }
}
