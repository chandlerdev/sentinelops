package com.sentinelops.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_log")
public class AuditLog {
    @Id
    @Column(length = 36)
    private String id;

    @Column(nullable = false)
    private String actor;

    @Column(nullable = false, length = 128)
    private String action;

    @Column(nullable = false, length = 64)
    private String entity;

    @Column(name = "entity_id", length = 36)
    private String entityId;

    @Column(columnDefinition = "TEXT")
    private String detail;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected AuditLog() {}

    public AuditLog(String id, String actor, String action, String entity, String entityId, String detail) {
        this.id = id;
        this.actor = actor;
        this.action = action;
        this.entity = entity;
        this.entityId = entityId;
        this.detail = detail;
    }

    public String getId() { return id; }
    public String getActor() { return actor; }
    public String getAction() { return action; }
    public String getEntity() { return entity; }
    public String getEntityId() { return entityId; }
    public String getDetail() { return detail; }
    public Instant getCreatedAt() { return createdAt; }
}
