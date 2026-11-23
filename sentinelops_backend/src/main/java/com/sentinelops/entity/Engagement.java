package com.sentinelops.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "engagement")
public class Engagement {
    @Id
    @Column(length = 36)
    private String id;

    @Column(nullable = false)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private TicketState state = TicketState.NEW;

    private String environment;

    @Column(name = "window_start")
    private Instant windowStart;

    @Column(name = "window_end")
    private Instant windowEnd;

    @Column(name = "client_id", nullable = false, length = 36)
    private String clientId;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    protected Engagement() {}

    public Engagement(String id, String name, String clientId, String environment) {
        this.id = id;
        this.name = name;
        this.clientId = clientId;
        this.environment = environment;
    }

    @PreUpdate
    void touch() { this.updatedAt = Instant.now(); }

    public String getId() { return id; }
    public String getName() { return name; }
    public TicketState getState() { return state; }
    public void setState(TicketState state) { this.state = state; }
    public String getEnvironment() { return environment; }
    public String getClientId() { return clientId; }
    public Instant getWindowStart() { return windowStart; }
    public void setWindowStart(Instant v) { this.windowStart = v; }
    public Instant getWindowEnd() { return windowEnd; }
    public void setWindowEnd(Instant v) { this.windowEnd = v; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
