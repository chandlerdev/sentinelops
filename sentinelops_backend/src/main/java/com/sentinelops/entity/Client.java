package com.sentinelops.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "client")
public class Client {
    @Id
    @Column(length = 36)
    private String id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String contact;

    private String tier;
    private String compliance;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected Client() {}

    public Client(String id, String name, String contact, String tier, String compliance) {
        this.id = id;
        this.name = name;
        this.contact = contact;
        this.tier = tier;
        this.compliance = compliance;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public String getContact() { return contact; }
    public String getTier() { return tier; }
    public String getCompliance() { return compliance; }
    public Instant getCreatedAt() { return createdAt; }
}
