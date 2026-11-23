package com.sentinelops.entity;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "system_setting")
public class SystemSetting {
    @Id
    @Column(name = "setting_key", length = 100)
    private String key;

    @Column(name = "setting_value", nullable = false, length = 512)
    private String value;

    @Column(name = "updated_by")
    private String updatedBy;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    protected SystemSetting() {}

    public SystemSetting(String key, String value, String updatedBy) {
        this.key = key;
        this.value = value;
        this.updatedBy = updatedBy;
    }

    public String getKey() { return key; }
    public String getValue() { return value; }
    public String getUpdatedBy() { return updatedBy; }
    public Instant getUpdatedAt() { return updatedAt; }

    public void update(String value, String by) {
        this.value = value;
        this.updatedBy = by;
        this.updatedAt = Instant.now();
    }
}
