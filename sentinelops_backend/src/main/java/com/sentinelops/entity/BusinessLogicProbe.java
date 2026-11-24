package com.sentinelops.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Phase 4 of the logic-testing engine (E/J: checkout / business logic; see PENTEST_COVERAGE_PLAN.md). One
 * request shape ({@code bodyTemplate} against {@code requestUrl}), replayed three ways: as-is, with
 * {@code tamperedField} overridden to {@code tamperedValue}, and {@code concurrency} times at once.
 */
@Entity
@Table(name = "business_logic_probe")
public class BusinessLogicProbe {
    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "target_id", nullable = false, length = 36)
    private String targetId;

    @Column(nullable = false, length = 64)
    private String label;

    @Column(name = "request_url", nullable = false, length = 512)
    private String requestUrl;

    @Column(name = "http_method", nullable = false, length = 8)
    private String httpMethod = "POST";

    @Column(name = "body_template", nullable = false, columnDefinition = "TEXT")
    private String bodyTemplate;

    /** Optional: a top-level JSON field in bodyTemplate to override for the tamper check. Null = skip it. */
    @Column(name = "tampered_field", length = 128)
    private String tamperedField;

    /** A JSON scalar as text, e.g. "0.01", "-5", "true", or "\"CODE\"" for a string. */
    @Column(name = "tampered_value", length = 512)
    private String tamperedValue;

    @Column(nullable = false)
    private int concurrency = 5;

    /** Optional: the test identity whose session sends the requests. Null = anonymous. */
    @Column(name = "identity_id", length = 36)
    private String identityId;

    @Column(name = "created_by", nullable = false)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected BusinessLogicProbe() {}

    public BusinessLogicProbe(String id, String targetId, String label, String requestUrl, String httpMethod,
                              String bodyTemplate, String tamperedField, String tamperedValue, int concurrency,
                              String identityId, String createdBy) {
        this.id = id;
        this.targetId = targetId;
        this.label = label;
        this.requestUrl = requestUrl;
        this.httpMethod = httpMethod == null || httpMethod.isBlank() ? "POST" : httpMethod;
        this.bodyTemplate = bodyTemplate;
        this.tamperedField = tamperedField;
        this.tamperedValue = tamperedValue;
        this.concurrency = concurrency;
        this.identityId = identityId;
        this.createdBy = createdBy;
    }

    public String getId() { return id; }
    public String getTargetId() { return targetId; }
    public String getLabel() { return label; }
    public String getRequestUrl() { return requestUrl; }
    public String getHttpMethod() { return httpMethod; }
    public String getBodyTemplate() { return bodyTemplate; }
    public String getTamperedField() { return tamperedField; }
    public String getTamperedValue() { return tamperedValue; }
    public int getConcurrency() { return concurrency; }
    public String getIdentityId() { return identityId; }
    public String getCreatedBy() { return createdBy; }
    public Instant getCreatedAt() { return createdAt; }
}
