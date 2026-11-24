package com.sentinelops.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * A stored test account (e.g. "User A", "Admin") on a target's own login, used by the logic-testing
 * modules (auth/session abuse, IDOR, checkout abuse) to act as that user. The password is encrypted at
 * rest with {@link com.sentinelops.util.SecretBox} and is never returned by the API once stored.
 */
@Entity
@Table(name = "test_identity")
public class TestIdentity {
    @Id
    @Column(length = 36)
    private String id;

    @Column(name = "target_id", nullable = false, length = 36)
    private String targetId;

    @Column(nullable = false, length = 64)
    private String label;

    @Column(name = "login_url", nullable = false, length = 512)
    private String loginUrl;

    @Column(name = "username_field", nullable = false, length = 64)
    private String usernameField = "email";

    @Column(name = "password_field", nullable = false, length = 64)
    private String passwordField = "password";

    @Column(nullable = false, length = 255)
    private String username;

    @Column(name = "enc_password", nullable = false, columnDefinition = "TEXT")
    private String encPassword;

    /** Dot-path to the token in the login response JSON (e.g. "token" or "data.token"). Null when sessionType is COOKIE. */
    @Column(name = "token_path", length = 128)
    private String tokenPath;

    @Enumerated(EnumType.STRING)
    @Column(name = "session_type", nullable = false, length = 16)
    private SessionType sessionType = SessionType.HEADER_BEARER;

    /** GET endpoint that requires authentication. Success (2xx) is how the engine tells a session still works. */
    @Column(name = "probe_url", length = 512)
    private String probeUrl;

    /** Endpoint that ends the session, used by the logout/session-reuse check (Phase 1). */
    @Column(name = "logout_url", length = 512)
    private String logoutUrl;

    @Column(name = "logout_method", nullable = false, length = 8)
    private String logoutMethod = "POST";

    @Column(name = "created_by", nullable = false)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected TestIdentity() {}

    public TestIdentity(String id, String targetId, String label, String loginUrl, String usernameField,
                        String passwordField, String username, String encPassword, String tokenPath,
                        SessionType sessionType, String probeUrl, String logoutUrl, String logoutMethod,
                        String createdBy) {
        this.id = id;
        this.targetId = targetId;
        this.label = label;
        this.loginUrl = loginUrl;
        this.usernameField = usernameField;
        this.passwordField = passwordField;
        this.username = username;
        this.encPassword = encPassword;
        this.tokenPath = tokenPath;
        this.sessionType = sessionType;
        this.probeUrl = probeUrl;
        this.logoutUrl = logoutUrl;
        this.logoutMethod = logoutMethod == null || logoutMethod.isBlank() ? "POST" : logoutMethod;
        this.createdBy = createdBy;
    }

    public String getId() { return id; }
    public String getTargetId() { return targetId; }
    public String getLabel() { return label; }
    public String getLoginUrl() { return loginUrl; }
    public String getUsernameField() { return usernameField; }
    public String getPasswordField() { return passwordField; }
    public String getUsername() { return username; }
    public String getEncPassword() { return encPassword; }
    public String getTokenPath() { return tokenPath; }
    public SessionType getSessionType() { return sessionType; }
    public String getProbeUrl() { return probeUrl; }
    public String getLogoutUrl() { return logoutUrl; }
    public String getLogoutMethod() { return logoutMethod; }
    public String getCreatedBy() { return createdBy; }
    public Instant getCreatedAt() { return createdAt; }
}
