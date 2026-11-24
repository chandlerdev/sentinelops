package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.exception.NotFoundException;
import com.sentinelops.repository.TargetRepository;
import com.sentinelops.repository.TestIdentityRepository;
import com.sentinelops.service.logic.LoginFlowRunner;
import com.sentinelops.util.SecretBox;
import com.sentinelops.util.TargetParser;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Phase 0 of the logic-testing engine: stored test accounts ("User A", "Admin", ...) on a target's own
 * login, so later modules (auth/session abuse, IDOR, checkout abuse) can act as that user. The password is
 * encrypted like a scan credential and is never returned once stored. Creating or using one requires the
 * same authorization gate as a scan: it sends real login traffic to the target.
 */
@Service
public class TestIdentityService {

    private static final Pattern LABEL = Pattern.compile("^[A-Za-z0-9 ._-]{1,64}$");
    private static final Pattern FIELD_NAME = Pattern.compile("^[A-Za-z][A-Za-z0-9_]{0,63}$");
    private static final Pattern TOKEN_PATH = Pattern.compile("^[A-Za-z0-9_.]{1,128}$");
    private static final java.util.Set<String> LOGOUT_METHODS = java.util.Set.of("GET", "POST");

    public record View(String id, String targetId, String label, String loginUrl, String usernameField,
                       String passwordField, String username, String tokenPath, SessionType sessionType,
                       String probeUrl, String logoutUrl, String logoutMethod,
                       String createdBy, Instant createdAt) {
        static View from(TestIdentity i) {
            return new View(i.getId(), i.getTargetId(), i.getLabel(), i.getLoginUrl(), i.getUsernameField(),
                    i.getPasswordField(), i.getUsername(), i.getTokenPath(), i.getSessionType(),
                    i.getProbeUrl(), i.getLogoutUrl(), i.getLogoutMethod(), i.getCreatedBy(), i.getCreatedAt());
        }
    }

    public record LoginTestResult(boolean success, int httpStatus, boolean sessionCaptured, String detail) {}

    private final TestIdentityRepository identities;
    private final TargetRepository targets;
    private final AccessService access;
    private final AuthorizationGateService gate;
    private final LoginFlowRunner runner;
    private final AuditService audit;
    private final AppProperties props;

    public TestIdentityService(TestIdentityRepository identities, TargetRepository targets, AccessService access,
                               AuthorizationGateService gate, LoginFlowRunner runner, AuditService audit,
                               AppProperties props) {
        this.identities = identities;
        this.targets = targets;
        this.access = access;
        this.gate = gate;
        this.runner = runner;
        this.audit = audit;
        this.props = props;
    }

    /** Package-private: also used by {@link LogicTestService} to re-validate before running a check. */
    Target target(String engagementId, String targetId) {
        access.requireEngagement(engagementId);
        Target t = targets.findById(targetId).orElseThrow(() -> new NotFoundException("Target not found"));
        if (!t.getEngagementId().equals(engagementId)) throw new NotFoundException("Target not found");
        return t;
    }

    TestIdentity identity(String targetId, String identityId) {
        TestIdentity i = identities.findById(identityId).orElseThrow(() -> new NotFoundException("Test identity not found"));
        if (!i.getTargetId().equals(targetId)) throw new NotFoundException("Test identity not found");
        return i;
    }

    private String sameHostUrl(String url, String fieldName, Target t, boolean required) {
        if (url == null || url.isBlank()) {
            if (required) throw new IllegalArgumentException(fieldName + " is required.");
            return null;
        }
        String host;
        try {
            host = TargetParser.hostOfUrl(url.trim());
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(fieldName + ": " + ex.getMessage());
        }
        if (!host.equals(t.getValue())) {
            throw new IllegalArgumentException(fieldName + " must be on the target's own host.");
        }
        return url.trim();
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public View create(String engagementId, String targetId, String label, String loginUrl, String usernameField,
                       String passwordField, String username, String password, String tokenPath,
                       SessionType sessionType, String probeUrl, String logoutUrl, String logoutMethod,
                       String actor) {
        Target t = target(engagementId, targetId);
        if (t.getKind() == TargetKind.CIDR) throw new IllegalArgumentException("A range cannot hold a test identity.");

        if (label == null || !LABEL.matcher(label).matches()) {
            throw new IllegalArgumentException("Label must be 1-64 letters, digits, spaces, '.', '_' or '-'.");
        }
        String login = sameHostUrl(loginUrl, "Login URL", t, true);
        String probe = sameHostUrl(probeUrl, "Probe URL", t, false);
        String logout = sameHostUrl(logoutUrl, "Logout URL", t, false);
        String lMethod = logoutMethod == null || logoutMethod.isBlank() ? "POST" : logoutMethod.trim().toUpperCase();
        if (!LOGOUT_METHODS.contains(lMethod)) throw new IllegalArgumentException("Logout method must be GET or POST.");

        String uField = usernameField == null || usernameField.isBlank() ? "email" : usernameField.trim();
        String pField = passwordField == null || passwordField.isBlank() ? "password" : passwordField.trim();
        if (!FIELD_NAME.matcher(uField).matches() || !FIELD_NAME.matcher(pField).matches()) {
            throw new IllegalArgumentException("Field names must start with a letter and contain only letters, digits or '_'.");
        }
        if (username == null || username.isBlank() || username.length() > 255) {
            throw new IllegalArgumentException("Username is required (max 255 characters).");
        }
        if (password == null || password.isEmpty() || password.length() > 500) {
            throw new IllegalArgumentException("Password is required (max 500 characters).");
        }
        SessionType st = sessionType == null ? SessionType.HEADER_BEARER : sessionType;
        String path = null;
        if (st == SessionType.HEADER_BEARER) {
            path = tokenPath == null || tokenPath.isBlank() ? "token" : tokenPath.trim();
            if (!TOKEN_PATH.matcher(path).matches()) {
                throw new IllegalArgumentException("Token path may only contain letters, digits, '.' or '_'.");
            }
        }

        SecretBox box = new SecretBox(props.getSecurity().getSecretKey()); // fails closed without a key
        TestIdentity id = new TestIdentity(UUID.randomUUID().toString(), targetId, label.trim(), login,
                uField, pField, username.trim(), box.encrypt(password), path, st, probe, logout, lMethod, actor);
        identities.save(id);
        audit.record(actor, "test_identity.created", "Target", targetId,
                "label=" + id.getLabel() + " loginUrl=" + id.getLoginUrl()); // never the password
        return View.from(id);
    }

    @Transactional(readOnly = true)
    public List<View> list(String engagementId, String targetId) {
        target(engagementId, targetId);
        return identities.findByTargetIdOrderByCreatedAtAsc(targetId).stream().map(View::from).toList();
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public void delete(String engagementId, String targetId, String identityId, String actor) {
        target(engagementId, targetId);
        TestIdentity i = identity(targetId, identityId);
        identities.delete(i);
        audit.record(actor, "test_identity.deleted", "Target", targetId, "label=" + i.getLabel());
    }

    /**
     * Runs one real login attempt. Gated exactly like a scan: ownership verified, a signed authorization
     * covers WEB testing on this target, and the authorization allows authenticated testing. The captured
     * session value is never returned to the caller; only success/failure and whether one was captured.
     */
    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public LoginTestResult testLogin(String engagementId, String targetId, String identityId, String actor) {
        target(engagementId, targetId);
        TestIdentity i = identity(targetId, identityId);

        var result = gate.evaluate(engagementId, targetId, ScanCategory.WEB, Instant.now());
        if (!result.allowed()) {
            audit.record(actor, "test_identity.login_test", "Target", targetId,
                    "identity=" + i.getLabel() + " denied: " + result.reason());
            throw new AccessDeniedException("Not permitted: " + result.reason());
        }
        if (!result.authorization().isAllowAuthenticated()) {
            audit.record(actor, "test_identity.login_test", "Target", targetId,
                    "identity=" + i.getLabel() + " denied: authorization does not allow authenticated testing");
            throw new AccessDeniedException("Not permitted: the signed authorization does not allow authenticated testing.");
        }

        String password = new SecretBox(props.getSecurity().getSecretKey()).decrypt(i.getEncPassword());
        var outcome = runner.attempt(i, password);
        audit.record(actor, "test_identity.login_test", "Target", targetId,
                "identity=" + i.getLabel() + " success=" + outcome.success() + " status=" + outcome.httpStatus());
        return new LoginTestResult(outcome.success(), outcome.httpStatus(), outcome.sessionCaptured(), outcome.detail());
    }
}
