package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.TargetRepository;
import com.sentinelops.repository.TestIdentityRepository;
import com.sentinelops.service.logic.LoginFlowRunner;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Phase 0: test identities are validated like scan credentials (same-host login URL, encrypted password,
 * never returned), and using one to log in goes through the same authorization gate as a scan.
 */
class TestIdentityServiceTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    private TargetRepository targetsWith(Target t) {
        var targets = mock(TargetRepository.class);
        when(targets.findById(t.getId())).thenReturn(Optional.of(t));
        return targets;
    }

    private TestIdentityService service(TestIdentityRepository repo, TargetRepository targets,
                                        AuthorizationGateService gate, LoginFlowRunner runner, String key) {
        AppProperties p = new AppProperties();
        p.getSecurity().setSecretKey(key);
        return new TestIdentityService(repo, targets, mock(AccessService.class), gate, runner, mock(AuditService.class), p);
    }

    @Test
    void storedPasswordIsEncryptedAndNeverAppearsInTheView() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var repo = mock(TestIdentityRepository.class);
        var saved = new TestIdentity[1];
        when(repo.save(any())).thenAnswer(i -> saved[0] = i.getArgument(0));
        var svc = service(repo, targetsWith(t), mock(AuthorizationGateService.class), mock(LoginFlowRunner.class), KEY);

        var view = svc.create("e1", "t1", "User A", "https://app.example.com/login", null, null,
                "user@example.com", "s3cr3t-pw", null, SessionType.HEADER_BEARER, null, null, null, "tess@x.com");

        assertFalse(saved[0].getEncPassword().contains("s3cr3t-pw"));
        assertEquals("User A", view.label());
        assertEquals("email", view.usernameField());
        assertEquals("password", view.passwordField());
        assertEquals("token", view.tokenPath());
        // The View record has no password field at all, so there's nothing to leak via reflection/toString either.
        assertFalse(view.toString().contains("s3cr3t-pw"));
    }

    @Test
    void loginUrlMustStayOnTheTargetsOwnHost() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(mock(TestIdentityRepository.class), targetsWith(t), mock(AuthorizationGateService.class),
                mock(LoginFlowRunner.class), KEY);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "User A",
                "https://evil.example.org/login", null, null, "u", "pw", null, SessionType.HEADER_BEARER,
                null, null, null, "tess"));
    }

    @Test
    void probeAndLogoutUrlsMustAlsoStayOnTheTargetsOwnHost() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(mock(TestIdentityRepository.class), targetsWith(t), mock(AuthorizationGateService.class),
                mock(LoginFlowRunner.class), KEY);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "User A",
                "https://app.example.com/login", null, null, "u", "pw", null, SessionType.HEADER_BEARER,
                "https://evil.example.org/me", null, null, "tess"));
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "User A",
                "https://app.example.com/login", null, null, "u", "pw", null, SessionType.HEADER_BEARER,
                null, "https://evil.example.org/logout", null, "tess"));
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "User A",
                "https://app.example.com/login", null, null, "u", "pw", null, SessionType.HEADER_BEARER,
                null, "https://app.example.com/logout", "DELETE", "tess"));
    }

    @Test
    void aRangeCannotHoldATestIdentity() {
        Target t = new Target("t1", "e1", TargetKind.CIDR, "203.0.113.0/28", "tess");
        var svc = service(mock(TestIdentityRepository.class), targetsWith(t), mock(AuthorizationGateService.class),
                mock(LoginFlowRunner.class), KEY);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "User A",
                "https://app.example.com/login", null, null, "u", "pw", null, SessionType.HEADER_BEARER,
                null, null, null, "tess"));
    }

    @Test
    void badFieldNamesAndBlankCredentialsAreRefused() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(mock(TestIdentityRepository.class), targetsWith(t), mock(AuthorizationGateService.class),
                mock(LoginFlowRunner.class), KEY);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "User A",
                "https://app.example.com/login", "bad name!", null, "u", "pw", null, SessionType.HEADER_BEARER,
                null, null, null, "tess"));
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "User A",
                "https://app.example.com/login", null, null, "", "pw", null, SessionType.HEADER_BEARER,
                null, null, null, "tess"));
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "User A",
                "https://app.example.com/login", null, null, "u", "", null, SessionType.HEADER_BEARER,
                null, null, null, "tess"));
    }

    @Test
    void storageFailsClosedWithoutASecretKey() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(mock(TestIdentityRepository.class), targetsWith(t), mock(AuthorizationGateService.class),
                mock(LoginFlowRunner.class), "");
        assertThrows(IllegalStateException.class, () -> svc.create("e1", "t1", "User A",
                "https://app.example.com/login", null, null, "u", "pw", null, SessionType.HEADER_BEARER,
                null, null, null, "tess"));
    }

    @Test
    void testLoginIsRefusedWhenTheGateDenies() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var identity = new TestIdentity("i1", "t1", "User A", "https://app.example.com/login", "email", "password",
                "u", new com.sentinelops.util.SecretBox(KEY).encrypt("pw"), "token", SessionType.HEADER_BEARER,
                null, null, "POST", "tess");
        var repo = mock(TestIdentityRepository.class);
        when(repo.findById("i1")).thenReturn(Optional.of(identity));
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(eq("e1"), eq("t1"), eq(ScanCategory.WEB), any(Instant.class)))
                .thenReturn(deny("No signed authorization covers this target."));
        var runner = mock(LoginFlowRunner.class);
        var svc = service(repo, targetsWith(t), gate, runner, KEY);

        assertThrows(AccessDeniedException.class, () -> svc.testLogin("e1", "t1", "i1", "tess@x.com"));
        verifyNoInteractions(runner);
    }

    @Test
    void testLoginIsRefusedWhenAuthorizationDoesNotAllowAuthenticatedTesting() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var identity = new TestIdentity("i1", "t1", "User A", "https://app.example.com/login", "email", "password",
                "u", new com.sentinelops.util.SecretBox(KEY).encrypt("pw"), "token", SessionType.HEADER_BEARER,
                null, null, "POST", "tess");
        var repo = mock(TestIdentityRepository.class);
        when(repo.findById("i1")).thenReturn(Optional.of(identity));
        Authorization auth = mock(Authorization.class);
        when(auth.isAllowAuthenticated()).thenReturn(false);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(eq("e1"), eq("t1"), eq(ScanCategory.WEB), any(Instant.class)))
                .thenReturn(allowed(auth, t));
        var runner = mock(LoginFlowRunner.class);
        var svc = service(repo, targetsWith(t), gate, runner, KEY);

        assertThrows(AccessDeniedException.class, () -> svc.testLogin("e1", "t1", "i1", "tess@x.com"));
        verifyNoInteractions(runner);
    }

    @Test
    void testLoginDecryptsAndRunsWhenPermittedAndNeverReturnsTheSession() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var identity = new TestIdentity("i1", "t1", "User A", "https://app.example.com/login", "email", "password",
                "u", new com.sentinelops.util.SecretBox(KEY).encrypt("the-real-password"), "token",
                SessionType.HEADER_BEARER, null, null, "POST", "tess");
        var repo = mock(TestIdentityRepository.class);
        when(repo.findById("i1")).thenReturn(Optional.of(identity));
        Authorization auth = mock(Authorization.class);
        when(auth.isAllowAuthenticated()).thenReturn(true);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(eq("e1"), eq("t1"), eq(ScanCategory.WEB), any(Instant.class)))
                .thenReturn(allowed(auth, t));
        var runner = mock(LoginFlowRunner.class);
        when(runner.attempt(eq(identity), eq("the-real-password")))
                .thenReturn(new LoginFlowRunner.LoginOutcome(true, 200, true, "super-secret-token", "ok"));
        var svc = service(repo, targetsWith(t), gate, runner, KEY);

        var result = svc.testLogin("e1", "t1", "i1", "tess@x.com");
        assertTrue(result.success());
        assertTrue(result.sessionCaptured());
        // The record has no session-value field to begin with.
        assertFalse(result.toString().contains("super-secret-token"));
    }

    // ---- small helpers to build gate results without touching repositories ----

    private static AuthorizationGateService.GateResult deny(String reason) {
        return new AuthorizationGateService.GateResult(false, reason, null, null, List.of());
    }

    private static AuthorizationGateService.GateResult allowed(Authorization a, Target t) {
        return new AuthorizationGateService.GateResult(true, null, a, t, List.of("93.184.216.34"));
    }
}
