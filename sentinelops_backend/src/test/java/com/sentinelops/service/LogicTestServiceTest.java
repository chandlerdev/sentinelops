package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.*;
import com.sentinelops.service.logic.AuthSessionChecks;
import com.sentinelops.service.logic.BusinessLogicChecks;
import com.sentinelops.service.logic.DefaultCredentialChecks;
import com.sentinelops.service.logic.DependencyChecks;
import com.sentinelops.service.logic.DnsHygieneChecks;
import com.sentinelops.service.logic.IdorChecks;
import com.sentinelops.service.logic.LoginFlowRunner;
import com.sentinelops.service.logic.UploadChecks;
import com.sentinelops.util.SecretBox;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;
import java.util.Optional;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;

/**
 * Both logic checks (Phase 1 auth/session, Phase 2 IDOR) need the normal gate PLUS allowActive PLUS
 * allowAuthenticated PLUS the global active-scanning switch, because they send intrusive traffic. Only a
 * VULNERABLE verdict becomes a Finding; a clean or inconclusive check never does.
 */
class LogicTestServiceTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    private TestIdentity identityWith(SecretBox box, String id, String label) {
        return new TestIdentity(id, "t1", label, "https://app.example.com/login", "email", "password",
                "u-" + id, box.encrypt("pw-" + id), "token", SessionType.HEADER_BEARER,
                "https://app.example.com/me", "https://app.example.com/logout", "POST", "tess");
    }

    private TestIdentityService identityService(Target t, TestIdentityRepository repo, AuthorizationGateService gate) {
        var targets = mock(TargetRepository.class);
        when(targets.findById("t1")).thenReturn(Optional.of(t));
        AppProperties p = new AppProperties();
        p.getSecurity().setSecretKey(KEY);
        return new TestIdentityService(repo, targets, mock(AccessService.class), gate, mock(LoginFlowRunner.class),
                mock(AuditService.class), p);
    }

    private TestIdentityRepository repoWith(TestIdentity... identities) {
        var repo = mock(TestIdentityRepository.class);
        for (var i : identities) when(repo.findById(i.getId())).thenReturn(Optional.of(i));
        return repo;
    }

    private ScanExecutor realScanExecutor(FindingRepository findings) {
        AppProperties p = new AppProperties();
        return new ScanExecutor(mock(AuthorizationGateService.class), mock(com.sentinelops.service.scanner.ScannerRegistry.class),
                mock(com.sentinelops.service.scanner.DockerRunner.class), mock(ScanRunRepository.class), findings,
                mock(RetestRepository.class), mock(CredentialService.class), mock(AuditService.class), p,
                mock(SettingsService.class), mock(TransactionTemplate.class));
    }

    private LogicTestService service(Target t, TestIdentityRepository idRepo, IdorProbeRepository probeRepo,
                                     AuthorizationGateService gate, SettingsService settings,
                                     AuthSessionChecks authChecks, IdorChecks idorChecks, FindingRepository findings) {
        return service(t, idRepo, probeRepo, mock(UploadProbeRepository.class), mock(BusinessLogicProbeRepository.class),
                gate, settings, authChecks, idorChecks, mock(UploadChecks.class), mock(BusinessLogicChecks.class), findings);
    }

    private LogicTestService service(Target t, TestIdentityRepository idRepo, IdorProbeRepository probeRepo,
                                     UploadProbeRepository uploadRepo, AuthorizationGateService gate,
                                     SettingsService settings, AuthSessionChecks authChecks, IdorChecks idorChecks,
                                     UploadChecks uploadChecks, FindingRepository findings) {
        return service(t, idRepo, probeRepo, uploadRepo, mock(BusinessLogicProbeRepository.class), gate, settings,
                authChecks, idorChecks, uploadChecks, mock(BusinessLogicChecks.class), findings);
    }

    private LogicTestService service(Target t, TestIdentityRepository idRepo, IdorProbeRepository probeRepo,
                                     UploadProbeRepository uploadRepo, BusinessLogicProbeRepository businessRepo,
                                     AuthorizationGateService gate, SettingsService settings,
                                     AuthSessionChecks authChecks, IdorChecks idorChecks, UploadChecks uploadChecks,
                                     BusinessLogicChecks businessChecks, FindingRepository findings) {
        return service(t, idRepo, probeRepo, uploadRepo, businessRepo, gate, settings, authChecks, idorChecks,
                uploadChecks, businessChecks, mock(DnsHygieneChecks.class), mock(DefaultCredentialChecks.class), findings);
    }

    private LogicTestService service(Target t, TestIdentityRepository idRepo, IdorProbeRepository probeRepo,
                                     UploadProbeRepository uploadRepo, BusinessLogicProbeRepository businessRepo,
                                     AuthorizationGateService gate, SettingsService settings,
                                     AuthSessionChecks authChecks, IdorChecks idorChecks, UploadChecks uploadChecks,
                                     BusinessLogicChecks businessChecks, DnsHygieneChecks dnsChecks,
                                     DefaultCredentialChecks defaultCredChecks, FindingRepository findings) {
        return service(t, idRepo, probeRepo, uploadRepo, businessRepo, mock(DependencyManifestRepository.class), gate,
                settings, authChecks, idorChecks, uploadChecks, businessChecks, dnsChecks, defaultCredChecks,
                mock(DependencyChecks.class), findings);
    }

    private LogicTestService service(Target t, TestIdentityRepository idRepo, IdorProbeRepository probeRepo,
                                     UploadProbeRepository uploadRepo, BusinessLogicProbeRepository businessRepo,
                                     DependencyManifestRepository dependencyRepo, AuthorizationGateService gate,
                                     SettingsService settings, AuthSessionChecks authChecks, IdorChecks idorChecks,
                                     UploadChecks uploadChecks, BusinessLogicChecks businessChecks,
                                     DnsHygieneChecks dnsChecks, DefaultCredentialChecks defaultCredChecks,
                                     DependencyChecks dependencyChecks, FindingRepository findings) {
        AppProperties p = new AppProperties();
        p.getSecurity().setSecretKey(KEY);
        var identityService = identityService(t, idRepo, gate);
        var idorProbeService = new IdorProbeService(probeRepo, identityService, mock(AuditService.class));
        var uploadProbeService = new UploadProbeService(uploadRepo, identityService, mock(AuditService.class));
        var businessProbeService = new BusinessLogicProbeService(businessRepo, identityService, mock(AuditService.class));
        var targets = mock(TargetRepository.class);
        when(targets.findById("t1")).thenReturn(Optional.of(t));
        var dependencyManifestService = new DependencyManifestService(dependencyRepo, targets, mock(AccessService.class), mock(AuditService.class));
        return new LogicTestService(identityService, idorProbeService, uploadProbeService, businessProbeService,
                dependencyManifestService, gate, settings, authChecks, idorChecks, uploadChecks, businessChecks,
                dnsChecks, defaultCredChecks, dependencyChecks, realScanExecutor(findings),
                mock(ScanRunRepository.class), mock(AuditService.class), p);
    }

    private static AuthorizationGateService.GateResult allowed(Authorization a, Target t) {
        return new AuthorizationGateService.GateResult(true, null, a, t, List.of("93.184.216.34"));
    }
    private static AuthorizationGateService.GateResult denied(String reason) {
        return new AuthorizationGateService.GateResult(false, reason, null, null, List.of());
    }

    // ---------------- Phase 1: auth checks ----------------

    @Test
    void authChecksRefusedWhenTheBasicGateDenies() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity identity = identityWith(new SecretBox(KEY), "i1", "User A");
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(denied("No signed authorization covers this target."));
        var svc = service(t, repoWith(identity), mock(IdorProbeRepository.class), gate, mock(SettingsService.class),
                mock(AuthSessionChecks.class), mock(IdorChecks.class), mock(FindingRepository.class));

        assertThrows(AccessDeniedException.class, () -> svc.runAuthChecks("e1", "t1", "i1", "tess@x.com"));
    }

    @Test
    void authChecksRefusedWhenAuthorizationDoesNotAllowAuthenticatedTesting() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity identity = identityWith(new SecretBox(KEY), "i1", "User A");
        Authorization auth = mock(Authorization.class);
        when(auth.isAllowAuthenticated()).thenReturn(false);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(allowed(auth, t));
        var settings = mock(SettingsService.class);
        when(settings.isActiveScanningEnabled()).thenReturn(true);
        var svc = service(t, repoWith(identity), mock(IdorProbeRepository.class), gate, settings,
                mock(AuthSessionChecks.class), mock(IdorChecks.class), mock(FindingRepository.class));

        assertThrows(AccessDeniedException.class, () -> svc.runAuthChecks("e1", "t1", "i1", "tess@x.com"));
    }

    @Test
    void authChecksRefusedWhenAuthorizationDoesNotAllowActiveTesting() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity identity = identityWith(new SecretBox(KEY), "i1", "User A");
        Authorization auth = mock(Authorization.class);
        when(auth.isAllowAuthenticated()).thenReturn(true);
        when(auth.isAllowActive()).thenReturn(false);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(allowed(auth, t));
        var settings = mock(SettingsService.class);
        when(settings.isActiveScanningEnabled()).thenReturn(true);
        var svc = service(t, repoWith(identity), mock(IdorProbeRepository.class), gate, settings,
                mock(AuthSessionChecks.class), mock(IdorChecks.class), mock(FindingRepository.class));

        assertThrows(AccessDeniedException.class, () -> svc.runAuthChecks("e1", "t1", "i1", "tess@x.com"));
    }

    @Test
    void authChecksRefusedWhenTheGlobalActiveScanningSwitchIsOff() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity identity = identityWith(new SecretBox(KEY), "i1", "User A");
        Authorization auth = mock(Authorization.class);
        when(auth.isAllowAuthenticated()).thenReturn(true);
        when(auth.isAllowActive()).thenReturn(true);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(allowed(auth, t));
        var settings = mock(SettingsService.class);
        when(settings.isActiveScanningEnabled()).thenReturn(false);
        var svc = service(t, repoWith(identity), mock(IdorProbeRepository.class), gate, settings,
                mock(AuthSessionChecks.class), mock(IdorChecks.class), mock(FindingRepository.class));

        assertThrows(AccessDeniedException.class, () -> svc.runAuthChecks("e1", "t1", "i1", "tess@x.com"));
    }

    @Test
    void authChecksWhenPermittedOnlyVulnerableVerdictsBecomeFindings() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity identity = identityWith(new SecretBox(KEY), "i1", "User A");
        Authorization auth = mock(Authorization.class);
        when(auth.getId()).thenReturn("auth1");
        when(auth.isAllowAuthenticated()).thenReturn(true);
        when(auth.isAllowActive()).thenReturn(true);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(allowed(auth, t));
        var settings = mock(SettingsService.class);
        when(settings.isActiveScanningEnabled()).thenReturn(true);

        var checks = mock(AuthSessionChecks.class);
        when(checks.checkLogoutSessionReuse(any(), any())).thenReturn(
                new AuthSessionChecks.Result("AUTH-12", "Session usable after logout", AuthSessionChecks.Verdict.VULNERABLE,
                        Severity.HIGH, "https://app.example.com/me", "still works after logout", "invalidate server-side"));
        when(checks.checkJwt(any(), any())).thenReturn(List.of(
                new AuthSessionChecks.Result("AUTH-11a", "alg=none", AuthSessionChecks.Verdict.NOT_VULNERABLE,
                        Severity.INFORMATIONAL, "https://app.example.com/me", null, null),
                new AuthSessionChecks.Result("AUTH-11b", "sig not checked", AuthSessionChecks.Verdict.NEEDS_MANUAL_REVIEW,
                        Severity.INFORMATIONAL, null, "no recognisable claim", null)));

        var findingRepo = mock(FindingRepository.class);
        when(findingRepo.findFirstByEngagementIdAndFingerprint(any(), any())).thenReturn(Optional.empty());
        var saved = new java.util.ArrayList<Finding>();
        when(findingRepo.save(any())).thenAnswer(i -> { saved.add(i.getArgument(0)); return i.getArgument(0); });

        var svc = service(t, repoWith(identity), mock(IdorProbeRepository.class), gate, settings, checks,
                mock(IdorChecks.class), findingRepo);
        var result = svc.runAuthChecks("e1", "t1", "i1", "tess@x.com");

        assertEquals(3, result.checks().size(), "every check result is reported, not just the vulnerable one");
        assertEquals(1, result.vulnerableCount());
        assertEquals(1, saved.size(), "only the VULNERABLE verdict is stored as a finding");
        assertEquals("Session usable after logout", saved.get(0).getTitle());
        assertEquals(Severity.HIGH, saved.get(0).getSeverity());
        assertFalse(saved.get(0).isValidated(), "scanner/logic output is a candidate until a tester confirms it");
    }

    // ---------------- Phase 2: IDOR checks ----------------

    private IdorProbe probe(SecretBox box, TestIdentity a, TestIdentity b) {
        return new IdorProbe("p1", "t1", "Order detail", "https://app.example.com/api/orders/{id}",
                a.getId(), "101", b.getId(), "102", "tess");
    }

    @Test
    void idorCheckRefusedWhenTheGateDoesNotAllowActiveTesting() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var box = new SecretBox(KEY);
        TestIdentity a = identityWith(box, "ia", "User A"), b = identityWith(box, "ib", "User B");
        var probeRepo = mock(IdorProbeRepository.class);
        when(probeRepo.findById("p1")).thenReturn(Optional.of(probe(box, a, b)));
        Authorization auth = mock(Authorization.class);
        when(auth.isAllowAuthenticated()).thenReturn(true);
        when(auth.isAllowActive()).thenReturn(false);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(allowed(auth, t));
        var settings = mock(SettingsService.class);
        when(settings.isActiveScanningEnabled()).thenReturn(true);

        var svc = service(t, repoWith(a, b), probeRepo, gate, settings, mock(AuthSessionChecks.class),
                mock(IdorChecks.class), mock(FindingRepository.class));
        assertThrows(AccessDeniedException.class, () -> svc.runIdorCheck("e1", "t1", "p1", "tess@x.com"));
    }

    @Test
    void idorCheckWhenPermittedOnlyVulnerableCrossAccessBecomesAFinding() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var box = new SecretBox(KEY);
        TestIdentity a = identityWith(box, "ia", "User A"), b = identityWith(box, "ib", "User B");
        var probeRepo = mock(IdorProbeRepository.class);
        when(probeRepo.findById("p1")).thenReturn(Optional.of(probe(box, a, b)));
        Authorization auth = mock(Authorization.class);
        when(auth.getId()).thenReturn("auth1");
        when(auth.isAllowAuthenticated()).thenReturn(true);
        when(auth.isAllowActive()).thenReturn(true);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(allowed(auth, t));
        var settings = mock(SettingsService.class);
        when(settings.isActiveScanningEnabled()).thenReturn(true);

        var idorChecks = mock(IdorChecks.class);
        when(idorChecks.checkCrossAccess(any(), any(), eq("101"), any(), any(), eq("102"), any())).thenReturn(List.of(
                new IdorChecks.Result("ACC-01a", "User B can read User A's resource (IDOR)", IdorChecks.Verdict.VULNERABLE,
                        Severity.HIGH, "https://app.example.com/api/orders/101", "B read A's order", "check ownership"),
                new IdorChecks.Result("ACC-01b", "User A can read User B's resource (IDOR)", IdorChecks.Verdict.NOT_VULNERABLE,
                        Severity.INFORMATIONAL, "https://app.example.com/api/orders/102", null, null)));

        var findingRepo = mock(FindingRepository.class);
        when(findingRepo.findFirstByEngagementIdAndFingerprint(any(), any())).thenReturn(Optional.empty());
        var saved = new java.util.ArrayList<Finding>();
        when(findingRepo.save(any())).thenAnswer(i -> { saved.add(i.getArgument(0)); return i.getArgument(0); });

        var svc = service(t, repoWith(a, b), probeRepo, gate, settings, mock(AuthSessionChecks.class), idorChecks, findingRepo);
        var result = svc.runIdorCheck("e1", "t1", "p1", "tess@x.com");

        assertEquals(2, result.checks().size());
        assertEquals(1, result.vulnerableCount());
        assertEquals(1, saved.size());
        assertEquals("User B can read User A's resource (IDOR)", saved.get(0).getTitle());
        assertEquals(Severity.HIGH, saved.get(0).getSeverity());
        assertFalse(saved.get(0).isValidated());
    }

    // ---------------- Phase 3: upload checks ----------------

    private UploadProbe uploadProbe(String identityId) {
        return new UploadProbe("u1", "t1", "Avatar upload", "https://app.example.com/upload", "file",
                "https://app.example.com/uploads/{filename}", identityId, "tess");
    }

    @Test
    void uploadCheckRefusedWhenAuthorizationDoesNotAllowAuthenticatedTesting() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var uploadRepo = mock(UploadProbeRepository.class);
        when(uploadRepo.findById("u1")).thenReturn(Optional.of(uploadProbe(null)));
        Authorization auth = mock(Authorization.class);
        when(auth.isAllowAuthenticated()).thenReturn(false);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(allowed(auth, t));
        var settings = mock(SettingsService.class);
        when(settings.isActiveScanningEnabled()).thenReturn(true);

        var svc = service(t, mock(TestIdentityRepository.class), mock(IdorProbeRepository.class), uploadRepo, gate,
                settings, mock(AuthSessionChecks.class), mock(IdorChecks.class), mock(UploadChecks.class), mock(FindingRepository.class));
        assertThrows(AccessDeniedException.class, () -> svc.runUploadCheck("e1", "t1", "u1", "tess@x.com"));
    }

    @Test
    void uploadCheckWhenPermittedOnlyVulnerableVerdictsBecomeFindings() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var uploadRepo = mock(UploadProbeRepository.class);
        when(uploadRepo.findById("u1")).thenReturn(Optional.of(uploadProbe(null))); // anonymous probe
        Authorization auth = mock(Authorization.class);
        when(auth.getId()).thenReturn("auth1");
        when(auth.isAllowAuthenticated()).thenReturn(true);
        when(auth.isAllowActive()).thenReturn(true);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(allowed(auth, t));
        var settings = mock(SettingsService.class);
        when(settings.isActiveScanningEnabled()).thenReturn(true);

        var uploadChecks = mock(UploadChecks.class);
        when(uploadChecks.checkExtensionBypass(isNull(), isNull(), eq("https://app.example.com/upload"), eq("file"), any()))
                .thenReturn(List.of(
                        new UploadChecks.Result("FILE-06a", "Dangerous extension accepted on upload", UploadChecks.Verdict.VULNERABLE,
                                Severity.HIGH, "https://app.example.com/uploads/x.php", "accepted and retrievable", "validate by content"),
                        new UploadChecks.Result("FILE-06b", "Double-extension upload accepted", UploadChecks.Verdict.NOT_VULNERABLE,
                                Severity.INFORMATIONAL, "https://app.example.com/upload", null, null)));

        var findingRepo = mock(FindingRepository.class);
        when(findingRepo.findFirstByEngagementIdAndFingerprint(any(), any())).thenReturn(Optional.empty());
        var saved = new java.util.ArrayList<Finding>();
        when(findingRepo.save(any())).thenAnswer(i -> { saved.add(i.getArgument(0)); return i.getArgument(0); });

        var svc = service(t, mock(TestIdentityRepository.class), mock(IdorProbeRepository.class), uploadRepo, gate,
                settings, mock(AuthSessionChecks.class), mock(IdorChecks.class), uploadChecks, findingRepo);
        var result = svc.runUploadCheck("e1", "t1", "u1", "tess@x.com");

        assertEquals(2, result.checks().size());
        assertEquals(1, result.vulnerableCount());
        assertEquals(1, saved.size());
        assertEquals("Dangerous extension accepted on upload", saved.get(0).getTitle());
        assertEquals(Severity.HIGH, saved.get(0).getSeverity());
    }

    @Test
    void anAuthenticatedUploadProbeDecryptsTheIdentitysPassword() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var box = new SecretBox(KEY);
        TestIdentity a = identityWith(box, "ia", "User A");
        var uploadRepo = mock(UploadProbeRepository.class);
        when(uploadRepo.findById("u1")).thenReturn(Optional.of(uploadProbe("ia")));
        Authorization auth = mock(Authorization.class);
        when(auth.getId()).thenReturn("auth1");
        when(auth.isAllowAuthenticated()).thenReturn(true);
        when(auth.isAllowActive()).thenReturn(true);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(allowed(auth, t));
        var settings = mock(SettingsService.class);
        when(settings.isActiveScanningEnabled()).thenReturn(true);

        var uploadChecks = mock(UploadChecks.class);
        when(uploadChecks.checkExtensionBypass(eq(a), eq("pw-ia"), any(), any(), any())).thenReturn(List.of());

        var svc = service(t, repoWith(a), mock(IdorProbeRepository.class), uploadRepo, gate, settings,
                mock(AuthSessionChecks.class), mock(IdorChecks.class), uploadChecks, mock(FindingRepository.class));
        svc.runUploadCheck("e1", "t1", "u1", "tess@x.com");

        verify(uploadChecks).checkExtensionBypass(eq(a), eq("pw-ia"), any(), any(), any());
    }

    // ---------------- Phase 4: business logic checks ----------------

    private static final String BIZ_BODY = "{\"productId\":\"p1\",\"price\":99.99,\"quantity\":1}";

    private BusinessLogicProbe businessProbe(String identityId) {
        return new BusinessLogicProbe("b1", "t1", "Checkout", "https://app.example.com/checkout", "POST",
                BIZ_BODY, "price", "0.01", 5, identityId, "tess");
    }

    @Test
    void businessCheckRefusedWhenTheGlobalActiveScanningSwitchIsOff() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var businessRepo = mock(BusinessLogicProbeRepository.class);
        when(businessRepo.findById("b1")).thenReturn(Optional.of(businessProbe(null)));
        Authorization auth = mock(Authorization.class);
        when(auth.isAllowAuthenticated()).thenReturn(true);
        when(auth.isAllowActive()).thenReturn(true);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(allowed(auth, t));
        var settings = mock(SettingsService.class);
        when(settings.isActiveScanningEnabled()).thenReturn(false);

        var svc = service(t, mock(TestIdentityRepository.class), mock(IdorProbeRepository.class),
                mock(UploadProbeRepository.class), businessRepo, gate, settings, mock(AuthSessionChecks.class),
                mock(IdorChecks.class), mock(UploadChecks.class), mock(BusinessLogicChecks.class), mock(FindingRepository.class));
        assertThrows(AccessDeniedException.class, () -> svc.runBusinessLogicCheck("e1", "t1", "b1", "tess@x.com"));
    }

    @Test
    void businessCheckWhenPermittedOnlyVulnerableVerdictsBecomeFindings() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var businessRepo = mock(BusinessLogicProbeRepository.class);
        when(businessRepo.findById("b1")).thenReturn(Optional.of(businessProbe(null)));
        Authorization auth = mock(Authorization.class);
        when(auth.getId()).thenReturn("auth1");
        when(auth.isAllowAuthenticated()).thenReturn(true);
        when(auth.isAllowActive()).thenReturn(true);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(allowed(auth, t));
        var settings = mock(SettingsService.class);
        when(settings.isActiveScanningEnabled()).thenReturn(true);

        var businessChecks = mock(BusinessLogicChecks.class);
        when(businessChecks.checkAll(isNull(), isNull(), eq("https://app.example.com/checkout"), eq("POST"),
                eq(BIZ_BODY), eq("price"), eq("0.01"), eq(5))).thenReturn(List.of(
                new BusinessLogicChecks.Result("BIZ-01", "Tampered parameter accepted", BusinessLogicChecks.Verdict.VULNERABLE,
                        Severity.HIGH, "https://app.example.com/checkout", "accepted price=0.01", "recompute server-side"),
                new BusinessLogicChecks.Result("BIZ-02", "Identical request accepted twice", BusinessLogicChecks.Verdict.NOT_VULNERABLE,
                        Severity.INFORMATIONAL, "https://app.example.com/checkout", null, null),
                new BusinessLogicChecks.Result("BIZ-03", "Concurrent requests all accepted", BusinessLogicChecks.Verdict.NEEDS_MANUAL_REVIEW,
                        Severity.INFORMATIONAL, null, "could not send", null)));

        var findingRepo = mock(FindingRepository.class);
        when(findingRepo.findFirstByEngagementIdAndFingerprint(any(), any())).thenReturn(Optional.empty());
        var saved = new java.util.ArrayList<Finding>();
        when(findingRepo.save(any())).thenAnswer(i -> { saved.add(i.getArgument(0)); return i.getArgument(0); });

        var svc = service(t, mock(TestIdentityRepository.class), mock(IdorProbeRepository.class),
                mock(UploadProbeRepository.class), businessRepo, gate, settings, mock(AuthSessionChecks.class),
                mock(IdorChecks.class), mock(UploadChecks.class), businessChecks, findingRepo);
        var result = svc.runBusinessLogicCheck("e1", "t1", "b1", "tess@x.com");

        assertEquals(3, result.checks().size());
        assertEquals(1, result.vulnerableCount());
        assertEquals(1, saved.size());
        assertEquals("Tampered parameter accepted", saved.get(0).getTitle());
        assertEquals(Severity.HIGH, saved.get(0).getSeverity());
        assertFalse(saved.get(0).isValidated());
    }

    // ---------------- Phase 5: DNS hygiene (passive - no triple gate) ----------------

    @Test
    void dnsHygieneRefusedWhenTheBasicGateDenies() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(eq("e1"), eq("t1"), eq(ScanCategory.NETWORK), any())).thenReturn(denied("No signed authorization covers this target."));
        var svc = service(t, mock(TestIdentityRepository.class), mock(IdorProbeRepository.class),
                mock(UploadProbeRepository.class), mock(BusinessLogicProbeRepository.class), gate, mock(SettingsService.class),
                mock(AuthSessionChecks.class), mock(IdorChecks.class), mock(UploadChecks.class), mock(BusinessLogicChecks.class),
                mock(FindingRepository.class));
        assertThrows(AccessDeniedException.class, () -> svc.runDnsHygieneCheck("e1", "t1", "tess@x.com"));
    }

    @Test
    void dnsHygieneDoesNotNeedActiveOrAuthenticatedTesting() {
        // allowActive/allowAuthenticated are both false - a plain passive gate must still be enough.
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        Authorization auth = mock(Authorization.class);
        when(auth.getId()).thenReturn("auth1");
        when(auth.isAllowActive()).thenReturn(false);
        when(auth.isAllowAuthenticated()).thenReturn(false);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(eq("e1"), eq("t1"), eq(ScanCategory.NETWORK), any())).thenReturn(allowed(auth, t));

        var dnsChecks = mock(DnsHygieneChecks.class);
        when(dnsChecks.check("app.example.com")).thenReturn(List.of(
                new DnsHygieneChecks.Result("NET-09a", "SPF record missing or overly permissive", DnsHygieneChecks.Verdict.VULNERABLE,
                        Severity.MEDIUM, "app.example.com", "no SPF", "publish one"),
                new DnsHygieneChecks.Result("NET-09b", "DMARC record missing or not enforced", DnsHygieneChecks.Verdict.NOT_VULNERABLE,
                        Severity.INFORMATIONAL, "_dmarc.app.example.com", null, null)));

        var findingRepo = mock(FindingRepository.class);
        when(findingRepo.findFirstByEngagementIdAndFingerprint(any(), any())).thenReturn(Optional.empty());
        var saved = new java.util.ArrayList<Finding>();
        when(findingRepo.save(any())).thenAnswer(i -> { saved.add(i.getArgument(0)); return i.getArgument(0); });

        var svc = service(t, mock(TestIdentityRepository.class), mock(IdorProbeRepository.class),
                mock(UploadProbeRepository.class), mock(BusinessLogicProbeRepository.class), gate, mock(SettingsService.class),
                mock(AuthSessionChecks.class), mock(IdorChecks.class), mock(UploadChecks.class), mock(BusinessLogicChecks.class),
                dnsChecks, mock(DefaultCredentialChecks.class), findingRepo);
        var result = svc.runDnsHygieneCheck("e1", "t1", "tess@x.com");

        assertEquals(2, result.checks().size());
        assertEquals(1, result.vulnerableCount());
        assertEquals(1, saved.size());
        assertEquals("SPF record missing or overly permissive", saved.get(0).getTitle());
    }

    @Test
    void dnsHygieneRefusesAnIpTarget() {
        Target t = new Target("t1", "e1", TargetKind.IP, "93.184.216.34", "tess");
        var svc = service(t, mock(TestIdentityRepository.class), mock(IdorProbeRepository.class),
                mock(UploadProbeRepository.class), mock(BusinessLogicProbeRepository.class), mock(AuthorizationGateService.class),
                mock(SettingsService.class), mock(AuthSessionChecks.class), mock(IdorChecks.class), mock(UploadChecks.class),
                mock(BusinessLogicChecks.class), mock(FindingRepository.class));
        assertThrows(IllegalArgumentException.class, () -> svc.runDnsHygieneCheck("e1", "t1", "tess@x.com"));
    }

    // ---------------- Phase 5: default credential check ----------------

    @Test
    void defaultCredsCheckRefusedWhenAuthorizationDoesNotAllowActiveTesting() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity identity = identityWith(new SecretBox(KEY), "i1", "Admin login");
        Authorization auth = mock(Authorization.class);
        when(auth.isAllowAuthenticated()).thenReturn(true);
        when(auth.isAllowActive()).thenReturn(false);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(allowed(auth, t));
        var settings = mock(SettingsService.class);
        when(settings.isActiveScanningEnabled()).thenReturn(true);

        var svc = service(t, repoWith(identity), mock(IdorProbeRepository.class), mock(UploadProbeRepository.class),
                mock(BusinessLogicProbeRepository.class), gate, settings, mock(AuthSessionChecks.class), mock(IdorChecks.class),
                mock(UploadChecks.class), mock(BusinessLogicChecks.class), mock(FindingRepository.class));
        assertThrows(AccessDeniedException.class, () -> svc.runDefaultCredentialCheck("e1", "t1", "i1", "tess@x.com"));
    }

    @Test
    void defaultCredsCheckWhenPermittedRecordsAVulnerableFinding() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity identity = identityWith(new SecretBox(KEY), "i1", "Admin login");
        Authorization auth = mock(Authorization.class);
        when(auth.getId()).thenReturn("auth1");
        when(auth.isAllowAuthenticated()).thenReturn(true);
        when(auth.isAllowActive()).thenReturn(true);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(allowed(auth, t));
        var settings = mock(SettingsService.class);
        when(settings.isActiveScanningEnabled()).thenReturn(true);

        var defaultCreds = mock(DefaultCredentialChecks.class);
        when(defaultCreds.check(eq(identity))).thenReturn(new DefaultCredentialChecks.Result("NET-07",
                "Default service credentials accepted", DefaultCredentialChecks.Verdict.VULNERABLE, Severity.CRITICAL,
                "https://app.example.com/login", "admin/admin accepted", "remove default accounts"));

        var findingRepo = mock(FindingRepository.class);
        when(findingRepo.findFirstByEngagementIdAndFingerprint(any(), any())).thenReturn(Optional.empty());
        var saved = new java.util.ArrayList<Finding>();
        when(findingRepo.save(any())).thenAnswer(i -> { saved.add(i.getArgument(0)); return i.getArgument(0); });

        var svc = service(t, repoWith(identity), mock(IdorProbeRepository.class), mock(UploadProbeRepository.class),
                mock(BusinessLogicProbeRepository.class), gate, settings, mock(AuthSessionChecks.class), mock(IdorChecks.class),
                mock(UploadChecks.class), mock(BusinessLogicChecks.class), mock(DnsHygieneChecks.class), defaultCreds, findingRepo);
        var result = svc.runDefaultCredentialCheck("e1", "t1", "i1", "tess@x.com");

        assertEquals(1, result.checks().size());
        assertEquals(1, result.vulnerableCount());
        assertEquals(1, saved.size());
        assertEquals(Severity.CRITICAL, saved.get(0).getSeverity());
    }

    // ---------------- Phase 6: dependency scanning (passive - no triple gate; scans a file, not the target) ----------------

    private DependencyManifest manifest() {
        return new DependencyManifest("m1", "t1", "Backend lockfile", DependencyEcosystem.NPM, "{\"packages\":{}}", "tess");
    }

    @Test
    void dependencyCheckRefusedWhenTheBasicGateDenies() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var depRepo = mock(DependencyManifestRepository.class);
        when(depRepo.findById("m1")).thenReturn(Optional.of(manifest()));
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(eq("e1"), eq("t1"), eq(ScanCategory.WEB), any())).thenReturn(denied("No signed authorization covers this target."));

        var svc = service(t, mock(TestIdentityRepository.class), mock(IdorProbeRepository.class),
                mock(UploadProbeRepository.class), mock(BusinessLogicProbeRepository.class), depRepo, gate,
                mock(SettingsService.class), mock(AuthSessionChecks.class), mock(IdorChecks.class), mock(UploadChecks.class),
                mock(BusinessLogicChecks.class), mock(DnsHygieneChecks.class), mock(DefaultCredentialChecks.class),
                mock(DependencyChecks.class), mock(FindingRepository.class));
        assertThrows(AccessDeniedException.class, () -> svc.runDependencyCheck("e1", "t1", "m1", "tess@x.com"));
    }

    @Test
    void dependencyCheckDoesNotNeedActiveOrAuthenticatedTesting() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var depRepo = mock(DependencyManifestRepository.class);
        when(depRepo.findById("m1")).thenReturn(Optional.of(manifest()));
        Authorization auth = mock(Authorization.class);
        when(auth.getId()).thenReturn("auth1");
        when(auth.isAllowActive()).thenReturn(false);
        when(auth.isAllowAuthenticated()).thenReturn(false);
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(eq("e1"), eq("t1"), eq(ScanCategory.WEB), any())).thenReturn(allowed(auth, t));

        var depChecks = mock(DependencyChecks.class);
        var finding = new com.sentinelops.service.scanner.NormalizedFinding("npm-lodash", "lodash has a known vulnerability (critical)",
                Severity.CRITICAL, "lodash <=4.17.23", "Prototype Pollution", "npm audit fix", "GHSA-fvqr-27wr-82fm");
        try { when(depChecks.check("{\"packages\":{}}")).thenReturn(List.of(finding)); } catch (Exception ignored) {}

        var findingRepo = mock(FindingRepository.class);
        when(findingRepo.findFirstByEngagementIdAndFingerprint(any(), any())).thenReturn(Optional.empty());
        var saved = new java.util.ArrayList<Finding>();
        when(findingRepo.save(any())).thenAnswer(i -> { saved.add(i.getArgument(0)); return i.getArgument(0); });

        var svc = service(t, mock(TestIdentityRepository.class), mock(IdorProbeRepository.class),
                mock(UploadProbeRepository.class), mock(BusinessLogicProbeRepository.class), depRepo, gate,
                mock(SettingsService.class), mock(AuthSessionChecks.class), mock(IdorChecks.class), mock(UploadChecks.class),
                mock(BusinessLogicChecks.class), mock(DnsHygieneChecks.class), mock(DefaultCredentialChecks.class),
                depChecks, findingRepo);
        var result = svc.runDependencyCheck("e1", "t1", "m1", "tess@x.com");

        assertEquals(1, result.checks().size());
        assertEquals(1, result.vulnerableCount());
        assertEquals(1, saved.size());
        assertEquals(Severity.CRITICAL, saved.get(0).getSeverity());
    }

    @Test
    void anExecutorFailureIsReportedNotSwallowed() throws Exception {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var depRepo = mock(DependencyManifestRepository.class);
        when(depRepo.findById("m1")).thenReturn(Optional.of(manifest()));
        Authorization auth = mock(Authorization.class);
        when(auth.getId()).thenReturn("auth1");
        var gate = mock(AuthorizationGateService.class);
        when(gate.evaluate(eq("e1"), eq("t1"), eq(ScanCategory.WEB), any())).thenReturn(allowed(auth, t));

        var depChecks = mock(DependencyChecks.class);
        when(depChecks.check(any())).thenThrow(new java.io.IOException("npm not found"));

        var svc = service(t, mock(TestIdentityRepository.class), mock(IdorProbeRepository.class),
                mock(UploadProbeRepository.class), mock(BusinessLogicProbeRepository.class), depRepo, gate,
                mock(SettingsService.class), mock(AuthSessionChecks.class), mock(IdorChecks.class), mock(UploadChecks.class),
                mock(BusinessLogicChecks.class), mock(DnsHygieneChecks.class), mock(DefaultCredentialChecks.class),
                depChecks, mock(FindingRepository.class));
        assertThrows(IllegalStateException.class, () -> svc.runDependencyCheck("e1", "t1", "m1", "tess@x.com"));
    }
}
