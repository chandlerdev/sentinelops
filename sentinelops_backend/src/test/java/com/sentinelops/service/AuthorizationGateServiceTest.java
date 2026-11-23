package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.AuthorizationRepository;
import com.sentinelops.repository.TargetRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** The authorization gate: every way a scan must be refused, and the one way it is allowed. */
class AuthorizationGateServiceTest {

    private static final String ENG = "e1";
    private static final String TGT = "t1";

    private final Map<String, List<String>> dns = new HashMap<>();
    private AppProperties props;
    private AuthorizationRepository authRepo;
    private TargetRepository targetRepo;
    private AuthorizationGateService gate;
    private final Instant now = Instant.now();

    private Target target;
    private Authorization auth;

    @BeforeEach
    void setUp() {
        props = new AppProperties();
        dns.put("app.example.com", List.of("93.184.216.34"));
        HostResolver fake = host -> {
            List<String> ips = dns.get(host);
            if (ips == null) throw new UnknownHostException(host);
            List<InetAddress> out = new ArrayList<>();
            for (String ip : ips) out.add(InetAddress.getByName(ip));
            return out;
        };
        authRepo = mock(AuthorizationRepository.class);
        targetRepo = mock(TargetRepository.class);
        gate = new AuthorizationGateService(authRepo, targetRepo, new ScopeValidator(props, fake));

        target = new Target(TGT, ENG, TargetKind.DOMAIN, "app.example.com", "tester");
        verify(target, now.plus(Duration.ofDays(10)));
        when(targetRepo.findById(TGT)).thenReturn(Optional.of(target));

        auth = new Authorization("a1", ENG, "tester");
        auth.getTargetIds().add(TGT);
        auth.setPermittedMethodSet(Set.of(ScanCategory.WEB, ScanCategory.TLS));
        auth.setWindowStart(now.minus(Duration.ofHours(1)));
        auth.setWindowEnd(now.plus(Duration.ofHours(8)));
        auth.setExpiresAt(auth.getWindowEnd());
        auth.setStatus(AuthStatus.SIGNED);
        when(authRepo.findByEngagementIdAndStatus(ENG, AuthStatus.SIGNED)).thenReturn(List.of(auth));
    }

    private static void verify(Target t, Instant expires) {
        t.setVerificationStatus(TargetStatus.VERIFIED);
        t.setVerifiedAt(Instant.now());
        t.setVerificationExpiresAt(expires);
    }

    private AuthorizationGateService.GateResult eval(ScanCategory c) {
        return gate.evaluate(ENG, TGT, c, Instant.now());
    }

    @Test
    void allowsWhenEverythingIsInOrder() {
        var r = eval(ScanCategory.WEB);
        assertTrue(r.allowed(), r.reason());
        assertEquals(List.of("93.184.216.34"), r.addresses());
        assertSame(auth, r.authorization());
    }

    @Test
    void unknownTargetOrTargetOfAnotherEngagementIsDenied() {
        assertFalse(gate.evaluate(ENG, "nope", ScanCategory.WEB, now).allowed());
        assertFalse(gate.evaluate("other-engagement", TGT, ScanCategory.WEB, now).allowed());
    }

    @Test
    void unverifiedTargetCannotBeScanned() {
        target.setVerificationStatus(TargetStatus.UNVERIFIED);
        var r = eval(ScanCategory.WEB);
        assertFalse(r.allowed());
        assertTrue(r.reason().contains("not verified"));
    }

    @Test
    void expiredVerificationCannotBeUsed() {
        verify(target, now.minus(Duration.ofMinutes(1)));
        assertFalse(eval(ScanCategory.WEB).allowed());
    }

    @Test
    void verificationAloneIsNotPermission() {
        when(authRepo.findByEngagementIdAndStatus(ENG, AuthStatus.SIGNED)).thenReturn(List.of());
        var r = eval(ScanCategory.WEB);
        assertFalse(r.allowed());
        assertTrue(r.reason().contains("No signed authorization"));
    }

    @Test
    void signedAuthorizationThatDoesNotCoverTheTargetIsIgnored() {
        auth.getTargetIds().clear();
        auth.getTargetIds().add("another-target");
        assertFalse(eval(ScanCategory.WEB).allowed());
    }

    @Test
    void expiredAuthorizationIsDenied() {
        auth.setExpiresAt(now.minus(Duration.ofMinutes(5)));
        var r = eval(ScanCategory.WEB);
        assertFalse(r.allowed());
        assertTrue(r.reason().contains("expired"));
    }

    @Test
    void outsideTheTestingWindowIsDenied() {
        auth.setWindowStart(now.plus(Duration.ofHours(1)));
        auth.setWindowEnd(now.plus(Duration.ofHours(5)));
        auth.setExpiresAt(auth.getWindowEnd());
        assertTrue(eval(ScanCategory.WEB).reason().contains("before"));

        auth.setWindowStart(now.minus(Duration.ofHours(5)));
        auth.setWindowEnd(now.minus(Duration.ofHours(1)));
        auth.setExpiresAt(now.plus(Duration.ofDays(1)));
        assertTrue(eval(ScanCategory.WEB).reason().contains("after"));
    }

    @Test
    void methodNotPermittedIsDenied() {
        var r = eval(ScanCategory.NETWORK);
        assertFalse(r.allowed());
        assertTrue(r.reason().contains("NETWORK"));
    }

    @Test
    void excludedAssetsAreDenied() {
        auth.setExcludedAssetList(List.of("app.example.com"));
        assertTrue(eval(ScanCategory.WEB).reason().contains("exclusion"));

        auth.setExcludedAssetList(List.of("example.com")); // excluding a parent domain excludes subdomains
        assertTrue(eval(ScanCategory.WEB).reason().contains("exclusion"));

        auth.setExcludedAssetList(List.of("93.184.216.0/24")); // excluding the network the name resolves into
        assertTrue(eval(ScanCategory.WEB).reason().contains("exclusion"));

        auth.setExcludedAssetList(List.of("other.org"));
        assertTrue(eval(ScanCategory.WEB).allowed());
    }

    @Test
    void dnsChangedToAnInternalAddressIsCaughtAtScanTime() {
        assertTrue(eval(ScanCategory.WEB).allowed());
        dns.put("app.example.com", List.of("10.20.30.40")); // record changed after approval
        var r = eval(ScanCategory.WEB);
        assertFalse(r.allowed());
        assertTrue(r.reason().contains("blocked"));
    }

    @Test
    void revokedOrPendingAuthorizationNeverAllows() {
        // The repository query only returns SIGNED records; confirm a non-signed one is never consulted.
        auth.setStatus(AuthStatus.REVOKED);
        when(authRepo.findByEngagementIdAndStatus(ENG, AuthStatus.SIGNED)).thenReturn(List.of());
        assertFalse(eval(ScanCategory.WEB).allowed());
    }

    // ---- lab ----

    private Target labTarget() {
        Target lab = new Target("lab1", ENG, TargetKind.DOMAIN, "juice-shop", "admin");
        lab.setLab(true);
        when(targetRepo.findById("lab1")).thenReturn(Optional.of(lab));
        auth.getTargetIds().add("lab1");
        dns.put("juice-shop", List.of("172.28.0.5"));
        return lab;
    }

    @Test
    void labTargetNeedsNoDnsVerificationButNeedsTheLabConfigAndAnAuthorization() {
        labTarget();
        // lab feature disabled -> denied
        assertFalse(gate.evaluate(ENG, "lab1", ScanCategory.WEB, now).allowed());

        props.getScan().getLab().setEnabled(true);
        props.getScan().getLab().setCidrs(List.of("172.28.0.0/24"));
        props.getScan().getLab().setHosts(List.of("juice-shop"));
        assertTrue(gate.evaluate(ENG, "lab1", ScanCategory.WEB, now).allowed());

        // still needs a signed authorization covering it
        auth.getTargetIds().remove("lab1");
        assertFalse(gate.evaluate(ENG, "lab1", ScanCategory.WEB, now).allowed());
    }
}
