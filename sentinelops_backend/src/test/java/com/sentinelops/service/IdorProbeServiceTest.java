package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.IdorProbeRepository;
import com.sentinelops.repository.TargetRepository;
import com.sentinelops.repository.TestIdentityRepository;
import com.sentinelops.service.logic.LoginFlowRunner;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class IdorProbeServiceTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    private TestIdentity identity(String id) {
        return new TestIdentity(id, "t1", "User", "https://app.example.com/login", "email", "password",
                "u", new com.sentinelops.util.SecretBox(KEY).encrypt("pw"), "token", SessionType.HEADER_BEARER,
                null, null, "POST", "tess");
    }

    private IdorProbeService service(Target t, TestIdentity... identities) {
        var targets = mock(TargetRepository.class);
        when(targets.findById(t.getId())).thenReturn(Optional.of(t));
        var identityRepo = mock(TestIdentityRepository.class);
        for (var i : identities) when(identityRepo.findById(i.getId())).thenReturn(Optional.of(i));
        AppProperties p = new AppProperties();
        p.getSecurity().setSecretKey(KEY);
        var identityService = new TestIdentityService(identityRepo, targets, mock(AccessService.class),
                mock(AuthorizationGateService.class), mock(LoginFlowRunner.class), mock(AuditService.class), p);
        return new IdorProbeService(mock(IdorProbeRepository.class), identityService, mock(AuditService.class));
    }

    @Test
    void acceptsAWellFormedProbe() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity a = identity("ia"), b = identity("ib");
        var svc = service(t, a, b);
        var view = svc.create("e1", "t1", "Order detail", "https://app.example.com/api/orders/{id}",
                "ia", "101", "ib", "102", "tess");
        assertEquals("Order detail", view.label());
        assertEquals("https://app.example.com/api/orders/{id}", view.urlTemplate());
    }

    @Test
    void theUrlTemplateMustContainThePlaceholderExactlyOnce() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity a = identity("ia"), b = identity("ib");
        var svc = service(t, a, b);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/api/orders", "ia", "101", "ib", "102", "tess"));
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/api/{id}/{id}", "ia", "101", "ib", "102", "tess"));
    }

    @Test
    void theUrlTemplateMustStayOnTheTargetsOwnHost() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity a = identity("ia"), b = identity("ib");
        var svc = service(t, a, b);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://evil.example.org/api/orders/{id}", "ia", "101", "ib", "102", "tess"));
    }

    @Test
    void theTwoIdentitiesMustBeDifferent() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity a = identity("ia");
        var svc = service(t, a);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/api/orders/{id}", "ia", "101", "ia", "102", "tess"));
    }

    @Test
    void theTwoResourceIdsMustBeDifferent() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity a = identity("ia"), b = identity("ib");
        var svc = service(t, a, b);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/api/orders/{id}", "ia", "101", "ib", "101", "tess"));
    }

    @Test
    void resourceIdsAreRestrictedToASafeCharacterSet() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity a = identity("ia"), b = identity("ib");
        var svc = service(t, a, b);
        for (String bad : new String[] {"101/../102", "101 102", "101;id", ""}) {
            assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                    "https://app.example.com/api/orders/{id}", "ia", bad, "ib", "102", "tess"), bad);
        }
    }

    @Test
    void aRangeCannotHoldAnIdorProbe() {
        Target t = new Target("t1", "e1", TargetKind.CIDR, "203.0.113.0/28", "tess");
        var svc = service(t);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/api/orders/{id}", "ia", "101", "ib", "102", "tess"));
    }
}
