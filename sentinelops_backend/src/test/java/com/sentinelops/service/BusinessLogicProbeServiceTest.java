package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.BusinessLogicProbeRepository;
import com.sentinelops.repository.TargetRepository;
import com.sentinelops.repository.TestIdentityRepository;
import com.sentinelops.service.logic.LoginFlowRunner;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class BusinessLogicProbeServiceTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);
    private static final String BODY = "{\"productId\":\"p1\",\"price\":99.99,\"quantity\":1}";

    private TestIdentity identity(String id) {
        return new TestIdentity(id, "t1", "User", "https://app.example.com/login", "email", "password",
                "u", new com.sentinelops.util.SecretBox(KEY).encrypt("pw"), "token", SessionType.HEADER_BEARER,
                null, null, "POST", "tess");
    }

    private BusinessLogicProbeService service(Target t, TestIdentity... identities) {
        var targets = mock(TargetRepository.class);
        when(targets.findById(t.getId())).thenReturn(Optional.of(t));
        var identityRepo = mock(TestIdentityRepository.class);
        for (var i : identities) when(identityRepo.findById(i.getId())).thenReturn(Optional.of(i));
        AppProperties p = new AppProperties();
        p.getSecurity().setSecretKey(KEY);
        var identityService = new TestIdentityService(identityRepo, targets, mock(AccessService.class),
                mock(AuthorizationGateService.class), mock(LoginFlowRunner.class), mock(AuditService.class), p);
        return new BusinessLogicProbeService(mock(BusinessLogicProbeRepository.class), identityService, mock(AuditService.class));
    }

    @Test
    void acceptsAWellFormedProbeWithATamperField() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        var view = svc.create("e1", "t1", "Checkout", "https://app.example.com/checkout", "POST", BODY,
                "price", "0.01", 5, null, "tess");
        assertEquals("price", view.tamperedField());
        assertEquals("POST", view.httpMethod());
        assertEquals(5, view.concurrency());
    }

    @Test
    void acceptsAWellFormedProbeWithoutATamperField() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        var view = svc.create("e1", "t1", "Coupon", "https://app.example.com/apply-coupon", null, BODY,
                null, null, null, null, "tess");
        assertNull(view.tamperedField());
        assertEquals("POST", view.httpMethod(), "default method");
        assertEquals(5, view.concurrency(), "default concurrency");
    }

    @Test
    void theBodyTemplateMustBeAValidJsonObject() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        for (String bad : new String[] {"not json", "[1,2,3]", "\"just a string\""}) {
            assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                    "https://app.example.com/checkout", "POST", bad, null, null, null, null, "tess"), bad);
        }
    }

    @Test
    void theTamperedFieldMustExistInTheBodyTemplate() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/checkout", "POST", BODY, "notARealField", "0.01", null, null, "tess"));
    }

    @Test
    void theTamperedValueMustBeValidJson() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/checkout", "POST", BODY, "price", "not-valid-json-{{{", null, null, "tess"));
    }

    @Test
    void theRequestUrlMustStayOnTheTargetsOwnHost() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://evil.example.org/checkout", "POST", BODY, null, null, null, null, "tess"));
    }

    @Test
    void theHttpMethodMustBePostOrPut() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/checkout", "DELETE", BODY, null, null, null, null, "tess"));
    }

    @Test
    void concurrencyIsBoundedBetweenTwoAndTen() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/checkout", "POST", BODY, null, null, 1, null, "tess"));
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/checkout", "POST", BODY, null, null, 11, null, "tess"));
    }

    @Test
    void anUnknownIdentityIsRefused() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        assertThrows(com.sentinelops.exception.NotFoundException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/checkout", "POST", BODY, null, null, null, "ghost", "tess"));
    }

    @Test
    void aRangeCannotHoldABusinessLogicProbe() {
        Target t = new Target("t1", "e1", TargetKind.CIDR, "203.0.113.0/28", "tess");
        var svc = service(t);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/checkout", "POST", BODY, null, null, null, null, "tess"));
    }
}
