package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.TargetRepository;
import com.sentinelops.repository.TestIdentityRepository;
import com.sentinelops.repository.UploadProbeRepository;
import com.sentinelops.service.logic.LoginFlowRunner;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class UploadProbeServiceTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    private TestIdentity identity(String id) {
        return new TestIdentity(id, "t1", "User", "https://app.example.com/login", "email", "password",
                "u", new com.sentinelops.util.SecretBox(KEY).encrypt("pw"), "token", SessionType.HEADER_BEARER,
                null, null, "POST", "tess");
    }

    private UploadProbeService service(Target t, TestIdentity... identities) {
        var targets = mock(TargetRepository.class);
        when(targets.findById(t.getId())).thenReturn(Optional.of(t));
        var identityRepo = mock(TestIdentityRepository.class);
        for (var i : identities) when(identityRepo.findById(i.getId())).thenReturn(Optional.of(i));
        AppProperties p = new AppProperties();
        p.getSecurity().setSecretKey(KEY);
        var identityService = new TestIdentityService(identityRepo, targets, mock(AccessService.class),
                mock(AuthorizationGateService.class), mock(LoginFlowRunner.class), mock(AuditService.class), p);
        return new UploadProbeService(mock(UploadProbeRepository.class), identityService, mock(AuditService.class));
    }

    @Test
    void acceptsAWellFormedAnonymousProbe() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        var view = svc.create("e1", "t1", "Avatar upload", "https://app.example.com/upload", null,
                "https://app.example.com/uploads/{filename}", null, "tess");
        assertEquals("file", view.fieldName(), "default field name");
        assertNull(view.identityId());
    }

    @Test
    void acceptsAWellFormedAuthenticatedProbe() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        TestIdentity id = identity("ia");
        var svc = service(t, id);
        var view = svc.create("e1", "t1", "Avatar upload", "https://app.example.com/upload", "avatar",
                "https://app.example.com/uploads/{filename}", "ia", "tess");
        assertEquals("avatar", view.fieldName());
        assertEquals("ia", view.identityId());
    }

    @Test
    void theRetrievalTemplateMustContainThePlaceholderExactlyOnce() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/upload", null, "https://app.example.com/uploads/", null, "tess"));
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/upload", null, "https://app.example.com/{filename}/{filename}", null, "tess"));
    }

    @Test
    void bothUrlsMustStayOnTheTargetsOwnHost() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://evil.example.org/upload", null, "https://app.example.com/uploads/{filename}", null, "tess"));
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/upload", null, "https://evil.example.org/uploads/{filename}", null, "tess"));
    }

    @Test
    void aRangeCannotHoldAnUploadProbe() {
        Target t = new Target("t1", "e1", TargetKind.CIDR, "203.0.113.0/28", "tess");
        var svc = service(t);
        assertThrows(IllegalArgumentException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/upload", null, "https://app.example.com/uploads/{filename}", null, "tess"));
    }

    @Test
    void anUnknownIdentityIsRefused() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = service(t); // no identities registered
        assertThrows(com.sentinelops.exception.NotFoundException.class, () -> svc.create("e1", "t1", "L",
                "https://app.example.com/upload", null, "https://app.example.com/uploads/{filename}", "ghost", "tess"));
    }
}
