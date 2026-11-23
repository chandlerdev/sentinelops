package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.AuthorizationRepository;
import com.sentinelops.repository.EngagementRepository;
import com.sentinelops.repository.TargetRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** The written-authorization workflow and its guard rails. */
class AuthorizationServiceTest {

    private AppProperties props;
    private AuthorizationRepository authRepo;
    private EngagementRepository engagementRepo;
    private TargetRepository targetRepo;
    private AuthorizationService service;
    private Engagement engagement;
    private Target verifiedTarget;
    private final AtomicReference<Authorization> stored = new AtomicReference<>();
    private final Instant now = Instant.now();

    @BeforeEach
    void setUp() {
        props = new AppProperties();
        authRepo = mock(AuthorizationRepository.class);
        engagementRepo = mock(EngagementRepository.class);
        targetRepo = mock(TargetRepository.class);
        AccessService access = mock(AccessService.class);

        engagement = new Engagement("e1", "Assessment", "c1", "Staging");
        engagement.setState(TicketState.AWAITING_AUTHORIZATION);
        when(access.requireEngagement("e1")).thenReturn(engagement);
        when(engagementRepo.findById("e1")).thenReturn(Optional.of(engagement));

        verifiedTarget = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tester");
        verifiedTarget.setVerificationStatus(TargetStatus.VERIFIED);
        verifiedTarget.setVerificationExpiresAt(now.plus(Duration.ofDays(20)));
        when(targetRepo.findById("t1")).thenReturn(Optional.of(verifiedTarget));

        when(authRepo.save(any())).thenAnswer(i -> {
            stored.set(i.getArgument(0));
            return i.getArgument(0);
        });
        when(authRepo.findById(any())).thenAnswer(i -> Optional.ofNullable(stored.get()));

        service = new AuthorizationService(authRepo, engagementRepo, targetRepo, access, mock(AuditService.class), props);
    }

    private AuthorizationService.Draft draft(Instant start, Instant end, Set<ScanCategory> methods, List<String> targets) {
        return new AuthorizationService.Draft("Q4 assessment", "Jordan Lee", "jordan@client.com", "+1-555-0100",
                methods, List.of("payments.example.com"), start, end, false, "EMAIL-123", targets);
    }

    private Authorization goodDraft() {
        return service.create("e1", draft(now.minus(Duration.ofHours(1)), now.plus(Duration.ofDays(7)),
                Set.of(ScanCategory.WEB), List.of("t1")), "tester@x.com");
    }

    @Test
    void createsADraftThatIsNotInForce() {
        Authorization a = goodDraft();
        assertEquals(AuthStatus.DRAFT, a.getStatus());
        assertEquals(Set.of("t1"), a.getTargetIds());
    }

    @Test
    void rejectsBadWindowsMethodsAndScope() {
        assertThrows(IllegalArgumentException.class, () -> service.create("e1",
                draft(now.plus(Duration.ofDays(2)), now.plus(Duration.ofDays(1)), Set.of(ScanCategory.WEB), List.of("t1")), "t"));
        assertThrows(IllegalArgumentException.class, () -> service.create("e1",
                draft(now.minus(Duration.ofDays(3)), now.minus(Duration.ofDays(1)), Set.of(ScanCategory.WEB), List.of("t1")), "t"));
        assertThrows(IllegalArgumentException.class, () -> service.create("e1",
                draft(now, now.plus(Duration.ofDays(200)), Set.of(ScanCategory.WEB), List.of("t1")), "t"));
        assertThrows(IllegalArgumentException.class, () -> service.create("e1",
                draft(now, now.plus(Duration.ofDays(2)), Set.of(), List.of("t1")), "t"));
        assertThrows(IllegalArgumentException.class, () -> service.create("e1",
                draft(now, now.plus(Duration.ofDays(2)), Set.of(ScanCategory.WEB), List.of()), "t"));
    }

    @Test
    void targetFromAnotherEngagementIsRefused() {
        Target foreign = new Target("t9", "other", TargetKind.DOMAIN, "x.example.org", "tester");
        when(targetRepo.findById("t9")).thenReturn(Optional.of(foreign));
        assertThrows(IllegalArgumentException.class, () -> service.create("e1",
                draft(now, now.plus(Duration.ofDays(2)), Set.of(ScanCategory.WEB), List.of("t9")), "t"));
    }

    @Test
    void fullWorkflowDraftSubmitApprove() {
        Authorization a = goodDraft();
        assertEquals(AuthStatus.PENDING_APPROVAL, service.submit(a.getId(), "tester@x.com").getStatus());

        Authorization approved = service.approve(a.getId(), "ok", "manager@x.com");
        assertEquals(AuthStatus.SIGNED, approved.getStatus());
        assertEquals("Jordan Lee", approved.getSignedBy());
        assertEquals("manager@x.com", approved.getApprovedBy());
        assertNotNull(approved.getSignedAt());
        assertEquals(TicketState.AUTHORIZED, engagement.getState());
    }

    @Test
    void cannotApproveADraftOrApproveTwice() {
        Authorization a = goodDraft();
        assertThrows(IllegalStateException.class, () -> service.approve(a.getId(), null, "manager@x.com"));
        service.submit(a.getId(), "tester@x.com");
        service.approve(a.getId(), null, "manager@x.com");
        assertThrows(IllegalStateException.class, () -> service.approve(a.getId(), null, "manager@x.com"));
    }

    @Test
    void fourEyesBlocksSelfApproval() {
        props.getSecurity().setFourEyes(true);
        Authorization a = goodDraft();
        service.submit(a.getId(), "tester@x.com");
        assertThrows(AccessDeniedException.class, () -> service.approve(a.getId(), null, "TESTER@x.com"));
        assertEquals(AuthStatus.PENDING_APPROVAL, a.getStatus());
    }

    @Test
    void selfApprovalAllowedOnlyWhenFourEyesIsOff() {
        props.getSecurity().setFourEyes(false);
        Authorization a = goodDraft();
        service.submit(a.getId(), "tester@x.com");
        assertEquals(AuthStatus.SIGNED, service.approve(a.getId(), null, "tester@x.com").getStatus());
    }

    @Test
    void cannotApproveWhileATargetIsUnverified() {
        verifiedTarget.setVerificationStatus(TargetStatus.UNVERIFIED);
        Authorization a = goodDraft();
        service.submit(a.getId(), "tester@x.com");
        var ex = assertThrows(IllegalStateException.class, () -> service.approve(a.getId(), null, "manager@x.com"));
        assertTrue(ex.getMessage().contains("not verified"));
        assertEquals(AuthStatus.PENDING_APPROVAL, a.getStatus());
    }

    @Test
    void cannotApproveOnceTheWindowHasEnded() {
        Authorization a = goodDraft();
        service.submit(a.getId(), "tester@x.com");
        a.setWindowEnd(now.minus(Duration.ofMinutes(1)));
        assertThrows(IllegalStateException.class, () -> service.approve(a.getId(), null, "manager@x.com"));
    }

    @Test
    void rejectAndRevoke() {
        Authorization a = goodDraft();
        service.submit(a.getId(), "tester@x.com");
        assertEquals(AuthStatus.REJECTED, service.reject(a.getId(), "wrong scope", "manager@x.com").getStatus());
        assertThrows(IllegalStateException.class, () -> service.revoke(a.getId(), null, "manager@x.com"));

        Authorization b = goodDraft();
        service.submit(b.getId(), "tester@x.com");
        service.approve(b.getId(), null, "manager@x.com");
        assertEquals(AuthStatus.REVOKED, service.revoke(b.getId(), "client withdrew consent", "manager@x.com").getStatus());
    }
}
