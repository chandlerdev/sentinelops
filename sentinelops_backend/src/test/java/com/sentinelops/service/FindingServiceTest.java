package com.sentinelops.service;

import com.sentinelops.entity.*;
import com.sentinelops.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/** Finding workflow: confirm / dismiss, who may move a finding where, retest request, dashboard numbers. */
class FindingServiceTest {

    private FindingRepository findings;
    private ScanRunRepository scanRuns;
    private TargetRepository targets;
    private EngagementRepository engagements;
    private AccessService access;
    private ScanService scans;
    private FindingService service;
    private User user;
    private final List<Finding> store = new ArrayList<>();

    @BeforeEach
    void setUp() {
        findings = mock(FindingRepository.class);
        scanRuns = mock(ScanRunRepository.class);
        targets = mock(TargetRepository.class);
        engagements = mock(EngagementRepository.class);
        access = mock(AccessService.class);
        scans = mock(ScanService.class);
        user = new User("u1", "Tess", "tess@x.com", "pw", Role.TESTER, null);
        when(access.currentUser()).thenAnswer(i -> user);
        when(access.requireEngagement("e1")).thenReturn(new Engagement("e1", "Q4 test", "c1", "prod"));
        when(findings.findById(any())).thenAnswer(i -> store.stream().filter(f -> f.getId().equals(i.getArgument(0))).findFirst());
        when(findings.findByEngagementId("e1")).thenAnswer(i -> List.copyOf(store));
        when(findings.save(any())).thenAnswer(i -> i.getArgument(0));
        service = new FindingService(findings, mock(RetestRepository.class), scanRuns, targets, engagements, access,
                mock(AuditService.class), scans);
    }

    private Finding add(String title, Severity sev, FindingStatus status, boolean validated) {
        Finding f = new Finding(java.util.UUID.randomUUID().toString(), "e1", "run1", null, title, sev);
        f.setStatus(status);
        f.setValidated(validated);
        f.setTool("nuclei");
        f.setTargetId("t1");
        store.add(f);
        return f;
    }

    @Test
    void listIsSortedWorstFirstNotAlphabetically() {
        add("a-info", Severity.INFORMATIONAL, FindingStatus.OPEN, true);
        add("b-low", Severity.LOW, FindingStatus.OPEN, true);
        add("c-crit", Severity.CRITICAL, FindingStatus.OPEN, true);
        add("d-med", Severity.MEDIUM, FindingStatus.OPEN, true);
        var sevs = service.list("e1", null, null, null).stream().map(Finding::getSeverity).toList();
        assertEquals(List.of(Severity.CRITICAL, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL), sevs);
    }

    @Test
    void aClientSeesOnlyConfirmedFindings() {
        add("candidate", Severity.HIGH, FindingStatus.OPEN, false);
        add("confirmed", Severity.HIGH, FindingStatus.OPEN, true);
        user = new User("u2", "Cli", "c@x.com", "pw", Role.CLIENT, null);
        assertEquals(List.of("confirmed"), service.list("e1", null, null, null).stream().map(Finding::getTitle).toList());
        user = new User("u1", "Tess", "tess@x.com", "pw", Role.TESTER, null);
        assertEquals(2, service.list("e1", null, null, null).size());
    }

    @Test
    void aClientCannotOpenAnUnconfirmedFindingDirectly() {
        Finding f = add("candidate", Severity.HIGH, FindingStatus.OPEN, false);
        user = new User("u2", "Cli", "c@x.com", "pw", Role.CLIENT, null);
        assertThrows(com.sentinelops.exception.NotFoundException.class, () -> service.detail(f.getId()));
    }

    @Test
    void confirmingMakesAFindingVisibleAndDismissingMakesItAFalsePositive() {
        Finding a = add("a", Severity.HIGH, FindingStatus.OPEN, false);
        service.validate(a.getId(), true, null, "tess@x.com");
        assertTrue(a.isValidated());
        assertEquals("tess@x.com", a.getValidatedBy());

        Finding b = add("b", Severity.HIGH, FindingStatus.OPEN, false);
        service.validate(b.getId(), false, "not exploitable", "tess@x.com");
        assertEquals(FindingStatus.FALSE_POSITIVE, b.getStatus());
        assertFalse(b.isValidated());

        assertThrows(IllegalStateException.class, () -> service.validate(a.getId(), true, null, "tess@x.com"));
    }

    @Test
    void staffMovesFollowTheWorkflowAndNeverSetRetestResultsByHand() {
        Finding f = add("a", Severity.HIGH, FindingStatus.OPEN, true);
        service.changeStatus(f.getId(), FindingStatus.IN_PROGRESS, null, "tess");
        service.changeStatus(f.getId(), FindingStatus.FIXED, "patched in 2.3", "tess");
        assertEquals(FindingStatus.FIXED, f.getStatus());
        assertNotNull(f.getFixedAt());
        assertEquals("patched in 2.3", f.getFixNotes());

        assertThrows(IllegalStateException.class, () -> service.changeStatus(f.getId(), FindingStatus.RETEST_PASS, null, "tess"));
        assertThrows(IllegalStateException.class, () -> service.changeStatus(f.getId(), FindingStatus.CLOSED, null, "tess"));

        Finding g = add("g", Severity.LOW, FindingStatus.RETEST_PASS, true);
        service.changeStatus(g.getId(), FindingStatus.CLOSED, null, "tess");
        assertEquals(FindingStatus.CLOSED, g.getStatus());
    }

    @Test
    void aClientMayOnlyReportProgressNotDismissOrClose() {
        Finding f = add("a", Severity.HIGH, FindingStatus.OPEN, true);
        user = new User("u2", "Cli", "c@x.com", "pw", Role.CLIENT, null);
        service.changeStatus(f.getId(), FindingStatus.FIXED, "done", "cli");
        assertEquals(FindingStatus.FIXED, f.getStatus());
        assertThrows(IllegalStateException.class, () -> service.changeStatus(f.getId(), FindingStatus.FALSE_POSITIVE, null, "cli"));
        assertThrows(IllegalStateException.class, () -> service.changeStatus(f.getId(), FindingStatus.CLOSED, null, "cli"));
        assertThrows(IllegalStateException.class, () -> service.changeStatus(f.getId(), FindingStatus.RETEST_PASS, null, "cli"));
    }

    @Test
    void retestNeedsAFixedFindingAndQueuesOnlyTheToolThatFoundIt() {
        Finding open = add("open", Severity.HIGH, FindingStatus.OPEN, true);
        assertThrows(IllegalStateException.class, () -> service.requestRetest(open.getId(), "tess"));

        Finding fixed = add("fixed", Severity.HIGH, FindingStatus.FIXED, true);
        fixed.setFoundMode(ScanMode.ACTIVE);
        ScanRun original = new ScanRun("run1", "e1", "a1", null, "app.example.com", ScanMode.ACTIVE, "nuclei");
        original.setCategory(ScanCategory.WEB);
        when(scanRuns.findById("run1")).thenReturn(Optional.of(original));
        when(scans.enqueue(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new ScanService.ScanRequested("r2", List.of("r2"), ScanMode.ACTIVE));

        service.requestRetest(fixed.getId(), "tess");
        verify(scans).enqueue("e1", "t1", ScanCategory.WEB, ScanMode.ACTIVE, "tess", "nuclei", "RETEST");
    }

    @Test
    void dashboardCountsOpenBySeverityAndSeparatesCandidatesFixedAndResolved() {
        add("crit", Severity.CRITICAL, FindingStatus.OPEN, true);
        add("high", Severity.HIGH, FindingStatus.IN_PROGRESS, true);
        add("cand", Severity.HIGH, FindingStatus.OPEN, false);
        add("fixed", Severity.MEDIUM, FindingStatus.FIXED, true);
        add("done", Severity.LOW, FindingStatus.CLOSED, true);
        add("fp", Severity.LOW, FindingStatus.FALSE_POSITIVE, true);
        when(scanRuns.findByEngagementIdOrderByCreatedAtDesc("e1")).thenReturn(List.of());
        when(targets.findByEngagementIdOrderByCreatedAtAsc("e1")).thenReturn(List.of());

        var s = service.engagementDashboard("e1").summary();
        assertEquals(3, s.open());
        assertEquals(1, s.openBySeverity().get("CRITICAL"));
        assertEquals(2, s.openBySeverity().get("HIGH"));
        assertEquals(1, s.awaitingRetest());
        assertEquals(1, s.resolved());
        assertEquals(1, s.falsePositives());
        assertEquals(1, s.candidates());
    }

    @Test
    void clientDashboardCountsDoNotIncludeCandidates() {
        add("cand", Severity.CRITICAL, FindingStatus.OPEN, false);
        add("ok", Severity.LOW, FindingStatus.OPEN, true);
        user = new User("u2", "Cli", "c@x.com", "pw", Role.CLIENT, null);
        when(scanRuns.findByEngagementIdOrderByCreatedAtDesc("e1")).thenReturn(List.of());
        when(targets.findByEngagementIdOrderByCreatedAtAsc("e1")).thenReturn(List.of());

        var s = service.engagementDashboard("e1").summary();
        assertEquals(1, s.open());
        assertEquals(0, s.openBySeverity().get("CRITICAL"));
    }
}
