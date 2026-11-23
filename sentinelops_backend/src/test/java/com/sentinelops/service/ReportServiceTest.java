package com.sentinelops.service;

import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.parser.PdfTextExtractor;
import com.sentinelops.entity.*;
import com.sentinelops.repository.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/** The PDF is built from stored facts only; unconfirmed findings are excluded unless staff ask for them. */
class ReportServiceTest {

    private AccessService access;
    private AuditService audit;
    private ReportService service;
    private User user;

    @BeforeEach
    void setUp() {
        access = mock(AccessService.class);
        audit = mock(AuditService.class);
        user = new User("u1", "Tess", "tess@x.com", "pw", Role.TESTER, null);
        when(access.currentUser()).thenAnswer(i -> user);
        when(access.requireEngagement("e1000000-0000")).thenReturn(new Engagement("e1000000-0000", "Q4 external test", "c1", "prod"));

        var clients = mock(ClientRepository.class);
        when(clients.findById("c1")).thenReturn(Optional.of(new Client("c1", "Acme Ltd", "a@acme.com", "gold", "none")));

        var targets = mock(TargetRepository.class);
        when(targets.findByEngagementIdOrderByCreatedAtAsc(any())).thenReturn(
                List.of(new Target("t1", "e1000000-0000", TargetKind.DOMAIN, "app.example.com", "tess")));

        var auths = mock(AuthorizationRepository.class);
        when(auths.findByEngagementIdOrderByCreatedAtDesc(any())).thenReturn(List.of());

        var runs = mock(ScanRunRepository.class);
        when(runs.findByEngagementIdOrderByCreatedAtDesc(any())).thenReturn(List.of());

        var findings = mock(FindingRepository.class);
        Finding confirmed = finding("Exposed git config", Severity.HIGH, true, FindingStatus.OPEN);
        Finding candidate = finding("Unreviewed candidate issue", Severity.MEDIUM, false, FindingStatus.OPEN);
        Finding fp = finding("Dismissed false positive", Severity.LOW, true, FindingStatus.FALSE_POSITIVE);
        Finding weird = finding("Unicode ☃ \u0000 title", Severity.LOW, true, FindingStatus.OPEN);
        when(findings.findByEngagementId(any())).thenReturn(List.of(confirmed, candidate, fp, weird));

        var retests = mock(RetestRepository.class);
        when(retests.findByFindingIdOrderByTestedAtDesc(any())).thenReturn(List.of());

        service = new ReportService(access, mock(EngagementRepository.class), clients, targets, auths, runs, findings,
                retests, audit);
    }

    private static Finding finding(String title, Severity sev, boolean validated, FindingStatus status) {
        Finding f = new Finding(java.util.UUID.randomUUID().toString(), "e1000000-0000", "r", null, title, sev);
        f.setValidated(validated);
        f.setStatus(status);
        f.setTool("nuclei");
        f.setTargetId("t1");
        f.setRemediation("Block access to the folder.");
        return f;
    }

    private static String text(byte[] pdf) throws Exception {
        PdfReader r = new PdfReader(pdf);
        StringBuilder sb = new StringBuilder();
        PdfTextExtractor x = new PdfTextExtractor(r);
        for (int p = 1; p <= r.getNumberOfPages(); p++) sb.append(x.getTextFromPage(p)).append('\n');
        return sb.toString();
    }

    @Test
    void producesARealPdfWithClientScopeFindingAndFixAdvice() throws Exception {
        var r = service.generate("e1000000-0000", false, "tess@x.com");
        assertEquals("%PDF", new String(r.pdf(), 0, 4, StandardCharsets.US_ASCII));
        String t = text(r.pdf());
        assertTrue(t.contains("Security Assessment Report"));
        assertTrue(t.contains("Acme Ltd"));
        assertTrue(t.contains("app.example.com"));
        assertTrue(t.contains("Exposed git config"));
        assertTrue(t.contains("Block access to the folder."));
        assertEquals(64, r.sha256().length());
    }

    @Test
    void unconfirmedAndDismissedFindingsAreLeftOutByDefault() throws Exception {
        String t = text(service.generate("e1000000-0000", false, "tess@x.com").pdf());
        assertFalse(t.contains("Unreviewed candidate issue"));
        assertFalse(t.contains("Dismissed false positive"));
    }

    @Test
    void staffCanIncludeCandidatesAndTheyAreLabelledUnconfirmed() throws Exception {
        String t = text(service.generate("e1000000-0000", true, "tess@x.com").pdf());
        assertTrue(t.contains("Unreviewed candidate issue"));
        assertTrue(t.contains("UNCONFIRMED"));
        assertFalse(t.contains("Dismissed false positive"));
    }

    @Test
    void aClientCanNeverGetCandidatesEvenIfTheyAskForThem() throws Exception {
        user = new User("u2", "Cli", "c@x.com", "pw", Role.CLIENT, null);
        String t = text(service.generate("e1000000-0000", true, "cli@x.com").pdf());
        assertFalse(t.contains("Unreviewed candidate issue"));
    }

    @Test
    void unprintableCharactersInScannerTextCannotBreakTheDocument() {
        assertEquals("a?b?c", ReportService.clean("a☃b\u0000c"));
        assertEquals("café", ReportService.clean("café"));
    }

    @Test
    void generatingAReportIsAudited() {
        var r = service.generate("e1000000-0000", false, "tess@x.com");
        verify(audit).record(eq("tess@x.com"), eq("report.generated"), eq("Engagement"), eq("e1000000-0000"),
                contains(r.sha256()));
    }
}
