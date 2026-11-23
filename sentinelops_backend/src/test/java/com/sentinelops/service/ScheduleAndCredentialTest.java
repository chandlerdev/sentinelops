package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.*;
import com.sentinelops.service.scanner.ScanContext;
import com.sentinelops.util.SecretBox;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/** Schedules go through the normal gate; credentials are encrypted, write-only and validated. */
class ScheduleAndCredentialTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);

    // ---------------- schedules ----------------

    private ScanScheduleRepository schedules;
    private ScanRunRepository scanRuns;
    private ScanService scans;
    private AppProperties props;
    private ScheduleService service;
    private ScanSchedule due;

    @BeforeEach
    void setUp() {
        schedules = mock(ScanScheduleRepository.class);
        scanRuns = mock(ScanRunRepository.class);
        scans = mock(ScanService.class);
        props = new AppProperties();
        props.getScan().getEngine().setEnabled(true);
        service = new ScheduleService(schedules, mock(TargetRepository.class), scanRuns, scans,
                mock(AccessService.class), mock(AuditService.class), props);
        due = new ScanSchedule("s1", "e1", "t1", ScanCategory.WEB, ScanMode.PASSIVE, 7,
                Instant.now().minusSeconds(60), "tess@x.com");
        when(schedules.findByEnabledTrueAndNextRunAtLessThanEqual(any())).thenReturn(List.of(due));
    }

    @Test
    void aDueScheduleAsksTheNormalScanPathAndMovesForward() {
        when(scans.enqueue(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new ScanService.ScanRequested("r1", List.of("r1", "r2"), ScanMode.PASSIVE));
        Instant now = Instant.now();
        service.tick(now);

        verify(scans).enqueue("e1", "t1", ScanCategory.WEB, ScanMode.PASSIVE, "scheduler:tess@x.com", null, "SCHEDULED");
        assertTrue(due.getLastResult().startsWith("Queued 2"));
        assertEquals(now.plus(Duration.ofDays(7)), due.getNextRunAt());
        assertEquals(0, due.getDeniedInARow());
    }

    @Test
    void aGateRefusalIsRecordedAndNothingIsQueuedThatTheGateRefused() {
        when(scans.enqueue(any(), any(), any(), any(), any(), any(), any()))
                .thenThrow(new ScanService.GateDeniedException("Authorization has expired."));
        service.tick(Instant.now());

        assertEquals(1, due.getDeniedInARow());
        assertTrue(due.getLastResult().contains("Authorization has expired."));
        assertTrue(due.isEnabled());
    }

    @Test
    void threeRefusalsInARowSwitchTheScheduleOff() {
        when(scans.enqueue(any(), any(), any(), any(), any(), any(), any()))
                .thenThrow(new ScanService.GateDeniedException("No signed authorization covers this target."));
        for (int i = 0; i < 3; i++) service.tick(Instant.now());
        assertFalse(due.isEnabled());
        assertTrue(due.getLastResult().contains("switched off"));
    }

    @Test
    void aSuccessResetsTheRefusalCounter() {
        due.setDeniedInARow(2);
        when(scans.enqueue(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new ScanService.ScanRequested("r1", List.of("r1"), ScanMode.PASSIVE));
        service.tick(Instant.now());
        assertEquals(0, due.getDeniedInARow());
    }

    @Test
    void aScanStillRunningIsNotStackedOnTop() {
        when(scanRuns.existsByTargetIdAndCategoryAndStatusIn(any(), any(), any())).thenReturn(true);
        service.tick(Instant.now());
        verifyNoInteractions(scans);
        assertTrue(due.getLastResult().startsWith("Skipped"));
    }

    @Test
    void nothingRunsWhileTheEngineIsOff() {
        props.getScan().getEngine().setEnabled(false);
        Instant before = due.getNextRunAt();
        service.tick(Instant.now());
        verifyNoInteractions(scans);
        assertEquals(before, due.getNextRunAt(), "the schedule is not consumed while the engine is off");
    }

    @Test
    void oneBrokenScheduleDoesNotStopTheOthers() {
        ScanSchedule second = new ScanSchedule("s2", "e1", "t2", ScanCategory.TLS, ScanMode.PASSIVE, 1,
                Instant.now().minusSeconds(5), "tess@x.com");
        when(schedules.findByEnabledTrueAndNextRunAtLessThanEqual(any())).thenReturn(List.of(due, second));
        when(scans.enqueue(any(), eq("t1"), any(), any(), any(), any(), any())).thenThrow(new RuntimeException("boom"));
        when(scans.enqueue(any(), eq("t2"), any(), any(), any(), any(), any()))
                .thenReturn(new ScanService.ScanRequested("r1", List.of("r1"), ScanMode.PASSIVE));
        service.tick(Instant.now());
        assertTrue(second.getLastResult().startsWith("Queued"));
    }

    // ---------------- secret box ----------------

    @Test
    void secretBoxRoundTripsAndEveryEncryptionIsDifferent() {
        var box = new SecretBox(KEY);
        String a = box.encrypt("Bearer abc");
        String b = box.encrypt("Bearer abc");
        assertNotEquals(a, b, "random nonce");
        assertFalse(a.contains("abc"));
        assertEquals("Bearer abc", box.decrypt(a));
    }

    @Test
    void tamperedOrForeignCiphertextIsRejected() {
        var box = new SecretBox(KEY);
        byte[] raw = Base64.getDecoder().decode(box.encrypt("secret"));
        raw[raw.length - 1] ^= 1;
        String tampered = Base64.getEncoder().encodeToString(raw);
        assertThrows(IllegalStateException.class, () -> box.decrypt(tampered));

        byte[] other = new byte[32];
        other[0] = 1;
        var otherBox = new SecretBox(Base64.getEncoder().encodeToString(other));
        assertThrows(IllegalStateException.class, () -> otherBox.decrypt(box.encrypt("secret")));
    }

    @Test
    void withoutAGoodKeyCredentialStorageFailsClosed() {
        assertThrows(IllegalStateException.class, () -> new SecretBox(""));
        assertThrows(IllegalStateException.class, () -> new SecretBox("not base64!!"));
        assertThrows(IllegalStateException.class, () -> new SecretBox(Base64.getEncoder().encodeToString(new byte[16])));
    }

    // ---------------- credential service ----------------

    private CredentialService credentialService(TargetCredentialRepository repo, TargetRepository targets, String key) {
        AppProperties p = new AppProperties();
        p.getSecurity().setSecretKey(key);
        return new CredentialService(repo, targets, mock(AccessService.class), mock(AuditService.class), p);
    }

    private TargetRepository targetsWith(Target t) {
        var targets = mock(TargetRepository.class);
        when(targets.findById(t.getId())).thenReturn(Optional.of(t));
        return targets;
    }

    @Test
    void storedCredentialIsEncryptedAndRoundTripsForTheWorker() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var repo = mock(TargetCredentialRepository.class);
        var saved = new TargetCredential[1];
        when(repo.save(any())).thenAnswer(i -> saved[0] = i.getArgument(0));
        var svc = credentialService(repo, targetsWith(t), KEY);

        svc.set("e1", "t1", "Authorization", "Bearer s3cr3t", "tess");
        assertFalse(saved[0].getEncValue().contains("s3cr3t"));
        when(repo.findById("t1")).thenReturn(Optional.of(saved[0]));
        assertEquals("Bearer s3cr3t", svc.decrypt("t1").orElseThrow().value());
    }

    @Test
    void credentialStorageRefusesWithoutAKeyAndStoresNothing() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var repo = mock(TargetCredentialRepository.class);
        var svc = credentialService(repo, targetsWith(t), "");
        assertThrows(IllegalStateException.class, () -> svc.set("e1", "t1", "Authorization", "Bearer x", "tess"));
        verify(repo, never()).save(any());
    }

    @Test
    void dangerousHeaderNamesAndValuesAreRefused() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = credentialService(mock(TargetCredentialRepository.class), targetsWith(t), KEY);
        for (String name : List.of("Host", "Content-Length", "Transfer-Encoding", "X-Forwarded-For", "Bad Name", "-x", ""))
            assertThrows(IllegalArgumentException.class, () -> svc.set("e1", "t1", name, "v", "tess"), name);
        for (String value : List.of("", "line1\nline2", "tab\tvalue", "é"))
            assertThrows(IllegalArgumentException.class, () -> svc.set("e1", "t1", "Authorization", value, "tess"), value);
    }

    @Test
    void aRangeCannotHoldACredential() {
        Target t = new Target("t1", "e1", TargetKind.CIDR, "203.0.113.0/28", "tess");
        var svc = credentialService(mock(TargetCredentialRepository.class), targetsWith(t), KEY);
        assertThrows(IllegalArgumentException.class, () -> svc.set("e1", "t1", "Authorization", "Bearer x", "tess"));
    }

    @Test
    void openApiUrlMustStayOnTheTargetsOwnHost() {
        Target t = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tess");
        var svc = credentialService(mock(TargetCredentialRepository.class), targetsWith(t), KEY);
        assertEquals("https://app.example.com/openapi.json",
                svc.setOpenApi("e1", "t1", "https://app.example.com/openapi.json", "tess").getOpenApiUrl());
        for (String bad : List.of("https://evil.example.org/openapi.json", "ftp://app.example.com/x",
                "https://u:p@app.example.com/x", "https://app.example.com/a b", "https://app.example.com/;id"))
            assertThrows(IllegalArgumentException.class, () -> svc.setOpenApi("e1", "t1", bad, "tess"), bad);
        assertNull(svc.setOpenApi("e1", "t1", "", "tess").getOpenApiUrl(), "blank clears it");
    }

    // ---------------- scan context ----------------

    private static ScanContext ctx(String authName, String authValue, String openApi) {
        return ScanContext.of("11111111-2222-3333-4444-555555555555", TargetKind.DOMAIN, "app.example.com", null, false,
                ScanMode.PASSIVE, List.of("93.184.216.34"), "X-Pentest", "sentinelops/e1", openApi, authName, authValue);
    }

    @Test
    void theContextNeverPrintsTheCredential() {
        var c = ctx("Authorization", "Bearer s3cr3t", null);
        assertTrue(c.authenticated());
        assertFalse(c.toString().contains("s3cr3t"));
    }

    @Test
    void contextRefusesRoutingHeadersAndBadValues() {
        assertThrows(IllegalArgumentException.class, () -> ctx("Host", "x", null));
        assertThrows(IllegalArgumentException.class, () -> ctx("X-Pentest", "x", null));
        assertThrows(IllegalArgumentException.class, () -> ctx("Authorization", "a\nb", null));
        assertFalse(ctx(null, null, null).authenticated());
    }

    @Test
    void contextRefusesAnOpenApiUrlOnAnotherHost() {
        assertEquals("https://app.example.com/openapi.json", ctx(null, null, "https://app.example.com/openapi.json").openApiUrl());
        assertThrows(IllegalArgumentException.class, () -> ctx(null, null, "https://evil.example.org/openapi.json"));
    }
}
