package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.ScanRunRepository;
import com.sentinelops.service.scanner.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/** Scan entry point: the gate decides, active mode needs both switches, runs are queued per tool, stop works. */
class ScanServiceTest {

    private AuthorizationGateService gate;
    private ScanRunRepository scanRuns;
    private SettingsService settings;
    private AppProperties props;
    private DockerRunner docker;
    private ScanService service;
    private final List<ScanRun> saved = new ArrayList<>();
    private Target target;
    private Authorization auth;

    @BeforeEach
    void setUp() {
        gate = mock(AuthorizationGateService.class);
        scanRuns = mock(ScanRunRepository.class);
        settings = mock(SettingsService.class);
        docker = mock(DockerRunner.class);
        props = new AppProperties();
        props.getScan().getEngine().setEnabled(true);
        when(scanRuns.save(any())).thenAnswer(i -> {
            saved.add(i.getArgument(0));
            return i.getArgument(0);
        });

        service = new ScanService(gate, new ScannerRegistry(List.of(new NucleiAdapter(), new ZapAdapter(),
                new TestsslAdapter(), new NmapAdapter())), scanRuns, mock(AuditService.class), props, settings,
                mock(AccessService.class), docker);

        target = new Target("t1", "e1", TargetKind.DOMAIN, "app.example.com", "tester");
        auth = new Authorization("a1", "e1", "tester");
    }

    private void gateAllows() {
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(
                new AuthorizationGateService.GateResult(true, null, auth, target, List.of("93.184.216.34")));
    }

    @Test
    void deniedGateStopsTheScanAndCreatesNoRun() {
        when(gate.evaluate(any(), any(), any(), any())).thenReturn(new AuthorizationGateService.GateResult(
                false, "No signed authorization covers this target.", null, target, List.of()));

        var ex = assertThrows(ScanService.GateDeniedException.class,
                () -> service.requestScan("e1", "t1", ScanCategory.WEB, ScanMode.PASSIVE, "tester"));
        assertTrue(ex.getMessage().contains("No signed authorization"));
        assertTrue(saved.isEmpty());
    }

    @Test
    void webScanQueuesOneRunPerToolAndExecutesNothingInTheRequest() {
        gateAllows();
        var r = service.requestScan("e1", "t1", ScanCategory.WEB, ScanMode.PASSIVE, "tester");

        assertEquals(ScanMode.PASSIVE, r.effectiveMode());
        assertEquals(2, r.scanRunIds().size());
        assertEquals(List.of("nuclei", "zap"), saved.stream().map(ScanRun::getTool).sorted().toList());
        for (ScanRun run : saved) {
            assertEquals(ScanStatus.QUEUED, run.getStatus());
            assertEquals("t1", run.getTargetId());
            assertEquals("93.184.216.34", run.getResolvedAddresses());
        }
        verifyNoInteractions(docker);
    }

    @Test
    void eachCategoryUsesItsOwnTools() {
        gateAllows();
        service.requestScan("e1", "t1", ScanCategory.TLS, ScanMode.PASSIVE, "tester");
        assertEquals(List.of("testssl"), saved.stream().map(ScanRun::getTool).toList());
        saved.clear();
        service.requestScan("e1", "t1", ScanCategory.NETWORK, ScanMode.PASSIVE, "tester");
        assertEquals(List.of("nmap"), saved.stream().map(ScanRun::getTool).toList());
    }

    @Test
    void engineSwitchedOffRefusesAndQueuesNothing() {
        gateAllows();
        props.getScan().getEngine().setEnabled(false);
        var ex = assertThrows(IllegalStateException.class,
                () -> service.requestScan("e1", "t1", ScanCategory.WEB, ScanMode.PASSIVE, "tester"));
        assertTrue(ex.getMessage().contains("switched off"));
        assertTrue(saved.isEmpty());
    }

    @Test
    void rangesCanOnlyBeNetworkScanned() {
        target = new Target("t1", "e1", TargetKind.CIDR, "203.0.113.0/28", "tester");
        gateAllows();
        assertThrows(IllegalArgumentException.class,
                () -> service.requestScan("e1", "t1", ScanCategory.WEB, ScanMode.PASSIVE, "tester"));
        service.requestScan("e1", "t1", ScanCategory.NETWORK, ScanMode.PASSIVE, "tester");
        assertEquals(1, saved.size());
    }

    @Test
    void tlsNeedsAnHttpsTarget() {
        target.setBaseUrl("http://app.example.com");
        gateAllows();
        assertThrows(IllegalArgumentException.class,
                () -> service.requestScan("e1", "t1", ScanCategory.TLS, ScanMode.PASSIVE, "tester"));
        assertTrue(saved.isEmpty());
    }

    @Test
    void activeModeNeedsBothTheEngagementPermissionAndTheGlobalSwitch() {
        gateAllows();

        auth.setAllowActive(false);
        when(settings.isActiveScanningEnabled()).thenReturn(true);
        assertEquals(ScanMode.PASSIVE, service.resolveMode(ScanMode.ACTIVE, auth), "global on, authorization off");

        auth.setAllowActive(true);
        when(settings.isActiveScanningEnabled()).thenReturn(false);
        assertEquals(ScanMode.PASSIVE, service.resolveMode(ScanMode.ACTIVE, auth), "authorization on, global off");

        when(settings.isActiveScanningEnabled()).thenReturn(true);
        assertEquals(ScanMode.ACTIVE, service.resolveMode(ScanMode.ACTIVE, auth), "both on");
        assertEquals(ScanMode.PASSIVE, service.resolveMode(ScanMode.PASSIVE, auth), "passive was requested");
    }

    @Test
    void dryRunGateCheckCreatesNoScanRun() {
        gateAllows();
        var r = service.checkGate("e1", "t1", ScanCategory.WEB, ScanMode.ACTIVE, "tester");
        assertTrue(r.allowed());
        assertEquals(ScanMode.PASSIVE, r.effectiveMode());
        assertTrue(saved.isEmpty());
    }

    @Test
    void stoppingAQueuedRunNeedsNoContainerAction() {
        ScanRun run = new ScanRun("11111111-2222-3333-4444-555555555555", "e1", "a1", null, "app.example.com",
                ScanMode.PASSIVE, "nuclei");
        when(scanRuns.findById(run.getId())).thenReturn(Optional.of(run));
        service.stop(run.getId(), "tester");
        assertEquals(ScanStatus.STOPPED, run.getStatus());
        verifyNoInteractions(docker);
    }

    @Test
    void stoppingARunningScanRemovesItsContainer() {
        ScanRun run = new ScanRun("11111111-2222-3333-4444-555555555555", "e1", "a1", null, "app.example.com",
                ScanMode.PASSIVE, "nuclei");
        run.setStatus(ScanStatus.RUNNING);
        when(scanRuns.findById(run.getId())).thenReturn(Optional.of(run));
        service.stop(run.getId(), "tester");
        assertEquals(ScanStatus.STOPPED, run.getStatus());
        verify(docker).kill("sentinelops-nuclei-11111111-2222-3333-4444-555555555555");
    }

    @Test
    void aFinishedScanCannotBeStopped() {
        ScanRun run = new ScanRun("11111111-2222-3333-4444-555555555555", "e1", "a1", null, "app.example.com",
                ScanMode.PASSIVE, "nuclei");
        run.setStatus(ScanStatus.COMPLETED);
        when(scanRuns.findById(run.getId())).thenReturn(Optional.of(run));
        assertThrows(IllegalStateException.class, () -> service.stop(run.getId(), "tester"));
    }
}
