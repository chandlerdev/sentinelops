package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.ScanMode;
import com.sentinelops.entity.ScanRun;
import com.sentinelops.entity.ScanStatus;
import com.sentinelops.repository.ScanRunRepository;
import com.sentinelops.service.scanner.DockerRunner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/** The queue is the database: claim atomically, respect the switch, recover what a restart interrupted. */
class ScanWorkerTest {

    private static final String RUN = "11111111-2222-3333-4444-555555555555";

    private ScanRunRepository scanRuns;
    private ScanExecutor executor;
    private DockerRunner docker;
    private AppProperties props;
    private ScanWorker worker;

    @BeforeEach
    void setUp() {
        scanRuns = mock(ScanRunRepository.class);
        executor = mock(ScanExecutor.class);
        docker = mock(DockerRunner.class);
        props = new AppProperties();
        worker = new ScanWorker(scanRuns, executor, docker, props);
    }

    private ScanRun queuedRun() {
        return new ScanRun(RUN, "e1", "a1", null, "app.example.com", ScanMode.PASSIVE, "nuclei");
    }

    @Test
    void doesNothingWhileTheEngineIsSwitchedOff() {
        props.getScan().getEngine().setEnabled(false);
        worker.poll();
        verifyNoInteractions(scanRuns, executor);
    }

    @Test
    void claimsAQueuedRunAndExecutesIt() {
        props.getScan().getEngine().setEnabled(true);
        when(scanRuns.findFirstByStatusOrderByCreatedAtAsc(ScanStatus.QUEUED))
                .thenReturn(Optional.of(queuedRun()), Optional.empty());
        when(scanRuns.claim(anyString(), any())).thenReturn(1);

        worker.poll();

        verify(executor, timeout(3000)).execute(RUN);
    }

    @Test
    void aRunThatSomeoneElseClaimedOrStoppedIsNotExecuted() throws Exception {
        props.getScan().getEngine().setEnabled(true);
        when(scanRuns.findFirstByStatusOrderByCreatedAtAsc(ScanStatus.QUEUED))
                .thenReturn(Optional.of(queuedRun()), Optional.empty());
        when(scanRuns.claim(anyString(), any())).thenReturn(0);

        worker.poll();
        Thread.sleep(200);

        verify(executor, never()).execute(any());
    }

    @Test
    void runsInterruptedByARestartAreFailedAndTheirContainersRemoved() {
        ScanRun r = queuedRun();
        r.setStatus(ScanStatus.RUNNING);
        when(scanRuns.findByStatus(ScanStatus.RUNNING)).thenReturn(List.of(r));

        worker.recoverInterrupted();

        assertEquals(ScanStatus.FAILED, r.getStatus());
        verify(docker).kill("sentinelops-nuclei-" + RUN);
        verify(scanRuns).save(r);
    }
}
