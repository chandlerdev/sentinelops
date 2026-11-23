package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.ScanRun;
import com.sentinelops.entity.ScanStatus;
import com.sentinelops.repository.ScanRunRepository;
import com.sentinelops.service.scanner.DockerRunner;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Persistent job queue: the queue is the scan_run table (status QUEUED), so nothing is lost on a restart.
 * Polls, claims atomically (safe even with two instances), and runs at most N scans at once.
 */
@Component
public class ScanWorker {

    private static final Logger log = LoggerFactory.getLogger(ScanWorker.class);

    private final ScanRunRepository scanRuns;
    private final ScanExecutor executor;
    private final DockerRunner docker;
    private final AppProperties props;
    private final ExecutorService pool;
    private final AtomicInteger active = new AtomicInteger();

    public ScanWorker(ScanRunRepository scanRuns, ScanExecutor executor, DockerRunner docker, AppProperties props) {
        this.scanRuns = scanRuns;
        this.executor = executor;
        this.docker = docker;
        this.props = props;
        this.pool = Executors.newFixedThreadPool(props.getScan().getEngine().getMaxConcurrent(), r -> {
            Thread t = new Thread(r, "scan-worker");
            t.setDaemon(true);
            return t;
        });
    }

    @Scheduled(fixedDelayString = "${sentinelops.scan.engine.poll-ms:5000}", initialDelay = 10000)
    public void poll() {
        if (!props.getScan().getEngine().isEnabled()) return;
        int max = props.getScan().getEngine().getMaxConcurrent();
        while (active.get() < max) {
            ScanRun next = scanRuns.findFirstByStatusOrderByCreatedAtAsc(ScanStatus.QUEUED).orElse(null);
            if (next == null) return;
            if (scanRuns.claim(next.getId(), Instant.now()) != 1) continue; // someone else (or a stop) got it first
            active.incrementAndGet();
            String id = next.getId();
            pool.submit(() -> {
                try {
                    executor.execute(id);
                } catch (RuntimeException ex) {
                    log.error("Scan {} crashed", id, ex);
                } finally {
                    active.decrementAndGet();
                }
            });
        }
    }

    /** After a restart no container of ours is still tracked: fail what was running and remove leftover containers. */
    @EventListener(ApplicationReadyEvent.class)
    public void recoverInterrupted() {
        for (ScanRun r : scanRuns.findByStatus(ScanStatus.RUNNING)) {
            docker.kill(DockerRunner.containerName(r.getTool(), r.getId()));
            r.setStatus(ScanStatus.FAILED);
            r.setEndedAt(Instant.now());
            r.setError("Interrupted by a restart of the platform. Request the scan again.");
            scanRuns.save(r);
        }
    }

    int activeCount() { return active.get(); }

    @PreDestroy
    void shutdown() {
        pool.shutdownNow();
    }
}
