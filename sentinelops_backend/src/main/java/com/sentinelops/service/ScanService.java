package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.exception.NotFoundException;
import com.sentinelops.repository.ScanRunRepository;
import com.sentinelops.service.scanner.DockerRunner;
import com.sentinelops.service.scanner.ScanContext;
import com.sentinelops.service.scanner.ScannerAdapter;
import com.sentinelops.service.scanner.ScannerRegistry;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Scan entry point. Enforces the authorization gate at request time, applies the active-scan policy and QUEUES one
 * run per tool for the category. Execution happens later in {@link ScanWorker} / {@link ScanExecutor}, which check
 * the gate again. The persistent queue is the scan_run table.
 * <p>
 * {@link #enqueue} is the single path used by manual requests, retests and schedules, so none of them can skip the gate.
 */
@Service
public class ScanService {

    private final AuthorizationGateService gate;
    private final ScannerRegistry registry;
    private final ScanRunRepository scanRuns;
    private final AuditService audit;
    private final AppProperties props;
    private final SettingsService settings;
    private final AccessService access;
    private final DockerRunner docker;

    public ScanService(AuthorizationGateService gate, ScannerRegistry registry, ScanRunRepository scanRuns,
                       AuditService audit, AppProperties props, SettingsService settings, AccessService access,
                       DockerRunner docker) {
        this.gate = gate;
        this.registry = registry;
        this.scanRuns = scanRuns;
        this.audit = audit;
        this.props = props;
        this.settings = settings;
        this.access = access;
        this.docker = docker;
    }

    public static class GateDeniedException extends RuntimeException {
        public GateDeniedException(String msg) { super(msg); }
    }

    /** scanRunId is the first run (kept for older clients); scanRunIds lists every queued run. */
    public record ScanRequested(String scanRunId, List<String> scanRunIds, ScanMode effectiveMode) {}

    /** Outcome of a dry-run gate evaluation (no scan is created). */
    public record GateCheck(boolean allowed, String reason, List<String> resolvedAddresses, ScanMode effectiveMode) {}

    /** Evaluates the gate exactly as a real scan would, without starting anything. Audited. */
    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public GateCheck checkGate(String engagementId, String targetId, ScanCategory category,
                               ScanMode requestedMode, String actor) {
        access.requireEngagement(engagementId);
        var result = gate.evaluate(engagementId, targetId, category, Instant.now());
        ScanMode mode = result.allowed() ? resolveMode(requestedMode, result.authorization()) : ScanMode.PASSIVE;
        audit.record(actor, "scan.gate_check", "Target", targetId,
                "category=" + category + " allowed=" + result.allowed() + " reason=" + result.reason());
        return new GateCheck(result.allowed(), result.reason(), result.addresses(), mode);
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public ScanRequested requestScan(String engagementId, String targetId, ScanCategory category,
                                     ScanMode requestedMode, String actor) {
        access.requireEngagement(engagementId);
        return enqueue(engagementId, targetId, category, requestedMode, actor, null, "SCAN");
    }

    /**
     * Gate, then one queued run per applicable tool. Callers must already have checked who is allowed to ask
     * (user requests, retests) or be trusted internal code (the scheduler).
     *
     * @param toolFilter when set, only that tool is queued (used by retests)
     * @param purpose    SCAN, RETEST or SCHEDULED
     */
    @Transactional
    public ScanRequested enqueue(String engagementId, String targetId, ScanCategory category, ScanMode requestedMode,
                                 String actor, String toolFilter, String purpose) {
        Instant now = Instant.now();
        var result = gate.evaluate(engagementId, targetId, category, now);
        audit.record(actor, "scan.gate", "Target", targetId,
                "category=" + category + " purpose=" + purpose + " allowed=" + result.allowed()
                        + " reason=" + result.reason());

        if (!result.allowed()) {
            throw new GateDeniedException(result.reason());
        }
        if (!props.getScan().getEngine().isEnabled()) {
            throw new IllegalStateException("The scan engine is switched off on this server "
                    + "(sentinelops.scan.engine.enabled=false). The gate would allow this scan; nothing was queued.");
        }

        ScanMode effective = resolveMode(requestedMode, result.authorization());
        Target target = result.target();

        if (target.getKind() == TargetKind.CIDR && category != ScanCategory.NETWORK) {
            throw new IllegalArgumentException("Web, API and TLS checks need a single host. Use NETWORK for a range.");
        }

        // Validate everything that will reach a command line NOW, so a bad value fails the request, not the worker.
        ScanContext ctx = ScanContext.of(UUID.randomUUID().toString(), target.getKind(), target.getValue(),
                target.getBaseUrl(), target.isLab(), effective, result.addresses(),
                props.getScan().getIdentifierHeader(), "sentinelops/" + engagementId,
                target.getOpenApiUrl(), null, null);
        if (category == ScanCategory.TLS && !ctx.https()) {
            throw new IllegalArgumentException("The TLS check needs an https target.");
        }

        List<ScannerAdapter> tools = registry.forScan(category, effective, ctx).stream()
                .filter(t -> toolFilter == null || t.id().equals(toolFilter)).toList();
        if (tools.isEmpty()) {
            throw new IllegalArgumentException("No scanner applies to " + category + " in " + effective + " mode"
                    + (toolFilter != null ? " for tool " + toolFilter : "") + ".");
        }

        List<String> ids = new ArrayList<>();
        for (ScannerAdapter tool : tools) {
            ScanRun run = new ScanRun(UUID.randomUUID().toString(), engagementId, result.authorization().getId(),
                    target.getTechnology(), target.getValue(), effective, tool.id());
            run.setTargetId(target.getId());
            run.setCategory(category);
            run.setPurpose(purpose);
            run.setResolvedAddresses(String.join(",", result.addresses()));
            scanRuns.save(run);
            ids.add(run.getId());
            audit.record(actor, "scan.queued", "ScanRun", run.getId(),
                    "tool=" + tool.id() + " mode=" + effective + " purpose=" + purpose + " target=" + target.getValue());
        }
        return new ScanRequested(ids.get(0), ids, effective);
    }

    @Transactional(readOnly = true)
    public List<ScanRun> list(String engagementId) {
        access.requireEngagement(engagementId);
        return scanRuns.findByEngagementIdOrderByCreatedAtDesc(engagementId);
    }

    /** Stops a queued or running scan. A running container is removed. */
    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public ScanRun stop(String scanRunId, String actor) {
        ScanRun run = scanRuns.findById(scanRunId).orElseThrow(() -> new NotFoundException("Scan not found"));
        access.requireEngagement(run.getEngagementId());
        if (run.getStatus() != ScanStatus.QUEUED && run.getStatus() != ScanStatus.RUNNING) {
            throw new IllegalStateException("This scan has already finished.");
        }
        boolean wasRunning = run.getStatus() == ScanStatus.RUNNING;
        run.setStatus(ScanStatus.STOPPED);
        run.setEndedAt(Instant.now());
        run.setError("Stopped by " + actor);
        scanRuns.save(run);
        audit.record(actor, "scan.stopped", "ScanRun", run.getId(), "tool=" + run.getTool());
        if (wasRunning) docker.kill(DockerRunner.containerName(run.getTool(), run.getId()));
        return run;
    }

    /**
     * Active scanning requires ALL of: the per-engagement active permission, the administrator's global
     * switch, and an explicit ACTIVE request. Anything else is downgraded to PASSIVE.
     */
    ScanMode resolveMode(ScanMode requested, Authorization auth) {
        if (requested == ScanMode.ACTIVE && auth.isAllowActive() && settings.isActiveScanningEnabled()) {
            return ScanMode.ACTIVE;
        }
        return ScanMode.PASSIVE;
    }
}
