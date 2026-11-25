package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.repository.FindingRepository;
import com.sentinelops.repository.RetestRepository;
import com.sentinelops.repository.ScanRunRepository;
import com.sentinelops.service.scanner.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Runs ONE claimed scan run (status RUNNING) to the end. Called by the worker, never by a request thread.
 * Order of events: gate re-check (fresh DNS) -> build validated context -> run tool in a container -> parse output
 * -> store findings -> settle retests. Any failure ends the run FAILED with a reason; nothing is ever invented.
 */
@Service
public class ScanExecutor {

    private static final Logger log = LoggerFactory.getLogger(ScanExecutor.class);
    private static final Pattern IPV4 = Pattern.compile("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$");

    private final AuthorizationGateService gate;
    private final ScannerRegistry registry;
    private final DockerRunner docker;
    private final ScanRunRepository scanRuns;
    private final FindingRepository findings;
    private final RetestRepository retests;
    private final CredentialService credentials;
    private final AuditService audit;
    private final AppProperties props;
    private final SettingsService settings;
    private final TransactionTemplate tx;

    public ScanExecutor(AuthorizationGateService gate, ScannerRegistry registry, DockerRunner docker,
                        ScanRunRepository scanRuns, FindingRepository findings, RetestRepository retests,
                        CredentialService credentials, AuditService audit, AppProperties props,
                        SettingsService settings, TransactionTemplate tx) {
        this.gate = gate;
        this.registry = registry;
        this.docker = docker;
        this.scanRuns = scanRuns;
        this.findings = findings;
        this.retests = retests;
        this.credentials = credentials;
        this.audit = audit;
        this.props = props;
        this.settings = settings;
        this.tx = tx;
    }

    public void execute(String runId) {
        ScanRun run = scanRuns.findById(runId).orElse(null);
        if (run == null || run.getStatus() != ScanStatus.RUNNING) return;
        try {
            doExecute(run);
        } catch (IllegalArgumentException | IllegalStateException ex) {
            // our own validation / configuration messages (never contain secrets)
            fail(run, ex.getMessage());
        } catch (IOException ex) {
            log.warn("Scan {} I/O problem: {}", runId, ex.getMessage());
            fail(run, "Could not run or read the tool: " + brief(ex.getMessage()));
        } catch (Exception ex) {
            log.error("Scan {} failed", runId, ex);
            fail(run, "Unexpected scanner error (see server log).");
        }
    }

    private void doExecute(ScanRun run) throws IOException {
        // 1. The gate again: the authorization may have been revoked or the DNS changed since the request.
        var re = gate.evaluate(run.getEngagementId(), run.getTargetId(), run.getCategory(), Instant.now());
        if (!re.allowed()) {
            fail(run, "Gate denied at execution: " + re.reason());
            return;
        }

        // Active mode is re-evaluated: switching the global kill-switch off stops queued active runs from attacking.
        ScanMode mode = run.getMode() == ScanMode.ACTIVE && re.authorization().isAllowActive()
                && settings.isActiveScanningEnabled() ? ScanMode.ACTIVE : ScanMode.PASSIVE;
        if (mode != run.getMode()) {
            run.setMode(mode);
            scanRuns.save(run);
            audit.record("worker", "scan.mode_downgraded", "ScanRun", run.getId(), "active switch no longer on");
        }

        Target target = re.target();

        // Authenticated scan: only when THIS authorization allows it, only web/API, only if a credential is stored.
        CredentialService.Header cred = null;
        if (re.authorization().isAllowAuthenticated()
                && (run.getCategory() == ScanCategory.WEB || run.getCategory() == ScanCategory.API)) {
            cred = credentials.decrypt(target.getId()).orElse(null);
        }

        ScanContext ctx = ScanContext.of(run.getId(), target.getKind(), target.getValue(), target.getBaseUrl(),
                target.isLab(), mode, re.addresses(), props.getScan().getIdentifierHeader(),
                "sentinelops/" + run.getEngagementId(), target.getOpenApiUrl(),
                cred == null ? null : cred.name(), cred == null ? null : cred.value());

        ScannerAdapter adapter = registry.get(run.getTool())
                .filter(a -> a.supports(run.getCategory(), mode, ctx)).orElse(null);
        if (adapter == null) {
            fail(run, "No scanner available for tool " + run.getTool() + " in " + mode + " mode");
            return;
        }

        AppProperties.Engine eng = props.getScan().getEngine();
        Path root = Path.of(eng.getWorkDir()).toAbsolutePath();
        Files.createDirectories(root);
        restrictToOwner(root); // other users of the server must not be able to read scan output or secrets
        Path outDir = root.resolve(run.getId());
        Files.createDirectories(outDir);
        outDir.toFile().setWritable(true, false); // the tool runs as an unprivileged user inside its container
        outDir.toFile().setReadable(true, false);
        outDir.toFile().setExecutable(true, false);
        run.setWorkDir(outDir.toString());
        scanRuns.save(run);

        // Pin the name to the addresses the gate approved (blocks DNS switching between check and connect).
        List<String> pins = target.isLab() || target.getKind() != TargetKind.DOMAIN ? List.of()
                : re.addresses().stream().filter(a -> IPV4.matcher(a).matches()).toList();

        var spec = new DockerRunner.RunSpec(
                DockerRunner.containerName(adapter.id(), run.getId()),
                adapter.image(eng),
                target.isLab() ? eng.getLabNetwork() : eng.getScanNetwork(),
                ctx.host(), pins, outDir, adapter.containerOutDir(), adapter.command(ctx),
                Duration.ofMinutes(eng.getTimeoutMinutes()), adapter.secretEnv(ctx), adapter.extraMounts());

        audit.record("worker", "scan.started", "ScanRun", run.getId(),
                "tool=" + adapter.id() + " mode=" + mode + " target=" + target.getValue() + " lab=" + target.isLab()
                        + " authenticated=" + ctx.authenticated());

        Map<String, String> secretFiles = adapter.secretFiles(ctx);
        CommandExecutor.Result result;
        try {
            for (var e : secretFiles.entrySet()) {
                Path f = outDir.resolve(e.getKey());
                Files.writeString(f, e.getValue(), StandardCharsets.UTF_8);
                f.toFile().setReadable(true, false); // the container user must read it; the parent folder is owner-only
            }
            result = docker.run(spec);
        } finally {
            for (String name : secretFiles.keySet()) {
                try { Files.deleteIfExists(outDir.resolve(name)); } catch (IOException ignored) { /* best effort */ }
            }
        }
        run.setExitCode(result.exitCode());

        // A stop request wins over everything the tool did.
        ScanRun fresh = scanRuns.findById(run.getId()).orElse(run);
        if (fresh.getStatus() == ScanStatus.STOPPED) return;

        if (result.timedOut()) {
            fail(run, "Timed out after " + eng.getTimeoutMinutes() + " minutes.");
            return;
        }
        if (!adapter.acceptsExit(result.exitCode())) {
            fail(run, "Tool exited with code " + result.exitCode() + ": " + scrub(result.outputTail(), ctx));
            return;
        }

        List<NormalizedFinding> parsed = adapter.parse(outDir, ctx);
        int added = tx.execute(status -> ingest(run, target, adapter.id(), mode, parsed));
        run.setFindingCount(parsed.size());
        run.setStatus(ScanStatus.COMPLETED);
        run.setEndedAt(Instant.now());
        scanRuns.save(run);
        audit.record("worker", "scan.completed", "ScanRun", run.getId(),
                "tool=" + adapter.id() + " findings=" + parsed.size() + " new=" + added);
    }

    /** Stores findings and settles retests. Only called for a run that COMPLETED with parsed output. */
    /** Package-private: also used by {@link LogicTestService} so logic-module findings share the same
     *  dedup/fingerprint/retest pipeline as scanner findings. */
    int ingest(ScanRun run, Target target, String tool, ScanMode mode, List<NormalizedFinding> parsed) {
        int added = 0;
        Instant now = Instant.now();
        Set<String> seen = new HashSet<>();
        for (NormalizedFinding n : parsed) {
            String fp = fingerprint(target.getId(), tool, n);
            seen.add(fp);
            var known = findings.findFirstByEngagementIdAndFingerprint(run.getEngagementId(), fp);
            if (known.isPresent()) {
                Finding f = known.get();
                f.setLastSeenAt(now);
                if (f.getStatus() == FindingStatus.RETEST_PASS || f.getStatus() == FindingStatus.CLOSED) {
                    f.setStatus(FindingStatus.OPEN); // it came back
                    audit.record("worker", "finding.reopened", "Finding", f.getId(), "seen again in run " + run.getId());
                }
                findings.save(f);
                continue;
            }
            Finding f = new Finding(UUID.randomUUID().toString(), run.getEngagementId(), run.getId(),
                    target.getTechnology(), n.title(), n.severity());
            f.setTargetId(target.getId());
            f.setTool(tool);
            f.setRuleId(n.ruleId());
            f.setLocation(n.location());
            f.setDescription(n.description());
            f.setRemediation(n.remediation());
            f.setReferenceIds(n.references());
            f.setFingerprint(fp);
            f.setLastSeenAt(now);
            f.setFoundMode(mode);
            f.setEvidenceRef(run.getWorkDir());
            // Scanner output is a CANDIDATE (validated=false) until a tester confirms it; clients only see confirmed ones.
            findings.save(f);
            added++;
        }
        settleRetests(run, target, tool, mode, seen);
        return added;
    }

    /**
     * Findings reported FIXED are settled by a successful run of the same tool on the same target:
     * seen again = RETEST_FAIL; not seen = RETEST_PASS, but only if this run was at least as thorough as the run
     * that found it (a passive run cannot prove an active finding fixed).
     */
    private void settleRetests(ScanRun run, Target target, String tool, ScanMode mode, Set<String> seen) {
        for (Finding f : findings.findByTargetIdAndToolAndStatus(target.getId(), tool, FindingStatus.FIXED)) {
            boolean still = seen.contains(f.getFingerprint());
            if (still) {
                f.setStatus(FindingStatus.RETEST_FAIL);
                retests.save(new Retest(UUID.randomUUID().toString(), f.getId(), "FAIL", "worker",
                        "Still detected by " + tool + " (" + mode + ")", run.getId()));
            } else if (mode == ScanMode.ACTIVE || f.getFoundMode() != ScanMode.ACTIVE) {
                f.setStatus(FindingStatus.RETEST_PASS);
                retests.save(new Retest(UUID.randomUUID().toString(), f.getId(), "PASS", "worker",
                        "Not detected by " + tool + " (" + mode + ")", run.getId()));
            } else {
                continue; // cannot conclude from a weaker scan; stays FIXED
            }
            findings.save(f);
            audit.record("worker", "finding.retest", "Finding", f.getId(), "status=" + f.getStatus() + " run=" + run.getId());
        }
    }

    static String fingerprint(String targetId, String tool, NormalizedFinding n) {
        // ZAP lists whatever URLs its spider happened to reach; the rule per target is the stable identity.
        String loc = tool.startsWith("zap") ? "" : String.valueOf(n.location());
        try {
            byte[] d = MessageDigest.getInstance("SHA-256")
                    .digest((targetId + "|" + tool + "|" + n.ruleId() + "|" + loc).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(d);
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private void fail(ScanRun run, String message) {
        ScanRun fresh = scanRuns.findById(run.getId()).orElse(run);
        if (fresh.getStatus() == ScanStatus.STOPPED) return;
        run.setStatus(ScanStatus.FAILED);
        run.setEndedAt(Instant.now());
        run.setError(brief(message));
        scanRuns.save(run);
        audit.record("worker", "scan.failed", "ScanRun", run.getId(), brief(message));
    }

    /** Tool output is shown to users; make sure a credential can never leak through it. */
    private static String scrub(String text, ScanContext ctx) {
        String t = text == null ? "" : text;
        if (ctx.authHeaderValue() != null) t = t.replace(ctx.authHeaderValue(), "[hidden]");
        return brief(t);
    }

    private static void restrictToOwner(Path dir) {
        try {
            Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        } catch (UnsupportedOperationException | IOException ignored) {
            // not a POSIX file system (local Windows development)
        }
    }

    private static String brief(String s) {
        if (s == null) return "";
        String t = s.replaceAll("\\s+", " ").strip();
        return t.length() <= 500 ? t : t.substring(0, 497) + "...";
    }
}
