package com.sentinelops.service;

import com.sentinelops.dto.FindingDtos.*;
import com.sentinelops.dto.ScanDtos.ScanRunView;
import com.sentinelops.entity.*;
import com.sentinelops.exception.NotFoundException;
import com.sentinelops.repository.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

/** Finding workflow (validate, fix, retest) and the dashboard numbers. */
@Service
public class FindingService {

    static final List<Severity> SEVERITY_ORDER = List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
            Severity.LOW, Severity.INFORMATIONAL);

    private static final Set<FindingStatus> OPEN = EnumSet.of(FindingStatus.OPEN, FindingStatus.IN_PROGRESS,
            FindingStatus.RETEST_FAIL);
    private static final Set<FindingStatus> RESOLVED = EnumSet.of(FindingStatus.RETEST_PASS, FindingStatus.CLOSED);

    /** Moves a person may make. RETEST_PASS / RETEST_FAIL are set only by the retest worker, never by hand. */
    private static final Map<FindingStatus, Set<FindingStatus>> STAFF = Map.of(
            FindingStatus.OPEN, EnumSet.of(FindingStatus.IN_PROGRESS, FindingStatus.FIXED, FindingStatus.FALSE_POSITIVE),
            FindingStatus.IN_PROGRESS, EnumSet.of(FindingStatus.OPEN, FindingStatus.FIXED, FindingStatus.FALSE_POSITIVE),
            FindingStatus.FIXED, EnumSet.of(FindingStatus.OPEN, FindingStatus.IN_PROGRESS),
            FindingStatus.RETEST_FAIL, EnumSet.of(FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.FIXED,
                    FindingStatus.FALSE_POSITIVE),
            FindingStatus.RETEST_PASS, EnumSet.of(FindingStatus.CLOSED, FindingStatus.OPEN),
            FindingStatus.CLOSED, EnumSet.of(FindingStatus.OPEN),
            FindingStatus.FALSE_POSITIVE, EnumSet.of(FindingStatus.OPEN));

    private static final Map<FindingStatus, Set<FindingStatus>> CLIENT = Map.of(
            FindingStatus.OPEN, EnumSet.of(FindingStatus.IN_PROGRESS, FindingStatus.FIXED),
            FindingStatus.IN_PROGRESS, EnumSet.of(FindingStatus.FIXED),
            FindingStatus.FIXED, EnumSet.of(FindingStatus.IN_PROGRESS),
            FindingStatus.RETEST_FAIL, EnumSet.of(FindingStatus.IN_PROGRESS, FindingStatus.FIXED));

    private final FindingRepository findings;
    private final RetestRepository retests;
    private final ScanRunRepository scanRuns;
    private final TargetRepository targets;
    private final EngagementRepository engagements;
    private final AccessService access;
    private final AuditService audit;
    private final ScanService scans;

    public FindingService(FindingRepository findings, RetestRepository retests, ScanRunRepository scanRuns,
                          TargetRepository targets, EngagementRepository engagements, AccessService access,
                          AuditService audit, ScanService scans) {
        this.findings = findings;
        this.retests = retests;
        this.scanRuns = scanRuns;
        this.targets = targets;
        this.engagements = engagements;
        this.access = access;
        this.audit = audit;
        this.scans = scans;
    }

    private boolean isClient() { return access.currentUser().getRole() == Role.CLIENT; }

    /** Findings the current user may see, worst first. A CLIENT sees only confirmed findings. */
    @Transactional(readOnly = true)
    public List<Finding> list(String engagementId, Severity severity, FindingStatus status, String tool) {
        access.requireEngagement(engagementId);
        boolean client = isClient();
        return findings.findByEngagementId(engagementId).stream()
                .filter(f -> !client || f.isValidated())
                .filter(f -> severity == null || f.getSeverity() == severity)
                .filter(f -> status == null || f.getStatus() == status)
                .filter(f -> tool == null || tool.equals(f.getTool()))
                .sorted(Comparator.comparingInt((Finding f) -> SEVERITY_ORDER.indexOf(f.getSeverity()))
                        .thenComparing(Finding::getTitle))
                .toList();
    }

    @Transactional(readOnly = true)
    public FindingDetail detail(String findingId) {
        Finding f = load(findingId);
        return new FindingDetail(FindingView.from(f),
                retests.findByFindingIdOrderByTestedAtDesc(f.getId()).stream().map(RetestView::from).toList());
    }

    private Finding load(String id) {
        Finding f = findings.findById(id).orElseThrow(() -> new NotFoundException("Finding not found"));
        access.requireEngagement(f.getEngagementId());
        if (isClient() && !f.isValidated()) throw new NotFoundException("Finding not found");
        return f;
    }

    /** A tester confirms a candidate (the client may then see it) or dismisses it as a false positive. */
    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public Finding validate(String findingId, boolean confirm, String note, String actor) {
        Finding f = load(findingId);
        if (f.isValidated()) throw new IllegalStateException("This finding is already confirmed.");
        f.setValidatedBy(actor);
        f.setValidatedAt(Instant.now());
        if (confirm) {
            f.setValidated(true);
        } else {
            f.setStatus(FindingStatus.FALSE_POSITIVE);
        }
        if (note != null && !note.isBlank()) f.setFixNotes(note.strip());
        findings.save(f);
        audit.record(actor, confirm ? "finding.confirmed" : "finding.false_positive", "Finding", f.getId(),
                "title=" + f.getTitle());
        return f;
    }

    @Transactional
    public Finding changeStatus(String findingId, FindingStatus to, String note, String actor) {
        Finding f = load(findingId);
        boolean client = isClient();
        Set<FindingStatus> allowed = (client ? CLIENT : STAFF).getOrDefault(f.getStatus(), Set.of());
        if (!allowed.contains(to)) {
            throw new IllegalStateException("A finding cannot move from " + f.getStatus() + " to " + to + ".");
        }
        FindingStatus from = f.getStatus();
        f.setStatus(to);
        if (to == FindingStatus.FIXED) f.setFixedAt(Instant.now());
        if (note != null && !note.isBlank()) f.setFixNotes(note.strip());
        findings.save(f);
        audit.record(actor, "finding.status", "Finding", f.getId(), from + " -> " + to);
        return f;
    }

    /** Queues a re-check of one finding with the tool that found it. The result is settled by the worker. */
    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public ScanService.ScanRequested requestRetest(String findingId, String actor) {
        Finding f = load(findingId);
        if (f.getStatus() != FindingStatus.FIXED) {
            throw new IllegalStateException("Only a finding marked FIXED can be retested.");
        }
        if (f.getTargetId() == null || f.getTool() == null || f.getScanRunId() == null) {
            throw new IllegalStateException("This finding has no scan information to retest from.");
        }
        ScanRun original = scanRuns.findById(f.getScanRunId())
                .orElseThrow(() -> new IllegalStateException("The scan that found this issue is gone."));
        ScanMode mode = f.getFoundMode() == null ? ScanMode.PASSIVE : f.getFoundMode();
        audit.record(actor, "finding.retest_requested", "Finding", f.getId(), "tool=" + f.getTool());
        return scans.enqueue(f.getEngagementId(), f.getTargetId(), original.getCategory(), mode, actor,
                f.getTool(), "RETEST");
    }

    // ---------------- dashboard ----------------

    @Transactional(readOnly = true)
    public EngagementDashboard engagementDashboard(String engagementId) {
        Engagement e = access.requireEngagement(engagementId);
        boolean client = isClient();
        List<ScanRun> runs = scanRuns.findByEngagementIdOrderByCreatedAtDesc(engagementId);
        return new EngagementDashboard(summarize(e, client, runs),
                runs.stream().limit(8).map(ScanRunView::of).toList());
    }

    @Transactional(readOnly = true)
    public GlobalDashboard globalDashboard() {
        User u = access.currentUser();
        boolean client = u.getRole() == Role.CLIENT;
        List<Engagement> list = engagements.findAll().stream()
                .filter(e -> !client || (u.getClientId() != null && u.getClientId().equals(e.getClientId())))
                .toList();
        List<Summary> rows = new ArrayList<>();
        for (Engagement e : list) rows.add(summarize(e, client, scanRuns.findByEngagementIdOrderByCreatedAtDesc(e.getId())));

        Map<String, Integer> sev = emptySeverity();
        int open = 0, crit = 0, awaiting = 0, cand = 0;
        for (Summary s : rows) {
            open += s.open();
            awaiting += s.awaitingRetest();
            cand += s.candidates();
            s.openBySeverity().forEach((k, v) -> sev.merge(k, v, Integer::sum));
        }
        crit = sev.get("CRITICAL") + sev.get("HIGH");
        return new GlobalDashboard(rows.size(), open, crit, awaiting, cand, sev, rows);
    }

    private Summary summarize(Engagement e, boolean client, List<ScanRun> runs) {
        List<Finding> all = findings.findByEngagementId(e.getId()).stream()
                .filter(f -> !client || f.isValidated()).toList();
        Map<String, Integer> openBySev = emptySeverity();
        Map<String, Integer> byStatus = new LinkedHashMap<>();
        Map<String, Integer> byTool = new LinkedHashMap<>();
        int open = 0, awaiting = 0, resolved = 0, fp = 0, cand = 0;
        for (Finding f : all) {
            byStatus.merge(f.getStatus().name(), 1, Integer::sum);
            if (f.getTool() != null) byTool.merge(f.getTool(), 1, Integer::sum);
            if (f.getStatus() == FindingStatus.FALSE_POSITIVE) { fp++; continue; }
            if (!f.isValidated()) cand++;
            if (OPEN.contains(f.getStatus())) { open++; openBySev.merge(f.getSeverity().name(), 1, Integer::sum); }
            else if (f.getStatus() == FindingStatus.FIXED) awaiting++;
            else if (RESOLVED.contains(f.getStatus())) resolved++;
        }
        List<Target> ts = targets.findByEngagementIdOrderByCreatedAtAsc(e.getId());
        Instant now = Instant.now();
        int verified = (int) ts.stream().filter(t -> t.isOwnershipEstablishedAt(now)).count();
        int running = (int) runs.stream().filter(r -> r.getStatus() == ScanStatus.QUEUED || r.getStatus() == ScanStatus.RUNNING).count();
        int failed = (int) runs.stream().filter(r -> r.getStatus() == ScanStatus.FAILED).count();
        Instant last = runs.stream().map(ScanRun::getEndedAt).filter(Objects::nonNull).max(Comparator.naturalOrder()).orElse(null);
        return new Summary(e.getId(), e.getName(), all.size(), open, awaiting, resolved, fp, cand, openBySev, byStatus,
                byTool, ts.size(), verified, running, failed, last);
    }

    private static Map<String, Integer> emptySeverity() {
        Map<String, Integer> m = new LinkedHashMap<>();
        for (Severity s : SEVERITY_ORDER) m.put(s.name(), 0);
        return m;
    }
}
