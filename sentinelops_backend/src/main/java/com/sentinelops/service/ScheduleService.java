package com.sentinelops.service;

import com.sentinelops.config.AppProperties;
import com.sentinelops.entity.*;
import com.sentinelops.exception.NotFoundException;
import com.sentinelops.repository.ScanRunRepository;
import com.sentinelops.repository.ScanScheduleRepository;
import com.sentinelops.repository.TargetRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

/**
 * Recurring scans. A schedule is only a reminder to ask the normal scan path: every run goes through
 * {@link ScanService#enqueue}, i.e. the full authorization gate (verified ownership, signed authorization, window,
 * method, fresh DNS). When the gate says no, the schedule records why and switches itself off after three refusals in a row.
 */
@Service
public class ScheduleService {

    private static final Logger log = LoggerFactory.getLogger(ScheduleService.class);
    static final int MAX_DENIALS = 3;

    private final ScanScheduleRepository schedules;
    private final TargetRepository targets;
    private final ScanRunRepository scanRuns;
    private final ScanService scans;
    private final AccessService access;
    private final AuditService audit;
    private final AppProperties props;

    public ScheduleService(ScanScheduleRepository schedules, TargetRepository targets, ScanRunRepository scanRuns,
                           ScanService scans, AccessService access, AuditService audit, AppProperties props) {
        this.schedules = schedules;
        this.targets = targets;
        this.scanRuns = scanRuns;
        this.scans = scans;
        this.access = access;
        this.audit = audit;
        this.props = props;
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public ScanSchedule create(String engagementId, String targetId, ScanCategory category, ScanMode mode,
                               int intervalDays, Instant startAt, String actor) {
        access.requireEngagement(engagementId);
        Target t = targets.findById(targetId).orElseThrow(() -> new NotFoundException("Target not found"));
        if (!t.getEngagementId().equals(engagementId)) throw new NotFoundException("Target not found");
        if (intervalDays < 1 || intervalDays > 365) throw new IllegalArgumentException("Interval must be 1-365 days.");
        Instant now = Instant.now();
        Instant first = startAt != null && startAt.isAfter(now) ? startAt : now.plus(Duration.ofMinutes(10));
        ScanSchedule s = new ScanSchedule(UUID.randomUUID().toString(), engagementId, targetId, category, mode,
                intervalDays, first, actor);
        schedules.save(s);
        audit.record(actor, "schedule.created", "ScanSchedule", s.getId(),
                "target=" + t.getValue() + " category=" + category + " mode=" + mode + " every=" + intervalDays + "d");
        return s;
    }

    @Transactional(readOnly = true)
    public List<ScanSchedule> list(String engagementId) {
        access.requireEngagement(engagementId);
        return schedules.findByEngagementIdOrderByCreatedAtAsc(engagementId);
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public ScanSchedule setEnabled(String id, boolean enabled, String actor) {
        ScanSchedule s = schedules.findById(id).orElseThrow(() -> new NotFoundException("Schedule not found"));
        access.requireEngagement(s.getEngagementId());
        s.setEnabled(enabled);
        if (enabled) {
            s.setDeniedInARow(0);
            if (s.getNextRunAt().isBefore(Instant.now())) s.setNextRunAt(Instant.now().plus(Duration.ofMinutes(10)));
        }
        schedules.save(s);
        audit.record(actor, enabled ? "schedule.enabled" : "schedule.disabled", "ScanSchedule", id, "");
        return s;
    }

    @PreAuthorize("hasAnyRole('TESTER','MANAGER','ADMIN')")
    @Transactional
    public void delete(String id, String actor) {
        ScanSchedule s = schedules.findById(id).orElseThrow(() -> new NotFoundException("Schedule not found"));
        access.requireEngagement(s.getEngagementId());
        schedules.delete(s);
        audit.record(actor, "schedule.deleted", "ScanSchedule", id, "");
    }

    @Scheduled(fixedDelay = 60_000, initialDelay = 60_000)
    public void tick() {
        tick(Instant.now());
    }

    /** Runs every schedule that is due. Never throws: one broken schedule must not stop the others. */
    void tick(Instant now) {
        if (!props.getScan().getEngine().isEnabled()) return; // engine off: do not consume or advance anything
        for (ScanSchedule s : schedules.findByEnabledTrueAndNextRunAtLessThanEqual(now)) {
            try {
                runOne(s, now);
            } catch (RuntimeException ex) {
                log.error("Schedule {} failed", s.getId(), ex);
            }
        }
    }

    private void runOne(ScanSchedule s, Instant now) {
        s.setNextRunAt(now.plus(Duration.ofDays(s.getIntervalDays()))); // always move forward: no catch-up burst
        boolean busy = scanRuns.existsByTargetIdAndCategoryAndStatusIn(s.getTargetId(), s.getCategory(),
                EnumSet.of(ScanStatus.QUEUED, ScanStatus.RUNNING));
        if (busy) {
            s.setLastResult("Skipped: a scan of this target is still queued or running.");
            schedules.save(s);
            return;
        }
        try {
            var r = scans.enqueue(s.getEngagementId(), s.getTargetId(), s.getCategory(), s.getMode(),
                    "scheduler:" + s.getCreatedBy(), null, "SCHEDULED");
            s.setDeniedInARow(0);
            s.setLastResult("Queued " + r.scanRunIds().size() + " run(s) as " + r.effectiveMode() + ".");
        } catch (ScanService.GateDeniedException ex) {
            s.setDeniedInARow(s.getDeniedInARow() + 1);
            s.setLastResult("Refused by the gate: " + ex.getMessage());
            if (s.getDeniedInARow() >= MAX_DENIALS) {
                s.setEnabled(false);
                s.setLastResult(s.getLastResult() + " Schedule switched off after " + MAX_DENIALS + " refusals.");
                audit.record("scheduler", "schedule.auto_disabled", "ScanSchedule", s.getId(), ex.getMessage());
            }
        } catch (IllegalStateException | IllegalArgumentException ex) {
            s.setLastResult("Not queued: " + ex.getMessage());
        }
        schedules.save(s);
    }
}
