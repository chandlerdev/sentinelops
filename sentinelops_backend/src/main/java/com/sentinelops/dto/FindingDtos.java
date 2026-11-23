package com.sentinelops.dto;

import com.sentinelops.dto.ScanDtos.ScanRunView;
import com.sentinelops.entity.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public final class FindingDtos {
    private FindingDtos() {}

    public record FindingView(String id, String engagementId, String targetId, String scanRunId, String tool,
                              String ruleId, String title, Severity severity, FindingStatus status,
                              boolean validated, String validatedBy, Instant validatedAt, ScanMode foundMode,
                              String location, String description, String remediation, String referenceIds,
                              String fixNotes, Instant fixedAt, Instant lastSeenAt, Instant createdAt) {
        public static FindingView from(Finding f) {
            return new FindingView(f.getId(), f.getEngagementId(), f.getTargetId(), f.getScanRunId(), f.getTool(),
                    f.getRuleId(), f.getTitle(), f.getSeverity(), f.getStatus(), f.isValidated(), f.getValidatedBy(),
                    f.getValidatedAt(), f.getFoundMode(), f.getLocation(), f.getDescription(), f.getRemediation(),
                    f.getReferenceIds(), f.getFixNotes(), f.getFixedAt(), f.getLastSeenAt(), f.getCreatedAt());
        }
    }

    public record RetestView(String result, String testedBy, Instant testedAt, String notes, String scanRunId) {
        public static RetestView from(Retest r) {
            return new RetestView(r.getResult(), r.getTestedBy(), r.getTestedAt(), r.getNotes(), r.getScanRunId());
        }
    }

    public record FindingDetail(FindingView finding, List<RetestView> retests) {}

    public record ValidateRequest(boolean confirm, @Size(max = 1000) String note) {}

    public record StatusRequest(@NotNull FindingStatus status, @Size(max = 1000) String note) {}

    /** Counts for one engagement. "open" = OPEN, IN_PROGRESS, RETEST_FAIL. */
    public record Summary(String engagementId, String engagementName, int totalFindings, int open, int awaitingRetest,
                          int resolved, int falsePositives, int candidates,
                          Map<String, Integer> openBySeverity, Map<String, Integer> byStatus,
                          Map<String, Integer> byTool, int targets, int verifiedTargets, int scansRunning,
                          int scansFailed, Instant lastScanAt) {}

    public record EngagementDashboard(Summary summary, List<ScanRunView> recentScans) {}

    public record GlobalDashboard(int engagements, int open, int criticalOrHighOpen, int awaitingRetest,
                                  int candidates, Map<String, Integer> openBySeverity, List<Summary> perEngagement) {}
}
