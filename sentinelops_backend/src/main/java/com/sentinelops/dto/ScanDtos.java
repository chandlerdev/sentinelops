package com.sentinelops.dto;

import com.sentinelops.entity.*;

import java.time.Instant;

public class ScanDtos {

    public record ScanRunView(String id, String engagementId, String targetId, String targetHost, String tool,
                              ScanCategory category, ScanMode mode, ScanStatus status, Instant startedAt,
                              Instant endedAt, String error, int findingCount, Instant createdAt,
                              String purpose) {
        public static ScanRunView of(ScanRun r) {
            return new ScanRunView(r.getId(), r.getEngagementId(), r.getTargetId(), r.getTargetHost(), r.getTool(),
                    r.getCategory(), r.getMode(), r.getStatus(), r.getStartedAt(), r.getEndedAt(), r.getError(),
                    r.getFindingCount(), r.getCreatedAt(), r.getPurpose());
        }
    }
}
