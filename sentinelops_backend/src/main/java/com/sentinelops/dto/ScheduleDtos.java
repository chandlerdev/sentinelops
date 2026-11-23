package com.sentinelops.dto;

import com.sentinelops.entity.ScanCategory;
import com.sentinelops.entity.ScanMode;
import com.sentinelops.entity.ScanSchedule;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public final class ScheduleDtos {
    private ScheduleDtos() {}

    public record ScheduleRequest(@NotBlank String targetId, @NotNull ScanCategory category, @NotNull ScanMode mode,
                                  @Min(1) @Max(365) int intervalDays, Instant startAt) {}

    public record EnabledRequest(boolean enabled) {}

    public record CredentialRequest(@NotBlank @Size(max = 41) String headerName, @NotBlank @Size(max = 2000) String value) {}

    public record OpenApiRequest(@Size(max = 512) String url) {}

    public record ScheduleView(String id, String engagementId, String targetId, ScanCategory category, ScanMode mode,
                               int intervalDays, Instant nextRunAt, boolean enabled, int deniedInARow,
                               String lastResult, String createdBy) {
        public static ScheduleView from(ScanSchedule s) {
            return new ScheduleView(s.getId(), s.getEngagementId(), s.getTargetId(), s.getCategory(), s.getMode(),
                    s.getIntervalDays(), s.getNextRunAt(), s.isEnabled(), s.getDeniedInARow(), s.getLastResult(),
                    s.getCreatedBy());
        }
    }
}
