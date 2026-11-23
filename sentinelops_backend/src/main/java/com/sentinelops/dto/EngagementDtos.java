package com.sentinelops.dto;

import com.sentinelops.entity.Engagement;
import com.sentinelops.entity.TicketState;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public final class EngagementDtos {
    private EngagementDtos() {}

    public record EngagementRequest(
            @NotBlank @Size(max = 255) String name,
            @NotBlank String clientId,
            @Size(max = 64) String environment,
            Instant windowStart,
            Instant windowEnd) {}

    public record EngagementView(String id, String name, TicketState state, String environment, String clientId,
                                 Instant windowStart, Instant windowEnd, Instant createdAt) {
        public static EngagementView from(Engagement e) {
            return new EngagementView(e.getId(), e.getName(), e.getState(), e.getEnvironment(), e.getClientId(),
                    e.getWindowStart(), e.getWindowEnd(), e.getCreatedAt());
        }
    }
}
