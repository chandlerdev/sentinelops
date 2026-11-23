package com.sentinelops.dto;

import com.sentinelops.entity.Client;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public final class ClientDtos {
    private ClientDtos() {}

    public record ClientRequest(
            @NotBlank @Size(max = 255) String name,
            @NotBlank @Size(max = 255) String contact,
            @Size(max = 64) String tier,
            @Size(max = 255) String compliance) {}

    public record ClientView(String id, String name, String contact, String tier, String compliance, Instant createdAt) {
        public static ClientView from(Client c) {
            return new ClientView(c.getId(), c.getName(), c.getContact(), c.getTier(), c.getCompliance(), c.getCreatedAt());
        }
    }
}
