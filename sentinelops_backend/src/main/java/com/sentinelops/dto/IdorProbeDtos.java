package com.sentinelops.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public final class IdorProbeDtos {
    private IdorProbeDtos() {}

    public record IdorProbeRequest(
            @NotBlank @Size(max = 64) String label,
            @NotBlank @Size(max = 512) String urlTemplate,
            @NotBlank String identityAId,
            @NotBlank @Size(max = 128) String resourceIdA,
            @NotBlank String identityBId,
            @NotBlank @Size(max = 128) String resourceIdB) {}
}
