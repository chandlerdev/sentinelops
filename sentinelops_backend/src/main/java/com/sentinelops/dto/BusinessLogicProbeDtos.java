package com.sentinelops.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public final class BusinessLogicProbeDtos {
    private BusinessLogicProbeDtos() {}

    public record BusinessLogicProbeRequest(
            @NotBlank @Size(max = 64) String label,
            @NotBlank @Size(max = 512) String requestUrl,
            String httpMethod,
            @NotBlank @Size(max = 4000) String bodyTemplate,
            @Size(max = 128) String tamperedField,
            @Size(max = 512) String tamperedValue,
            Integer concurrency,
            String identityId) {}
}
