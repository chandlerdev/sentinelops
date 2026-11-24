package com.sentinelops.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public final class UploadProbeDtos {
    private UploadProbeDtos() {}

    public record UploadProbeRequest(
            @NotBlank @Size(max = 64) String label,
            @NotBlank @Size(max = 512) String uploadUrl,
            @Size(max = 64) String fieldName,
            @NotBlank @Size(max = 512) String retrievalUrlTemplate,
            String identityId) {}
}
