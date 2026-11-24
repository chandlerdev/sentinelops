package com.sentinelops.dto;

import com.sentinelops.entity.DependencyEcosystem;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public final class DependencyManifestDtos {
    private DependencyManifestDtos() {}

    public record DependencyManifestRequest(
            @NotBlank @Size(max = 64) String label,
            DependencyEcosystem ecosystem,
            @NotBlank String manifestContent) {}
}
