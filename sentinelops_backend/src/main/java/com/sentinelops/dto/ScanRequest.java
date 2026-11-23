package com.sentinelops.dto;

import com.sentinelops.entity.ScanCategory;
import com.sentinelops.entity.ScanMode;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/** Request to start an authorized scan of one registered target. The target URL is derived server-side. */
public record ScanRequest(
        @NotBlank String targetId,
        @NotNull ScanCategory category,
        @NotNull ScanMode mode
) {}
