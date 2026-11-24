package com.sentinelops.dto;

import com.sentinelops.entity.SessionType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public final class TestIdentityDtos {
    private TestIdentityDtos() {}

    public record TestIdentityRequest(
            @NotBlank @Size(max = 64) String label,
            @NotBlank @Size(max = 512) String loginUrl,
            @Size(max = 64) String usernameField,
            @Size(max = 64) String passwordField,
            @NotBlank @Size(max = 255) String username,
            @NotBlank @Size(max = 500) String password,
            @Size(max = 128) String tokenPath,
            SessionType sessionType,
            @Size(max = 512) String probeUrl,
            @Size(max = 512) String logoutUrl,
            @Size(max = 8) String logoutMethod) {}
}
