package com.sentinelops.dto;

import com.sentinelops.entity.AuditLog;
import com.sentinelops.entity.Role;
import com.sentinelops.entity.User;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;

public final class AdminDtos {
    private AdminDtos() {}

    public record UserRequest(
            @NotBlank @Size(max = 255) String name,
            @NotBlank @Email @Size(max = 255) String email,
            @NotBlank @Size(min = 10, max = 128) String password,
            @NotNull Role role,
            String clientId) {}

    /** Never includes the password hash. */
    public record UserView(String id, String name, String email, Role role, String clientId, boolean active,
                           Instant createdAt) {
        public static UserView from(User u) {
            return new UserView(u.getId(), u.getName(), u.getEmail(), u.getRole(), u.getClientId(), u.isActive(),
                    u.getCreatedAt());
        }
    }

    public record SettingsView(boolean activeScanningEnabled) {}

    public record ActiveScanningRequest(boolean enabled) {}

    public record AuditView(String id, String actor, String action, String entity, String entityId, String detail,
                            Instant createdAt) {
        public static AuditView from(AuditLog a) {
            return new AuditView(a.getId(), a.getActor(), a.getAction(), a.getEntity(), a.getEntityId(),
                    a.getDetail(), a.getCreatedAt());
        }
    }
}
